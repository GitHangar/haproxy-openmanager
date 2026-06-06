import React, { useState, useEffect, useCallback } from 'react';
import {
  Table, Button, Space, Modal, Form, Input, InputNumber, Select, Tag, message,
  Switch, Typography, Card, Alert, Tooltip, Spin
} from 'antd';
import {
  PlusOutlined, EditOutlined, DeleteOutlined, ReloadOutlined, WarningOutlined,
  PlayCircleOutlined, SyncOutlined, CrownOutlined, ClockCircleOutlined, FileSearchOutlined,
  InfoCircleOutlined
} from '@ant-design/icons';
import { useCluster } from '../contexts/ClusterContext';
import { extractApiError } from '../utils/apiError';

const { Option } = Select;
const { Title, Text } = Typography;

// Interfaces that are never sensible VIP carriers — hidden from the dropdown.
const IFACE_HIDE = /^(lo|docker|veth|br-|cni|flannel|kube|virbr)/i;

const authHeaders = () => ({
  'Content-Type': 'application/json',
  'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
});

// Convergence-aware status (issue #27 follow-up): like other entities, a VIP only reads
// "live" once its member agents have actually deployed & acked — never the instant Apply
// is clicked. Backend returns deploy_status; we fall back to last_config_status.
const DEPLOY_STATUS = {
  PENDING:   { color: 'orange',     label: 'PENDING',  tip: 'Staged change — review and Apply (or Reject) it from the Apply Management page.' },
  PENDING_DELETE: { color: 'volcano', label: 'PENDING DELETE', tip: 'Deletion staged for approval — the VIP keeps running untouched until you APPROVE it in Apply Management. Reject to keep it. The node is not changed until approval.' },
  DELETING:  { color: 'processing', label: 'DELETING', tip: 'Deletion approved — member node(s) are stopping keepalived and releasing the VIP. Disappears once every node has torn down.' },
  DELETED:   { color: 'default',    label: 'DELETED',  tip: 'All member nodes have torn keepalived down.' },
  SYNCING:   { color: 'processing', label: 'SYNCING',  tip: 'Applied — an online member node is installing/configuring keepalived and will acknowledge on its next poll (~2–3 min).' },
  AWAITING:  { color: 'gold',       label: 'AWAITING AGENT', tip: 'Applied, but the member node(s) that still need it are OFFLINE, so nothing can deploy yet. Bring the node\'s agent online — it converges on its next poll. (Not a hang.)' },
  ACTIVE:    { color: 'green',      label: 'ACTIVE',   tip: 'Applied and every member node has deployed keepalived and acknowledged the current config.' },
  ERROR:     { color: 'red',        label: 'ERROR',    tip: 'A member node failed to deploy keepalived — see Members / Live state for the node, then check that agent.' },
  ATTENTION: { color: 'gold',       label: 'ATTENTION',tip: 'A member already runs a hand-managed keepalived; the agent left it untouched (externally managed). Resolve it on that node or remove it from the VIP.' },
  APPLIED:   { color: 'green',      label: 'APPLIED',  tip: 'Applied.' },
};

// agents.capabilities / network_interfaces come from the API as JSONB → a JSON string
// (asyncpg has no jsonb codec). Mirror AgentManagement.js and JSON.parse when needed.
const parseArr = (v) => {
  if (Array.isArray(v)) return v;
  if (typeof v === 'string') { try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; } }
  return [];
};

// This component uses raw fetch(), but extractApiError expects an axios-shaped error
// (err.response.data). Read the fetch Response body and reuse the envelope-aware extractor
// so backend messages — e.g. the 409 "node already in VIP X" — actually reach the user.
const fetchApiError = async (res, fallback) => {
  try { const data = await res.json(); return extractApiError({ response: { data } }, fallback); }
  catch { return fallback; }
};

const VIPManagement = () => {
  const { clusters } = useCluster();
  const [vips, setVips] = useState([]);
  const [loading, setLoading] = useState(false);
  const [modalVisible, setModalVisible] = useState(false);
  const [editing, setEditing] = useState(null);
  const [selectedPoolId, setSelectedPoolId] = useState(null);
  // One row per agent in the selected pool — the user toggles which participate.
  const [memberRows, setMemberRows] = useState([]);
  const [form] = Form.useForm();
  // Delete confirmation (with opt-in package uninstall) + diagnostics modal state.
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [showL2Note, setShowL2Note] = useState(false);
  const [diagVip, setDiagVip] = useState(null);
  const [diagData, setDiagData] = useState(null);
  const [diagLoading, setDiagLoading] = useState(false);

  // Distinct pools derived from the cluster list (cluster -> pool_id).
  const pools = React.useMemo(() => {
    const seen = new Map();
    (clusters || []).forEach((c) => {
      if (c.pool_id && !seen.has(c.pool_id)) seen.set(c.pool_id, c.name || `pool ${c.pool_id}`);
    });
    return Array.from(seen, ([id, name]) => ({ id, name }));
  }, [clusters]);

  const fetchVips = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/vip', { headers: authHeaders() });
      if (res.ok) {
        const data = await res.json();
        setVips(data.vips || []);
      } else if (res.status === 403) {
        message.warning('You do not have permission to view VIPs (vip.read).');
        setVips([]);
      }
    } catch (e) {
      console.error('fetchVips failed', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchVips();
    const t = setInterval(fetchVips, 30000); // live MASTER/BACKUP via existing detection pipeline
    return () => clearInterval(t);
  }, [fetchVips]);

  // Build the participating-nodes table from the pool's EXISTING agents (installed via the
  // standard Agent Management process). On edit, pre-select the VIP's current members.
  const buildMemberRows = (agents, existing) => {
    const ex = {};
    (existing || []).forEach((m) => { ex[m.agent_id] = m; });
    return (agents || [])
      .filter((a) => !String(a.name).startsWith('token_'))
      .map((a) => {
        const interfaces = parseArr(a.network_interfaces).filter((n) => !IFACE_HIDE.test(n));
        const e = ex[a.id];
        return {
          agent_id: a.id,
          agent_name: a.name,
          ip_address: a.ip_address,
          capable: parseArr(a.capabilities).includes('keepalived_management'),
          interfaces,
          participate: !!e,
          role: e ? e.role : 'BACKUP',
          priority: e ? e.priority : 100,
          network_interface: e ? e.network_interface : (interfaces[0] || ''),
        };
      });
  };

  const loadPoolMembers = useCallback(async (poolId, existing) => {
    if (!poolId) { setMemberRows([]); return; }
    try {
      const res = await fetch(`/api/agents?pool_id=${poolId}`, { headers: authHeaders() });
      const data = res.ok ? await res.json() : { agents: [] };
      setMemberRows(buildMemberRows(data.agents || [], existing));
    } catch (e) {
      console.error('loadPoolMembers failed', e);
      setMemberRows([]);
    }
  }, []);

  const setRow = (agentId, patch) =>
    setMemberRows((rows) => rows.map((r) => (r.agent_id === agentId ? { ...r, ...patch } : r)));

  // Toggling a node into the VIP: if no other participating node is MASTER yet, make this
  // one the MASTER. This makes the single-node case work without the operator having to flip
  // the role by hand (a one-node VIP's only node IS the master), and gives a sensible default
  // for multi-node (first picked = master, the rest backup). Editing keeps stored roles.
  const toggleParticipate = (agentId, on) =>
    setMemberRows((rows) => {
      const otherMaster = rows.some((r) => r.agent_id !== agentId && r.participate && r.role === 'MASTER');
      return rows.map((r) => {
        if (r.agent_id !== agentId) return r;
        if (on && !otherMaster) return { ...r, participate: true, role: 'MASTER', priority: 150 };
        return { ...r, participate: on };
      });
    });

  const openCreate = () => {
    setEditing(null);
    setSelectedPoolId(null);
    setMemberRows([]);
    form.resetFields();
    form.setFieldsValue({ prefix_length: 24, advert_int: 1, use_unicast: true, track_haproxy: true });
    setModalVisible(true);
  };

  const openEdit = (vip) => {
    setEditing(vip);
    setSelectedPoolId(vip.pool_id);
    loadPoolMembers(vip.pool_id, vip.members);
    form.resetFields();
    form.setFieldsValue({
      name: vip.name, description: vip.description, pool_id: vip.pool_id,
      virtual_ip: vip.virtual_ip, prefix_length: vip.prefix_length,
      virtual_router_id: vip.virtual_router_id, advert_int: vip.advert_int,
      use_unicast: vip.use_unicast, track_haproxy: vip.track_haproxy,
    });
    setModalVisible(true);
  };

  const submit = async () => {
    let values;
    try { values = await form.validateFields(); }
    catch { return; }

    const chosen = memberRows.filter((r) => r.participate);
    if (chosen.length < 1) { message.error('Select at least 1 participating node.'); return; }
    const masters = chosen.filter((r) => r.role === 'MASTER');
    if (masters.length !== 1) { message.error('Exactly one participating node must be MASTER.'); return; }
    if (chosen.some((r) => !r.network_interface)) { message.error('Pick a network interface for every participating node.'); return; }
    const maxBackup = Math.max(...chosen.filter((r) => r.role === 'BACKUP').map((r) => r.priority));
    if (masters[0].priority <= maxBackup) { message.error('The MASTER must have a higher priority than every BACKUP.'); return; }

    const body = {
      ...values,
      members: chosen.map((r) => ({
        agent_id: r.agent_id, network_interface: r.network_interface, role: r.role, priority: r.priority,
      })),
    };
    if (!body.auth_pass) delete body.auth_pass; // omit to keep existing on edit
    try {
      const url = editing ? `/api/vip/${editing.id}` : '/api/vip';
      const res = await fetch(url, { method: editing ? 'PUT' : 'POST', headers: authHeaders(), body: JSON.stringify(body) });
      if (res.ok) {
        message.success(editing
          ? 'VIP updated (PENDING) — apply it from the Apply Management page'
          : 'VIP created (PENDING) — apply it from the Apply Management page');
        setModalVisible(false);
        fetchVips();
      } else {
        message.error(await fetchApiError(res, 'Failed to save VIP'));
      }
    } catch (e) {
      message.error('Failed to save VIP: ' + e.message);
    }
  };

  const deleteVip = async (vip, purge) => {
    try {
      const res = await fetch(`/api/vip/${vip.id}${purge ? '?purge_package=true' : ''}`,
        { method: 'DELETE', headers: authHeaders() });
      if (res.ok) {
        let body = {};
        try { body = await res.json(); } catch (_) { /* ignore */ }
        // Backend returns staged=true (approval required, VIP still running) or staged=false
        // (never-applied VIP removed at once). Surface its exact message either way.
        (body.staged ? message.info : message.success)(
          body.message || 'Deletion requested.');
        setDeleteTarget(null); fetchVips();
      } else message.error(await fetchApiError(res, 'Delete failed'));
    } catch (e) { message.error('Delete failed: ' + e.message); }
  };

  // Diagnostics: per-member deploy state/ack from GET /api/vip/{id}/status — the live view
  // of what each node reported (installing/applied/error/externally-managed), most useful
  // while a freshly-applied VIP is SYNCING (keepalived install can take ~30s).
  const openDiagnostics = async (vip) => {
    setDiagVip(vip); setDiagData(null); setDiagLoading(true);
    try {
      const res = await fetch(`/api/vip/${vip.id}/status`, { headers: authHeaders() });
      if (res.ok) setDiagData(await res.json());
      else message.error(await fetchApiError(res, 'Failed to load diagnostics'));
    } catch (e) { message.error('Diagnostics failed: ' + e.message); }
    finally { setDiagLoading(false); }
  };

  // Colorful, IP-Inventory/Agent-consistent state: live VRRP MASTER (green, crowned) /
  // BACKUP (orange) / FAULT (red); when the agent hasn't reported a live state yet, show
  // the configured role as a dashed outline tag (same color) so it's clearly "intended,
  // not yet observed". A node whose agent is too old gets an "awaiting agent" flag.
  const renderMembers = (_, vip) => (
    <Space direction="vertical" size={4}>
      {(vip.members || []).map((m) => {
        const live = m.keepalive_state && m.keepalive_state !== 'NONE' ? m.keepalive_state : null;
        const roleColor = m.role === 'MASTER' ? 'green' : 'orange';
        const awaiting = !live && !m.keepalived_capable;
        return (
          <Space key={m.agent_id} size={6}>
            <Text style={{ fontSize: 12 }}>{m.agent_name || `agent ${m.agent_id}`}</Text>
            {live ? (
              <Tooltip title={`Live VRRP state: ${live}`}>
                <Tag
                  color={live === 'MASTER' ? 'green' : live === 'BACKUP' ? 'orange' : 'red'}
                  icon={live === 'MASTER' ? <CrownOutlined /> : undefined}
                  style={{ marginInlineEnd: 0, fontWeight: 600 }}
                >
                  {live}
                </Tag>
              </Tooltip>
            ) : (
              <Tooltip title="Configured role — live VRRP state not observed yet (agent offline or still converging).">
                <Tag color={roleColor} style={{ marginInlineEnd: 0, borderStyle: 'dashed', opacity: 0.85 }}>
                  {m.role}
                </Tag>
              </Tooltip>
            )}
            {awaiting && (
              <Tooltip title="This node's agent does not advertise keepalived_management — upgrade the agent.">
                <Tag color="gold" icon={<WarningOutlined />} style={{ marginInlineEnd: 0 }}>awaiting agent</Tag>
              </Tooltip>
            )}
          </Space>
        );
      })}
    </Space>
  );

  const columns = [
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Virtual IP', key: 'vip', render: (_, v) => <Text code>{v.virtual_ip}/{v.prefix_length}</Text> },
    { title: 'Pool', dataIndex: 'pool_name', key: 'pool' },
    { title: 'VRID', dataIndex: 'virtual_router_id', key: 'vrid' },
    { title: 'Members / Live state', key: 'members', render: renderMembers },
    {
      title: 'Status', key: 'status', render: (_, v) => {
        const s = v.deploy_status || v.last_config_status;
        const d = DEPLOY_STATUS[s] || { color: 'default', label: s, tip: '' };
        const count = (s === 'SYNCING' || s === 'AWAITING' || s === 'ACTIVE' || s === 'DELETING' || s === 'DELETED') && v.deploy_total
          ? ` (${v.deploy_synced}/${v.deploy_total})` : '';
        return (
          <Tooltip title={d.tip}>
            <Tag color={d.color} icon={(s === 'SYNCING' || s === 'DELETING') ? <SyncOutlined spin /> : s === 'AWAITING' ? <ClockCircleOutlined /> : undefined}>
              {(d.label || s)}{count}
            </Tag>
          </Tooltip>
        );
      },
    },
    {
      title: 'Actions', key: 'actions', render: (_, v) => (
        <Space>
          {v.last_config_status === 'PENDING' && (
            <Tooltip title="Apply pending configuration changes">
              <Button type="primary" size="small" icon={<PlayCircleOutlined />}
                onClick={() => { window.location.href = '/apply-management'; }}
                style={{ backgroundColor: '#1890ff', borderColor: '#1890ff' }}>
                Apply
              </Button>
            </Tooltip>
          )}
          <Tooltip title="Edit VIP (changes become PENDING; apply from Apply Management)">
            <Button size="small" icon={<EditOutlined />} onClick={() => openEdit(v)} />
          </Tooltip>
          <Tooltip title="Diagnostics — per-node keepalived deploy status & logs">
            <Button size="small" icon={<FileSearchOutlined />} onClick={() => openDiagnostics(v)} />
          </Tooltip>
          <Tooltip title="Delete VIP">
            <Button size="small" danger icon={<DeleteOutlined />}
              onClick={() => setDeleteTarget(v)} />
          </Tooltip>
        </Space>
      ),
    },
  ];

  // Member-selection table inside the modal — the pool's installed agents (nodes).
  const memberColumns = [
    {
      title: 'Node (agent)', key: 'node', render: (_, r) => (
        <span>
          <Text strong>{r.agent_name}</Text>{' '}
          <Text type="secondary" style={{ fontSize: 12 }}>{r.ip_address ? `(${r.ip_address})` : '(no IP yet)'}</Text>
          {!r.capable && (
            <Tooltip title="This agent doesn't advertise keepalived_management — upgrade it or this node won't deploy.">
              {' '}<Tag color="gold" icon={<WarningOutlined />}>agent too old</Tag>
            </Tooltip>
          )}
        </span>
      ),
    },
    {
      title: 'Participate', key: 'participate', width: 100, render: (_, r) => (
        <Switch checked={r.participate} onChange={(c) => toggleParticipate(r.agent_id, c)} />
      ),
    },
    {
      title: 'Role', key: 'role', width: 130, render: (_, r) => (
        <Select size="small" style={{ width: 110 }} value={r.role} disabled={!r.participate}
          onChange={(val) => setRow(r.agent_id, { role: val, priority: val === 'MASTER' ? 150 : 100 })}>
          <Option value="MASTER">MASTER</Option>
          <Option value="BACKUP">BACKUP</Option>
        </Select>
      ),
    },
    {
      title: 'Priority', key: 'priority', width: 110, render: (_, r) => (
        <InputNumber size="small" min={1} max={254} value={r.priority} disabled={!r.participate}
          onChange={(val) => setRow(r.agent_id, { priority: val })} />
      ),
    },
    {
      title: 'Interface', key: 'iface', width: 160, render: (_, r) => (
        <Select size="small" style={{ width: 140 }} value={r.network_interface || undefined}
          placeholder="interface" disabled={!r.participate} showSearch
          onChange={(val) => setRow(r.agent_id, { network_interface: val })}
          notFoundContent="no interfaces reported"
          options={(r.interfaces || []).map((n) => ({ label: n, value: n }))}
          {...((r.interfaces || []).length === 0 ? { mode: 'tags' } : {})} />
      ),
    },
  ];

  return (
    <div>
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <Title level={2} style={{ margin: 0 }}>HA / VIP (Keepalived)</Title>
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetchVips}>Refresh</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>Create VIP</Button>
          </Space>
        </div>
        {/* The cloud caveat is rarely relevant for the on-prem target audience, so it's a
            subtle, collapsed-by-default info note (not a prominent yellow warning). */}
        <div style={{ marginBottom: 12 }}>
          <Button type="link" size="small" icon={<InfoCircleOutlined />} style={{ paddingLeft: 0 }}
            onClick={() => setShowL2Note((v) => !v)}>
            Network requirements (on-prem / L2)
          </Button>
          {showL2Note && (
            <Alert
              type="info" showIcon style={{ marginTop: 4 }}
              message="On-prem / L2 networks"
              description="VRRP-based VIP failover targets bare-metal / VMware / on-prem L2 segments. On AWS/Azure/GCP, cloud fabrics don't honor VRRP/gratuitous-ARP, so VIPs won't move. Ensure VRRP (IP protocol 112) is permitted by host firewalls."
            />
          )}
        </div>
        <Table rowKey="id" columns={columns} dataSource={vips} loading={loading} pagination={{ pageSize: 10 }} />
      </Card>

      <Modal
        title={editing ? `Edit VIP — ${editing.name}` : 'Create VIP'}
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        onOk={submit}
        okText={editing ? 'Save (PENDING)' : 'Create (PENDING)'}
        width={880}
        destroyOnClose
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label="Name" rules={[{ required: true }]}>
            <Input placeholder="web-vip" disabled={!!editing} />
          </Form.Item>
          <Form.Item name="description" label="Description">
            <Input placeholder="optional" />
          </Form.Item>
          {!editing && (
            <Form.Item name="pool_id" label="Pool" rules={[{ required: true }]}
              tooltip="The VIP's nodes are the HAProxy servers (agents) already enrolled in this pool.">
              <Select placeholder="Select a pool" onChange={(pid) => { setSelectedPoolId(pid); loadPoolMembers(pid); }}>
                {pools.map((p) => <Option key={p.id} value={p.id}>{p.name}</Option>)}
              </Select>
            </Form.Item>
          )}
          <Space size="large" style={{ display: 'flex' }}>
            <Form.Item name="virtual_ip" label="Virtual IP (IPv4)" rules={[{ required: true }]}>
              <Input placeholder="10.0.0.100" />
            </Form.Item>
            <Form.Item name="prefix_length" label="Prefix" rules={[{ required: true }]}>
              <InputNumber min={1} max={32} />
            </Form.Item>
            <Form.Item name="virtual_router_id" label="VRID (blank = auto)">
              <InputNumber min={1} max={255} placeholder="auto" />
            </Form.Item>
            <Form.Item name="advert_int" label="Advert int (s)">
              <InputNumber min={1} max={255} />
            </Form.Item>
          </Space>
          <Space size="large">
            <Form.Item name="use_unicast" label="Unicast VRRP" valuePropName="checked" tooltip="Recommended; works where multicast is blocked.">
              <Switch />
            </Form.Item>
            <Form.Item name="track_haproxy" label="Fail over when HAProxy drops" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="auth_pass" label="VRRP secret (≤8 chars)">
              <Input.Password placeholder={editing ? '•••• (unchanged)' : 'optional'} maxLength={8} />
            </Form.Item>
          </Space>

          <Text strong>Participating nodes</Text>
          <div style={{ color: '#888', fontSize: 12, marginBottom: 8 }}>
            These are the HAProxy servers (agents) already enrolled in this pool — toggle which join the VIP.
            Pick <b>exactly one MASTER</b> (highest priority); the rest are BACKUP. A <b>single node</b> is allowed
            (a keepalived-managed VIP <i>without</i> failover) — add a second node for real HA. Add new servers from
            the standard Agent Management install flow.
          </div>
          <Alert
            type="info" showIcon style={{ marginBottom: 8 }}
            message="keepalived is installed automatically on Apply"
            description={<>On Apply, any participating node that doesn’t already run keepalived will <b>install it from the node’s OS package repositories</b> (apt/dnf/yum/zypper/apk) — make sure the node can reach its repos (internet or an internal mirror). A node already running a <b>hand-managed</b> keepalived is left untouched (reported as “externally managed”).</>}
          />
          <Table
            rowKey="agent_id"
            size="small"
            columns={memberColumns}
            dataSource={memberRows}
            pagination={false}
            locale={{ emptyText: selectedPoolId ? 'No agents in this pool — install agents from Agent Management first.' : 'Select a pool to list its nodes.' }}
          />
        </Form>
      </Modal>

      {/* Delete confirmation with opt-in package uninstall. Enterprise-safe DEFAULT keeps the
          package (just stop/disable + remove our config + release the VIP). */}
      <Modal
        title="Delete VIP — requires approval"
        open={!!deleteTarget}
        onCancel={() => setDeleteTarget(null)}
        onOk={() => deleteVip(deleteTarget, false)}
        okText="Stage deletion for approval"
        okButtonProps={{ danger: true }}
      >
        {deleteTarget && (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Alert
              type="warning"
              showIcon
              message="This does NOT delete the VIP immediately"
              description={<>It stages the deletion for approval. The VIP <b>keeps running, untouched</b>, on its
                member node(s) until you <b>Approve</b> it on the <b>Apply Management</b> page — and you can
                <b> Reject</b> it there to keep it. The node is changed <b>only after approval</b>, so an
                accidental click can't tear down a production VIP.</>}
            />
            <Text>
              Stage deletion of <Text strong>{deleteTarget.name}</Text> ({deleteTarget.virtual_ip}/{deleteTarget.prefix_length})?
              When approved, the member node(s) <b>stop &amp; disable keepalived, remove the config we manage, and release the VIP</b>. The keepalived package itself is left installed, so re-adding a VIP later is instant.
            </Text>
          </Space>
        )}
      </Modal>

      {/* Per-node keepalived deploy diagnostics + node-side log commands (esp. during SYNCING). */}
      <Modal
        title={diagVip ? `Diagnostics — ${diagVip.name}` : 'Diagnostics'}
        open={!!diagVip}
        onCancel={() => { setDiagVip(null); setDiagData(null); }}
        width={780}
        footer={[
          <Button key="refresh" icon={<ReloadOutlined />} onClick={() => diagVip && openDiagnostics(diagVip)}>Refresh</Button>,
          <Button key="close" type="primary" onClick={() => { setDiagVip(null); setDiagData(null); }}>Close</Button>,
        ]}
      >
        {diagLoading && <div style={{ textAlign: 'center', padding: 24 }}><Spin /></div>}
        {!diagLoading && diagData && (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Text type="secondary">
              Staging <Tag>{diagData.last_config_status}</Tag> — each node reports its deploy state after every poll; a fresh keepalived install can take ~30s.
            </Text>
            <Table
              size="small" rowKey={(m) => m.agent_name} pagination={false}
              dataSource={diagData.members || []}
              columns={[
                { title: 'Node', key: 'node', render: (_, m) => (
                  <Space size={4}>
                    <Text style={{ fontSize: 12 }}>{m.agent_name}</Text>
                    {m.role === 'MASTER'
                      ? <Tag color="green" icon={<CrownOutlined />} style={{ marginInlineEnd: 0 }}>MASTER</Tag>
                      : <Tag color="orange" style={{ marginInlineEnd: 0 }}>BACKUP</Tag>}
                  </Space>) },
                { title: 'Agent', dataIndex: 'agent_status', key: 'agent',
                  render: (s) => <Tag color={s === 'online' ? 'green' : 'red'}>{s || 'offline'}</Tag> },
                { title: 'Live VRRP', dataIndex: 'keepalive_state', key: 'live',
                  render: (s) => (s && s !== 'NONE')
                    ? <Tag color={s === 'MASTER' ? 'green' : s === 'BACKUP' ? 'orange' : 'red'}>{s}</Tag>
                    : <Text type="secondary">—</Text> },
                { title: 'Deploy', key: 'deploy', render: (_, m) => {
                    const st = m.deploy_state;
                    const color = st === 'enabled' ? 'green' : st === 'error' ? 'red'
                      : st === 'externally_managed' ? 'gold' : 'blue';
                    return <Tooltip title={m.deploy_message || ''}><Tag color={color}>{m.convergence || st || 'pending'}</Tag></Tooltip>;
                  } },
                { title: 'Last ack', dataIndex: 'deploy_at', key: 'ack',
                  render: (t) => t ? <Text style={{ fontSize: 11 }}>{new Date(t).toLocaleString()}</Text> : <Text type="secondary">—</Text> },
              ]}
            />
            {(diagData.members || []).some((m) => m.deploy_message) && (
              <Card size="small" title="Latest node messages" bodyStyle={{ padding: 8 }}>
                {(diagData.members || []).filter((m) => m.deploy_message).map((m) => (
                  <div key={m.agent_name} style={{ fontSize: 12 }}><Text strong>{m.agent_name}:</Text> {m.deploy_message}</div>
                ))}
              </Card>
            )}
            <Alert
              type="info" showIcon
              message="See the live install / VRRP logs on the node"
              description={
                <pre style={{ margin: 0, fontSize: 11, whiteSpace: 'pre-wrap' }}>{`systemctl status keepalived --no-pager
journalctl -u keepalived --no-pager -n 50
tail -n 100 /var/log/haproxy-agent/agent.log | grep -i keepalived`}</pre>
              }
            />
          </Space>
        )}
        {!diagLoading && !diagData && <Text type="secondary">No diagnostics available.</Text>}
      </Modal>
    </div>
  );
};

export default VIPManagement;
