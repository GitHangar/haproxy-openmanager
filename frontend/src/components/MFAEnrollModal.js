import React, { useEffect, useRef, useState } from 'react';
import {
  Modal,
  Steps,
  Form,
  Input,
  Button,
  Alert,
  Typography,
  Space,
  Checkbox,
  message,
} from 'antd';
import { QRCodeSVG } from 'qrcode.react';
import axios from 'axios';
import { extractApiError } from '../utils/apiError';

const { Text, Paragraph } = Typography;

const STEP_SETUP = 0;
const STEP_VERIFY = 1;
const STEP_BACKUP = 2;

/**
 * MFA enrollment wizard. Strictly modal-controlled: the modal cannot be
 * dismissed via the X / mask in step 2/3 — backup codes are shown only once
 * and the server-side pending row is opaque after enrollment confirms.
 */
const MFAEnrollModal = ({ open, onClose, onEnrolled }) => {
  const [verifyForm] = Form.useForm();
  const [step, setStep] = useState(STEP_SETUP);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [otpauthUri, setOtpauthUri] = useState('');
  const [secret, setSecret] = useState('');
  const [backupCodes, setBackupCodes] = useState([]);
  const [savedAcknowledged, setSavedAcknowledged] = useState(false);
  const startedRef = useRef(false);

  useEffect(() => {
    if (!open) return undefined;
    if (startedRef.current) return undefined;
    startedRef.current = true;
    startEnrollment();
    return () => {
      // No-op: cleanup happens via the explicit handleClose path.
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const resetState = () => {
    setStep(STEP_SETUP);
    setLoading(false);
    setError('');
    setOtpauthUri('');
    setSecret('');
    setBackupCodes([]);
    setSavedAcknowledged(false);
    startedRef.current = false;
    verifyForm.resetFields();
  };

  const startEnrollment = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await axios.post('/api/mfa/enroll/start', {});
      setOtpauthUri(response.data.otpauth_uri);
      setSecret(response.data.secret);
    } catch (err) {
      setError(extractApiError(err, 'Could not start MFA enrollment.'));
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async (values) => {
    setLoading(true);
    setError('');
    try {
      const response = await axios.post('/api/mfa/enroll/confirm', {
        code: (values.code || '').trim(),
      });
      setBackupCodes(response.data.backup_codes || []);
      setStep(STEP_BACKUP);
    } catch (err) {
      setError(extractApiError(err, 'Verification failed.'));
      verifyForm.setFieldsValue({ code: '' });
    } finally {
      setLoading(false);
    }
  };

  const handleCopyAll = () => {
    const text = backupCodes.join('\n');
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        () => message.success('Backup codes copied to clipboard'),
        () => message.error('Could not copy. Please copy manually.'),
      );
    } else {
      message.warning('Clipboard API unavailable. Please copy manually.');
    }
  };

  const handleDownload = () => {
    const blob = new Blob(
      [
        'HAProxy OpenManager — MFA backup codes\n',
        'Generated: ' + new Date().toISOString() + '\n',
        'Each code is single-use. Store them somewhere safe and offline.\n\n',
        ...backupCodes.map((c) => c + '\n'),
      ],
      { type: 'text/plain;charset=utf-8' },
    );
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'haproxy-openmanager-mfa-backup-codes.txt';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleClose = (force = false) => {
    if (step === STEP_BACKUP && !savedAcknowledged && !force) return;
    resetState();
    if (step === STEP_BACKUP) {
      if (typeof onEnrolled === 'function') onEnrolled();
    } else if (typeof onClose === 'function') {
      onClose();
    }
  };

  const renderSetup = () => (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Paragraph>
        Open your authenticator app (Google Authenticator, Authy, 1Password, Microsoft
        Authenticator) and scan this QR code, or enter the secret manually.
      </Paragraph>
      <div style={{ display: 'flex', justifyContent: 'center' }}>
        {otpauthUri ? (
          <QRCodeSVG value={otpauthUri} size={220} level="M" includeMargin />
        ) : (
          <Text type="secondary">Generating…</Text>
        )}
      </div>
      {secret && (
        <Alert
          message="Trouble scanning?"
          description={
            <Space direction="vertical" size={4}>
              <Text>Enter this secret manually in your authenticator app:</Text>
              <Text code copyable={{ text: secret }} style={{ fontSize: 16 }}>
                {secret}
              </Text>
            </Space>
          }
          type="info"
          showIcon
        />
      )}
      <div style={{ textAlign: 'right' }}>
        <Space>
          <Button onClick={() => handleClose(true)}>Cancel</Button>
          <Button
            type="primary"
            onClick={() => setStep(STEP_VERIFY)}
            disabled={!otpauthUri}
          >
            I&apos;ve added the account
          </Button>
        </Space>
      </div>
    </Space>
  );

  const renderVerify = () => (
    <Form form={verifyForm} layout="vertical" onFinish={handleVerify}>
      <Alert
        message="Verify your authenticator"
        description="Enter the 6-digit code displayed by your authenticator app. You have 5 attempts before the enrollment is invalidated and you'll need to start over."
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
      />
      <Form.Item
        name="code"
        label="Authenticator code"
        rules={[
          { required: true, message: 'Please enter the 6-digit code.' },
          { len: 6, message: 'Code must be exactly 6 digits.' },
        ]}
      >
        <Input
          placeholder="123456"
          autoComplete="one-time-code"
          inputMode="numeric"
          maxLength={6}
          autoFocus
        />
      </Form.Item>
      <div style={{ textAlign: 'right' }}>
        <Space>
          <Button onClick={() => setStep(STEP_SETUP)} disabled={loading}>
            Back
          </Button>
          <Button onClick={() => handleClose(true)} disabled={loading}>
            Cancel
          </Button>
          <Button type="primary" htmlType="submit" loading={loading}>
            Verify
          </Button>
        </Space>
      </div>
    </Form>
  );

  const renderBackup = () => (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Alert
        message="Save your backup codes now"
        description={
          <>
            Each code can be used <strong>once</strong> when you can&apos;t access your
            authenticator. <strong>They won&apos;t be shown again.</strong> If you lose
            them, ask an administrator to reset your MFA.
          </>
        }
        type="warning"
        showIcon
      />
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '8px 16px',
          padding: '12px',
          backgroundColor: 'var(--ant-color-fill-quaternary, #fafafa)',
          borderRadius: 6,
        }}
      >
        {backupCodes.map((code) => (
          <Text key={code} code style={{ fontSize: 15, letterSpacing: 1 }}>
            {code}
          </Text>
        ))}
      </div>
      <Space>
        <Button onClick={handleCopyAll}>Copy all</Button>
        <Button onClick={handleDownload}>Download .txt</Button>
      </Space>
      <Checkbox
        checked={savedAcknowledged}
        onChange={(e) => setSavedAcknowledged(e.target.checked)}
      >
        I have saved my backup codes somewhere safe.
      </Checkbox>
      <div style={{ textAlign: 'right' }}>
        <Button
          type="primary"
          disabled={!savedAcknowledged}
          onClick={() => handleClose(false)}
        >
          Close
        </Button>
      </div>
    </Space>
  );

  return (
    <Modal
      open={open}
      title="Enable Multi-Factor Authentication"
      width={520}
      footer={null}
      closable={false}
      maskClosable={false}
      destroyOnClose
      keyboard={false}
    >
      <Steps
        size="small"
        current={step}
        items={[{ title: 'Set up' }, { title: 'Verify' }, { title: 'Backup codes' }]}
        style={{ marginBottom: 24 }}
      />
      {error && (
        <Alert
          message={error}
          type="error"
          showIcon
          closable
          onClose={() => setError('')}
          style={{ marginBottom: 16 }}
        />
      )}
      {step === STEP_SETUP && renderSetup()}
      {step === STEP_VERIFY && renderVerify()}
      {step === STEP_BACKUP && renderBackup()}
    </Modal>
  );
};

export default MFAEnrollModal;
