import React, { useEffect, useRef, useState } from 'react';
import {
  Card,
  Form,
  Input,
  Button,
  message,
  Typography,
  Row,
  Col,
  Alert,
} from 'antd';
import {
  UserOutlined,
  LockOutlined,
  ClusterOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';
import axios from 'axios';
import { useAuth } from '../contexts/AuthContext';
import { extractApiError } from '../utils/apiError';
import './Login.css';

const { Title, Text } = Typography;

const PHASE_CREDENTIALS = 'credentials';
const PHASE_MFA = 'mfa';
const PHASE_SUBMITTING = 'submitting';

const Login = () => {
  const [credentialsForm] = Form.useForm();
  const [mfaForm] = Form.useForm();
  const [phase, setPhase] = useState(PHASE_CREDENTIALS);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();

  // MFA-specific state — RAM only, never persisted.
  const mfaTokenRef = useRef(null);
  const [mfaExpiresAt, setMfaExpiresAt] = useState(null);
  const [mfaCountdown, setMfaCountdown] = useState(0);

  useEffect(() => {
    if (phase !== PHASE_MFA || !mfaExpiresAt) return undefined;
    const id = setInterval(() => {
      const remaining = Math.max(0, Math.floor((mfaExpiresAt - Date.now()) / 1000));
      setMfaCountdown(remaining);
      if (remaining <= 0) {
        clearInterval(id);
        resetToCredentials('MFA session expired. Please log in again.');
      }
    }, 1000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, mfaExpiresAt]);

  const resetToCredentials = (errMessage) => {
    mfaTokenRef.current = null;
    setMfaExpiresAt(null);
    setMfaCountdown(0);
    mfaForm.resetFields();
    setPhase(PHASE_CREDENTIALS);
    if (errMessage) setError(errMessage);
  };

  const completeAuth = (authData) => {
    // Write storage + axios header ONLY after a full, MFA-cleared response.
    localStorage.setItem('token', authData.access_token);
    localStorage.setItem('authToken', authData.access_token);
    localStorage.setItem('userData', JSON.stringify(authData.user));
    localStorage.setItem('userRoles', JSON.stringify([]));
    localStorage.setItem('userPermissions', JSON.stringify({}));
    const expiryDate = new Date();
    expiryDate.setSeconds(expiryDate.getSeconds() + authData.expires_in);
    localStorage.setItem('tokenExpiry', expiryDate.toISOString());
    const loginSuccess = login(authData);
    if (loginSuccess) {
      message.success(`Welcome back, ${authData.user.username}!`);
    } else {
      throw new Error('Failed to update authentication state');
    }
  };

  const handleCredentialsSubmit = async (values) => {
    setLoading(true);
    setPhase(PHASE_SUBMITTING);
    setError('');
    try {
      const response = await axios.post('/api/auth/login', {
        username: values.username,
        password: values.password,
      });

      if (response.data && response.data.mfa_required) {
        // Phase 2 — TOTP / backup code challenge. Keep credentials secret-free.
        mfaTokenRef.current = response.data.mfa_token;
        const ttlSeconds = response.data.expires_in || 300;
        setMfaExpiresAt(Date.now() + ttlSeconds * 1000);
        setMfaCountdown(ttlSeconds);
        setPhase(PHASE_MFA);
        return;
      }

      completeAuth(response.data);
    } catch (err) {
      const errorMessage = extractApiError(err, 'Login failed. Please try again.');
      setError(errorMessage);
      message.error(errorMessage);
      setPhase(PHASE_CREDENTIALS);
    } finally {
      setLoading(false);
    }
  };

  const handleMfaSubmit = async (values) => {
    if (!mfaTokenRef.current) {
      resetToCredentials('MFA session lost. Please log in again.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const response = await axios.post(
        '/api/auth/login/mfa-verify',
        {
          mfa_token: mfaTokenRef.current,
          code: (values.code || '').trim(),
        },
        // Explicit opt-out: never attach a stale Authorization header here.
        { headers: { Authorization: undefined } },
      );
      completeAuth(response.data);
    } catch (err) {
      const status = err && err.response && err.response.status;
      const errorMessage = extractApiError(err, 'Verification failed.');
      if (status === 410) {
        resetToCredentials(errorMessage || 'MFA challenge invalidated. Please log in again.');
      } else {
        setError(errorMessage);
        mfaForm.setFieldsValue({ code: '' });
      }
    } finally {
      setLoading(false);
    }
  };

  const renderCredentialsForm = () => (
    <Form
      form={credentialsForm}
      name="login"
      onFinish={handleCredentialsSubmit}
      layout="vertical"
      autoComplete="off"
    >
      <Form.Item
        name="username"
        rules={[
          { required: true, message: 'Please enter your username!' },
          { min: 3, message: 'Username must be at least 3 characters!' },
        ]}
      >
        <Input prefix={<UserOutlined />} placeholder="Username" autoComplete="username" />
      </Form.Item>

      <Form.Item
        name="password"
        rules={[
          { required: true, message: 'Please enter your password!' },
          { min: 6, message: 'Password must be at least 6 characters!' },
        ]}
      >
        <Input.Password
          prefix={<LockOutlined />}
          placeholder="Password"
          autoComplete="current-password"
        />
      </Form.Item>

      <Form.Item style={{ marginBottom: 0 }}>
        <Button
          type="primary"
          htmlType="submit"
          loading={loading}
          block
          className="login-button"
        >
          {loading ? 'Signing in...' : 'Sign In'}
        </Button>
      </Form.Item>
    </Form>
  );

  const renderMfaForm = () => {
    const minutes = Math.floor(mfaCountdown / 60);
    const seconds = String(mfaCountdown % 60).padStart(2, '0');
    return (
      <Form form={mfaForm} name="mfa" onFinish={handleMfaSubmit} layout="vertical" autoComplete="off">
        <Alert
          message="Multi-Factor Authentication"
          description={
            <span>
              Enter the 6-digit code from your authenticator app, or use a backup code
              (format: <code>XXXX-YYYY</code>).
              {mfaCountdown > 0 && (
                <>
                  {' '}Session expires in <strong>{minutes}:{seconds}</strong>.
                </>
              )}
            </span>
          }
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
        />
        <Form.Item
          name="code"
          rules={[
            { required: true, message: 'Please enter your MFA code.' },
            { min: 6, message: 'Code must be at least 6 characters.' },
            { max: 10, message: 'Code is too long.' },
          ]}
        >
          <Input
            prefix={<SafetyCertificateOutlined />}
            placeholder="123456 or XXXX-YYYY"
            autoComplete="one-time-code"
            inputMode="text"
            maxLength={10}
            autoFocus
          />
        </Form.Item>
        <Form.Item style={{ marginBottom: 8 }}>
          <Button
            type="primary"
            htmlType="submit"
            loading={loading}
            block
            className="login-button"
          >
            {loading ? 'Verifying...' : 'Verify'}
          </Button>
        </Form.Item>
        <Form.Item style={{ marginBottom: 0 }}>
          <Button
            type="default"
            block
            onClick={() => resetToCredentials('')}
            disabled={loading}
          >
            Use a different account
          </Button>
        </Form.Item>
      </Form>
    );
  };

  return (
    <div className="login-container">
      <Row
        justify="center"
        align="middle"
        style={{
          minHeight: '100vh',
          minHeight: '100dvh',
          width: '100%',
          margin: 0,
        }}
      >
        <Col
          xs={24}
          sm={20}
          md={16}
          lg={12}
          xl={10}
          xxl={8}
          style={{
            display: 'flex',
            justifyContent: 'center',
            padding: '0 8px',
          }}
        >
          <Card className="login-card">
            <div className="login-header">
              <ClusterOutlined className="login-icon" />
              <Title level={2} className="login-title">
                HAProxy OpenManager
              </Title>
              <Text type="secondary" className="login-subtitle">
                Multi-Cluster Load Balancer Management
              </Text>
            </div>

            {error && (
              <Alert
                message={error}
                type="error"
                showIcon
                style={{ marginBottom: 24 }}
                closable
                onClose={() => setError('')}
              />
            )}

            {phase === PHASE_MFA ? renderMfaForm() : renderCredentialsForm()}

            <div className="login-footer">
              <Text
                type="secondary"
                style={{ fontSize: 12, display: 'block', textAlign: 'center' }}
              >
                Centralized management for multiple HAProxy clusters
              </Text>
            </div>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Login;
