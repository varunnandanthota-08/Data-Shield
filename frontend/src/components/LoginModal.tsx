import React, { useState, useEffect } from 'react';
import {
  Shield,
  Lock,
  User,
  Mail,
  AlertTriangle,
  KeyRound,
  CheckCircle2,
  UserPlus,
  ArrowLeft,
  Info,
  RefreshCw,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import {
  checkRegistrationStatus,
  registerUser,
  RegistrationStatusResponse,
} from '../api/client';

export const LoginModal: React.FC = () => {
  const { requiresBootstrap, login, setupAdmin } = useAuth();

  const [mode, setMode] = useState<'signin' | 'create_user'>('signin');

  // Sign-in state
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [adminNotice, setAdminNotice] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Registration state
  const [registrationStatus, setRegistrationStatus] = useState<RegistrationStatusResponse | null>(null);
  const [statusLoading, setStatusLoading] = useState(false);
  const [regUsername, setRegUsername] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regConfirmPassword, setRegConfirmPassword] = useState('');
  const [regError, setRegError] = useState<string | null>(null);
  const [regSuccess, setRegSuccess] = useState<string | null>(null);
  const [regSubmitting, setRegSubmitting] = useState(false);

  const fetchRegStatus = async () => {
    setStatusLoading(true);
    try {
      const st = await checkRegistrationStatus();
      setRegistrationStatus(st);
    } catch {
      setRegistrationStatus({
        allow_public_registration: false,
        registration_mode: 'admin_provisioned',
        message: 'Administrator-managed user creation is enforced.',
      });
    } finally {
      setStatusLoading(false);
    }
  };

  useEffect(() => {
    if (mode === 'create_user') {
      fetchRegStatus();
    }
  }, [mode]);

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      if (requiresBootstrap) {
        if (!username.trim() || !email.trim() || !password) {
          setError('Please complete all required fields.');
          setIsSubmitting(false);
          return;
        }
        if (password.length < 10) {
          setError('Administrator password must be at least 10 characters.');
          setIsSubmitting(false);
          return;
        }
        await setupAdmin(username.trim(), email.trim(), password);
      } else {
        if (!username.trim() || !password) {
          setError('Please enter both username and password.');
          setIsSubmitting(false);
          return;
        }
        await login(username.trim(), password);
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setRegError(null);
    setRegSuccess(null);

    if (!regUsername.trim() || !regEmail.trim() || !regPassword) {
      setRegError('Please complete all required fields.');
      return;
    }

    if (regPassword.length < 8) {
      setRegError('Password must be at least 8 characters in length.');
      return;
    }

    if (regPassword !== regConfirmPassword) {
      setRegError('Passwords do not match. Please verify.');
      return;
    }

    setRegSubmitting(true);
    try {
      const createdUser = await registerUser({
        username: regUsername.trim(),
        email: regEmail.trim().toLowerCase(),
        password: regPassword,
      });

      setRegSuccess(`Account for "${createdUser.username}" registered successfully! You may now sign in.`);
      // Pre-fill username on sign-in form
      setUsername(createdUser.username);
      setPassword('');
      setRegUsername('');
      setRegEmail('');
      setRegPassword('');
      setRegConfirmPassword('');
    } catch (err: any) {
      setRegError(err.message || 'Registration failed. Please verify submission.');
    } finally {
      setRegSubmitting(false);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'rgba(8, 8, 8, 0.98)',
        backdropFilter: 'blur(8px)',
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '20px',
      }}
    >
      <div
        className="card"
        style={{
          width: '100%',
          maxWidth: '460px',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-strong)',
          borderRadius: 'var(--radius-md)',
          boxShadow: '0 20px 40px rgba(0, 0, 0, 0.6)',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '26px 28px 20px',
            borderBottom: '1px solid var(--border-subtle)',
            background: 'linear-gradient(180deg, #181818 0%, #121212 100%)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div
                style={{
                  width: '38px',
                  height: '38px',
                  borderRadius: 'var(--radius-sm)',
                  background: '#1f1f1f',
                  border: '1px solid var(--border-strong)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                {mode === 'create_user' ? (
                  <UserPlus size={20} color="#ffffff" strokeWidth={2} />
                ) : (
                  <Shield size={22} color="#ffffff" strokeWidth={2} />
                )}
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: '1.1rem', letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
                  DataShield AI
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  {requiresBootstrap
                    ? 'Initial Administrator Setup'
                    : mode === 'create_user'
                    ? 'Account & User Creation'
                    : 'SOC Security Gateway'}
                </div>
              </div>
            </div>

            {mode === 'create_user' && (
              <button
                type="button"
                onClick={() => {
                  setMode('signin');
                  setRegError(null);
                  setRegSuccess(null);
                }}
                style={{
                  background: 'transparent',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '5px 9px',
                  color: 'var(--text-secondary)',
                  fontSize: '0.76rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  cursor: 'pointer',
                }}
                title="Return to sign in"
              >
                <ArrowLeft size={13} />
                <span>Sign In</span>
              </button>
            )}
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.4, margin: 0 }}>
            {requiresBootstrap
              ? 'Zero-trust initialization: configure the primary administrator account. No default credentials exist.'
              : mode === 'create_user'
              ? 'Create a new account or view enterprise administrator user provisioning rules.'
              : 'Sign in to access the SOC Workbench, DLP policy controls, and hash-chained audit verification.'}
          </p>
        </div>

        {/* Form Body - Sign In Flow */}
        {mode === 'signin' && (
          <form onSubmit={handleSignIn} style={{ padding: '24px 28px' }}>
            {adminNotice && (
              <div
                style={{
                  marginBottom: '18px',
                  padding: '12px 14px',
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(59, 130, 246, 0.1)',
                  border: '1px solid rgba(59, 130, 246, 0.3)',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '10px',
                  fontSize: '0.82rem',
                  color: '#93c5fd',
                }}
              >
                <Info size={16} color="#3b82f6" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div style={{ lineHeight: 1.4 }}>{adminNotice}</div>
              </div>
            )}

            {error && (
              <div
                style={{
                  marginBottom: '18px',
                  padding: '12px 14px',
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '10px',
                  fontSize: '0.82rem',
                  color: '#fca5a5',
                }}
              >
                <AlertTriangle size={16} color="#ef4444" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div style={{ lineHeight: 1.4 }}>{error}</div>
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label
                  style={{
                    display: 'block',
                    fontSize: '0.76rem',
                    fontWeight: 600,
                    color: 'var(--text-secondary)',
                    marginBottom: '6px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em',
                  }}
                >
                  Username or Email
                </label>
                <div style={{ position: 'relative' }}>
                  <span
                    style={{
                      position: 'absolute',
                      left: '12px',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      color: 'var(--text-muted)',
                      display: 'flex',
                    }}
                  >
                    <User size={16} />
                  </span>
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder={requiresBootstrap ? 'e.g. soc_admin' : 'Username or Email'}
                    autoComplete="username"
                    style={{
                      width: '100%',
                      padding: '10px 12px 10px 38px',
                      borderRadius: 'var(--radius-sm)',
                      background: '#151515',
                      border: '1px solid var(--border-strong)',
                      color: 'var(--text-primary)',
                      fontSize: '0.86rem',
                      outline: 'none',
                    }}
                  />
                </div>
              </div>

              {requiresBootstrap && (
                <div>
                  <label
                    style={{
                      display: 'block',
                      fontSize: '0.76rem',
                      fontWeight: 600,
                      color: 'var(--text-secondary)',
                      marginBottom: '6px',
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                    }}
                  >
                    Administrator Work Email
                  </label>
                  <div style={{ position: 'relative' }}>
                    <span
                      style={{
                        position: 'absolute',
                        left: '12px',
                        top: '50%',
                        transform: 'translateY(-50%)',
                        color: 'var(--text-muted)',
                        display: 'flex',
                      }}
                    >
                      <Mail size={16} />
                    </span>
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="admin@datashield.ai"
                      autoComplete="email"
                      style={{
                        width: '100%',
                        padding: '10px 12px 10px 38px',
                        borderRadius: 'var(--radius-sm)',
                        background: '#151515',
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-primary)',
                        fontSize: '0.86rem',
                        outline: 'none',
                      }}
                    />
                  </div>
                </div>
              )}

              <div>
                <label
                  style={{
                    display: 'block',
                    fontSize: '0.76rem',
                    fontWeight: 600,
                    color: 'var(--text-secondary)',
                    marginBottom: '6px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em',
                  }}
                >
                  Password {requiresBootstrap && <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(min 10 characters)</span>}
                </label>
                <div style={{ position: 'relative' }}>
                  <span
                    style={{
                      position: 'absolute',
                      left: '12px',
                      top: '50%',
                      transform: 'translateY(-50%)',
                      color: 'var(--text-muted)',
                      display: 'flex',
                    }}
                  >
                    <Lock size={16} />
                  </span>
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    autoComplete="current-password"
                    style={{
                      width: '100%',
                      padding: '10px 12px 10px 38px',
                      borderRadius: 'var(--radius-sm)',
                      background: '#151515',
                      border: '1px solid var(--border-strong)',
                      color: 'var(--text-primary)',
                      fontSize: '0.86rem',
                      outline: 'none',
                    }}
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="btn btn-primary"
                style={{
                  marginTop: '6px',
                  width: '100%',
                  padding: '11px',
                  fontWeight: 600,
                  fontSize: '0.88rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  cursor: isSubmitting ? 'not-allowed' : 'pointer',
                  opacity: isSubmitting ? 0.7 : 1,
                }}
              >
                <KeyRound size={16} />
                {isSubmitting
                  ? requiresBootstrap
                    ? 'Provisioning Administrator...'
                    : 'Authenticating...'
                  : requiresBootstrap
                  ? 'Complete Setup & Enter SOC'
                  : 'Authenticate'}
              </button>
            </div>

            {/* Entry point for user creation / registration */}
            {!requiresBootstrap && (
              <div
                style={{
                  marginTop: '20px',
                  paddingTop: '16px',
                  borderTop: '1px solid var(--border-subtle)',
                  textAlign: 'center',
                }}
              >
                <button
                  type="button"
                  id="btn-goto-create-account"
                  onClick={() => {
                    setError(null);
                    setAdminNotice(null);
                    setMode('create_user');
                  }}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--text-secondary)',
                    fontSize: '0.82rem',
                    cursor: 'pointer',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '6px 10px',
                    borderRadius: 'var(--radius-sm)',
                    transition: 'all 120ms ease',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.color = '#ffffff';
                    e.currentTarget.style.background = '#1e1e1e';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.color = 'var(--text-secondary)';
                    e.currentTarget.style.background = 'none';
                  }}
                >
                  <UserPlus size={15} color="#3b82f6" />
                  <span>
                    Need an account or new user?{' '}
                    <strong style={{ color: '#60a5fa' }}>Create account / Provisioning</strong>
                  </span>
                </button>
              </div>
            )}
          </form>
        )}

        {/* Form Body - Create User / Registration Flow */}
        {mode === 'create_user' && (
          <div style={{ padding: '24px 28px' }}>
            {statusLoading ? (
              <div style={{ padding: '30px 0', textAlign: 'center', color: 'var(--text-muted)' }}>
                <RefreshCw size={22} className="spin" style={{ margin: '0 auto 10px' }} />
                <div style={{ fontSize: '0.82rem' }}>Verifying security registration policies...</div>
              </div>
            ) : registrationStatus?.allow_public_registration ? (
              /* Public Self-Registration Form when explicitly enabled */
              <form onSubmit={handleRegister}>
                <div
                  style={{
                    marginBottom: '16px',
                    padding: '10px 12px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'rgba(16, 185, 129, 0.1)',
                    border: '1px solid rgba(16, 185, 129, 0.3)',
                    fontSize: '0.78rem',
                    color: '#6ee7b7',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                  }}
                >
                  <CheckCircle2 size={15} color="#10b981" />
                  <span>Public registration enabled. New accounts receive Viewer role by default.</span>
                </div>

                {regSuccess && (
                  <div
                    style={{
                      marginBottom: '16px',
                      padding: '12px 14px',
                      borderRadius: 'var(--radius-sm)',
                      background: 'rgba(16, 185, 129, 0.15)',
                      border: '1px solid rgba(16, 185, 129, 0.4)',
                      fontSize: '0.82rem',
                      color: '#a7f3d0',
                    }}
                  >
                    <div style={{ fontWeight: 600, marginBottom: '6px' }}>{regSuccess}</div>
                    <button
                      type="button"
                      onClick={() => setMode('signin')}
                      style={{
                        background: '#10b981',
                        border: 'none',
                        color: '#000000',
                        fontWeight: 600,
                        fontSize: '0.78rem',
                        padding: '6px 12px',
                        borderRadius: 'var(--radius-sm)',
                        cursor: 'pointer',
                        marginTop: '4px',
                      }}
                    >
                      Return to Sign In Now
                    </button>
                  </div>
                )}

                {regError && (
                  <div
                    style={{
                      marginBottom: '16px',
                      padding: '12px 14px',
                      borderRadius: 'var(--radius-sm)',
                      background: 'rgba(239, 68, 68, 0.1)',
                      border: '1px solid rgba(239, 68, 68, 0.3)',
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '10px',
                      fontSize: '0.82rem',
                      color: '#fca5a5',
                    }}
                  >
                    <AlertTriangle size={16} color="#ef4444" style={{ flexShrink: 0, marginTop: '2px' }} />
                    <div style={{ lineHeight: 1.4 }}>{regError}</div>
                  </div>
                )}

                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  <div>
                    <label
                      style={{
                        display: 'block',
                        fontSize: '0.74rem',
                        fontWeight: 600,
                        color: 'var(--text-secondary)',
                        marginBottom: '5px',
                        textTransform: 'uppercase',
                        letterSpacing: '0.04em',
                      }}
                    >
                      Desired Username
                    </label>
                    <input
                      type="text"
                      required
                      value={regUsername}
                      onChange={(e) => setRegUsername(e.target.value)}
                      placeholder="e.g. jdoe_analyst"
                      style={{
                        width: '100%',
                        padding: '9px 12px',
                        borderRadius: 'var(--radius-sm)',
                        background: '#151515',
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-primary)',
                        fontSize: '0.86rem',
                        outline: 'none',
                      }}
                    />
                  </div>

                  <div>
                    <label
                      style={{
                        display: 'block',
                        fontSize: '0.74rem',
                        fontWeight: 600,
                        color: 'var(--text-secondary)',
                        marginBottom: '5px',
                        textTransform: 'uppercase',
                        letterSpacing: '0.04em',
                      }}
                    >
                      Work Email
                    </label>
                    <input
                      type="email"
                      required
                      value={regEmail}
                      onChange={(e) => setRegEmail(e.target.value)}
                      placeholder="user@enterprise.com"
                      style={{
                        width: '100%',
                        padding: '9px 12px',
                        borderRadius: 'var(--radius-sm)',
                        background: '#151515',
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-primary)',
                        fontSize: '0.86rem',
                        outline: 'none',
                      }}
                    />
                  </div>

                  <div>
                    <label
                      style={{
                        display: 'block',
                        fontSize: '0.74rem',
                        fontWeight: 600,
                        color: 'var(--text-secondary)',
                        marginBottom: '5px',
                        textTransform: 'uppercase',
                        letterSpacing: '0.04em',
                      }}
                    >
                      Password <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(min 8 characters)</span>
                    </label>
                    <input
                      type="password"
                      required
                      value={regPassword}
                      onChange={(e) => setRegPassword(e.target.value)}
                      placeholder="••••••••••••"
                      style={{
                        width: '100%',
                        padding: '9px 12px',
                        borderRadius: 'var(--radius-sm)',
                        background: '#151515',
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-primary)',
                        fontSize: '0.86rem',
                        outline: 'none',
                      }}
                    />
                  </div>

                  <div>
                    <label
                      style={{
                        display: 'block',
                        fontSize: '0.74rem',
                        fontWeight: 600,
                        color: 'var(--text-secondary)',
                        marginBottom: '5px',
                        textTransform: 'uppercase',
                        letterSpacing: '0.04em',
                      }}
                    >
                      Confirm Password
                    </label>
                    <input
                      type="password"
                      required
                      value={regConfirmPassword}
                      onChange={(e) => setRegConfirmPassword(e.target.value)}
                      placeholder="••••••••••••"
                      style={{
                        width: '100%',
                        padding: '9px 12px',
                        borderRadius: 'var(--radius-sm)',
                        background: '#151515',
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-primary)',
                        fontSize: '0.86rem',
                        outline: 'none',
                      }}
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={regSubmitting}
                    className="btn btn-primary"
                    style={{
                      marginTop: '6px',
                      width: '100%',
                      padding: '11px',
                      fontWeight: 600,
                      fontSize: '0.88rem',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '8px',
                      cursor: regSubmitting ? 'not-allowed' : 'pointer',
                    }}
                  >
                    <UserPlus size={16} />
                    {regSubmitting ? 'Registering...' : 'Create Account'}
                  </button>

                  <div style={{ textAlign: 'center', marginTop: '10px' }}>
                    <button
                      type="button"
                      onClick={() => setMode('signin')}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-muted)',
                        fontSize: '0.80rem',
                        cursor: 'pointer',
                        textDecoration: 'underline',
                      }}
                    >
                      Already have credentials? Return to Sign In
                    </button>
                  </div>
                </div>
              </form>
            ) : (
              /* Enterprise Zero-Trust Policy Notice when public registration is disabled (DEFAULT) */
              <div>
                <div
                  style={{
                    padding: '16px',
                    borderRadius: 'var(--radius-sm)',
                    background: '#141414',
                    border: '1px solid var(--border-strong)',
                    marginBottom: '18px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                    <Shield size={18} color="#eab308" />
                    <span style={{ fontWeight: 600, fontSize: '0.88rem', color: '#fef08a' }}>
                      Zero-Trust Access Model
                    </span>
                  </div>
                  <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: '0 0 10px' }}>
                    Public self-registration is disabled in this environment by policy:
                  </p>
                  <div
                    className="font-mono"
                    style={{
                      padding: '6px 10px',
                      background: '#0d0d0d',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '0.74rem',
                      color: '#a3a3a3',
                      marginBottom: '10px',
                      border: '1px solid #222222',
                    }}
                  >
                    ALLOW_PUBLIC_REGISTRATION=false
                  </div>
                  <p style={{ fontSize: '0.80rem', color: 'var(--text-muted)', lineHeight: 1.4, margin: 0 }}>
                    In compliance with enterprise security requirements, all user accounts (Security Analysts, Policy Admins, and Viewers) must be provisioned by an authenticated Administrator.
                  </p>
                </div>

                <div
                  style={{
                    padding: '14px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'rgba(59, 130, 246, 0.08)',
                    border: '1px solid rgba(59, 130, 246, 0.25)',
                    marginBottom: '20px',
                    fontSize: '0.80rem',
                    color: '#93c5fd',
                    lineHeight: 1.45,
                  }}
                >
                  <strong>How to create users:</strong>
                  <ol style={{ margin: '8px 0 0', paddingLeft: '18px' }}>
                    <li>Sign in with your <strong>Administrator</strong> credentials.</li>
                    <li>Navigate to the <strong>Identity & RBAC</strong> tab in the SOC navigation bar.</li>
                    <li>Click <strong>+ Provision User</strong> to assign roles and tenant organizations.</li>
                  </ol>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <button
                    type="button"
                    onClick={() => {
                      setMode('signin');
                      setAdminNotice('Sign in with your Administrator credentials to access the user provisioning dashboard.');
                    }}
                    className="btn btn-primary"
                    style={{
                      width: '100%',
                      padding: '11px',
                      fontWeight: 600,
                      fontSize: '0.86rem',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '8px',
                      cursor: 'pointer',
                    }}
                  >
                    <KeyRound size={15} />
                    <span>Sign In as Administrator to Provision Users</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setMode('signin')}
                    style={{
                      width: '100%',
                      padding: '9px',
                      background: 'transparent',
                      border: '1px solid var(--border-subtle)',
                      color: 'var(--text-secondary)',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '0.82rem',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '6px',
                    }}
                  >
                    <ArrowLeft size={14} />
                    <span>Return to Sign In</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Security Profile Footer */}
        <div
          style={{
            padding: '12px 28px 16px',
            background: '#111111',
            borderTop: '1px solid var(--border-subtle)',
            fontSize: '0.72rem',
            color: 'var(--text-muted)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <CheckCircle2 size={13} color="#10b981" />
            <span>Argon2id Hash Protection</span>
          </div>
          <span className="font-mono">Rate-Limited Guard</span>
        </div>
      </div>
    </div>
  );
};
