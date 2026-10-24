import React, { useState, useEffect, useCallback } from 'react';
import {
  Users,
  UserPlus,
  ShieldCheck,
  Trash2,
  ToggleLeft,
  ToggleRight,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
} from 'lucide-react';
import {
  UserResponse,
  UserRole,
  fetchUsers,
  createUser,
  updateUser,
  deleteUser,
} from '../api/client';
import { useAuth } from '../context/AuthContext';

export const UserManagementView: React.FC = () => {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<UserResponse[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Modal State for user provisioning
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newUsername, setNewUsername] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<UserRole>('analyst');
  const [newOrgId, setNewOrgId] = useState('default');
  const [isCreating, setIsCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const loadUsers = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await fetchUsers();
      setUsers(data);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve user registry');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError(null);
    setIsCreating(true);

    try {
      if (!newUsername.trim() || !newEmail.trim() || !newPassword) {
        setCreateError('Please complete all required fields.');
        setIsCreating(false);
        return;
      }
      if (newPassword.length < 8) {
        setCreateError('Password must be at least 8 characters.');
        setIsCreating(false);
        return;
      }

      await createUser({
        username: newUsername.trim(),
        email: newEmail.trim().toLowerCase(),
        password: newPassword,
        role: newRole,
        org_id: newOrgId.trim() || 'default',
      });

      setSuccessMsg(`User "${newUsername}" provisioned successfully with role "${newRole.toUpperCase()}".`);
      setShowCreateModal(false);
      setNewUsername('');
      setNewEmail('');
      setNewPassword('');
      setNewRole('analyst');
      loadUsers();
      setTimeout(() => setSuccessMsg(null), 4000);
    } catch (err: any) {
      setCreateError(err.message || 'Failed to create user');
    } finally {
      setIsCreating(false);
    }
  };

  const handleToggleActive = async (targetUser: UserResponse) => {
    try {
      await updateUser(targetUser.id, { is_active: !targetUser.is_active });
      loadUsers();
    } catch (err: any) {
      setError(err.message || 'Failed to update user status');
    }
  };

  const handleDeleteUser = async (targetUser: UserResponse) => {
    if (!window.confirm(`Permanently delete user account "${targetUser.username}"?`)) {
      return;
    }
    try {
      await deleteUser(targetUser.id);
      setSuccessMsg(`User "${targetUser.username}" removed.`);
      loadUsers();
      setTimeout(() => setSuccessMsg(null), 4000);
    } catch (err: any) {
      setError(err.message || 'Failed to delete user');
    }
  };

  const getRoleBadgeStyle = (role: UserRole) => {
    switch (role) {
      case 'admin':
        return {
          background: 'rgba(239, 68, 68, 0.15)',
          color: '#f87171',
          border: '1px solid rgba(239, 68, 68, 0.3)',
        };
      case 'analyst':
        return {
          background: 'rgba(59, 130, 246, 0.15)',
          color: '#60a5fa',
          border: '1px solid rgba(59, 130, 246, 0.3)',
        };
      case 'viewer':
        return {
          background: 'rgba(156, 163, 175, 0.15)',
          color: '#d1d5db',
          border: '1px solid rgba(156, 163, 175, 0.3)',
        };
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Users size={22} color="#f5f5f5" />
            <h1 style={{ fontSize: '1.4rem', fontWeight: 700, margin: 0, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
              Access Control & User Registry
            </h1>
          </div>
          <p style={{ margin: '6px 0 0', color: 'var(--text-secondary)', fontSize: '0.84rem' }}>
            Manage SOC identity records, enforce role-based permissions, and provision secure access credentials.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            onClick={loadUsers}
            disabled={isLoading}
            className="btn btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem' }}
          >
            <RefreshCw size={14} className={isLoading ? 'spin-animation' : ''} />
            Refresh
          </button>
          <button
            id="btn-provision-user"
            onClick={() => setShowCreateModal(true)}
            className="btn btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem' }}
          >
            <UserPlus size={15} />
            Provision User
          </button>
        </div>
      </div>

      {/* Status Notifications */}
      {error && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: 'var(--radius-sm)',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            color: '#fca5a5',
            fontSize: '0.82rem',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
          }}
        >
          <AlertTriangle size={16} color="#ef4444" />
          <span>{error}</span>
        </div>
      )}

      {successMsg && (
        <div
          style={{
            padding: '12px 16px',
            borderRadius: 'var(--radius-sm)',
            background: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            color: '#6ee7b7',
            fontSize: '0.82rem',
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
          }}
        >
          <CheckCircle size={16} color="#10b981" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* User Table Card */}
      <div className="card" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-primary)', borderRadius: 'var(--radius-md)', overflow: 'hidden' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldCheck size={16} color="var(--text-secondary)" />
            <span style={{ fontSize: '0.86rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Registered SOC Identities ({users.length})
            </span>
          </div>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            Argon2id Hashed • No Plaintext Storage
          </span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'rgba(255,255,255,0.02)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '12px 20px', fontWeight: 600 }}>USER</th>
                <th style={{ padding: '12px 16px', fontWeight: 600 }}>ROLE</th>
                <th style={{ padding: '12px 16px', fontWeight: 600 }}>ORG TENANT</th>
                <th style={{ padding: '12px 16px', fontWeight: 600 }}>STATUS</th>
                <th style={{ padding: '12px 16px', fontWeight: 600 }}>LAST LOGIN</th>
                <th style={{ padding: '12px 20px', fontWeight: 600, textAlign: 'right' }}>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={6} style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    Loading user registry...
                  </td>
                </tr>
              ) : users.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No users found.
                  </td>
                </tr>
              ) : (
                users.map((u) => {
                  const isSelf = u.id === currentUser?.id;
                  const roleStyle = getRoleBadgeStyle(u.role);
                  return (
                    <tr
                      key={u.id}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        background: isSelf ? 'rgba(255, 255, 255, 0.015)' : 'transparent',
                      }}
                    >
                      <td style={{ padding: '14px 20px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <div
                            style={{
                              width: '28px',
                              height: '28px',
                              borderRadius: '50%',
                              background: '#222',
                              border: '1px solid var(--border-subtle)',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontSize: '0.74rem',
                              fontWeight: 700,
                              color: 'var(--text-secondary)',
                            }}
                          >
                            {u.username.substring(0, 2).toUpperCase()}
                          </div>
                          <div>
                            <div style={{ fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                              <span>{u.username}</span>
                              {isSelf && (
                                <span
                                  style={{
                                    fontSize: '0.64rem',
                                    padding: '1px 5px',
                                    borderRadius: '3px',
                                    background: '#262626',
                                    color: 'var(--text-muted)',
                                    fontWeight: 500,
                                  }}
                                >
                                  You
                                </span>
                              )}
                            </div>
                            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>{u.email}</div>
                          </div>
                        </div>
                      </td>
                      <td style={{ padding: '14px 16px' }}>
                        <span
                          style={{
                            padding: '3px 8px',
                            borderRadius: 'var(--radius-xs)',
                            fontSize: '0.7rem',
                            fontWeight: 600,
                            letterSpacing: '0.04em',
                            textTransform: 'uppercase',
                            ...roleStyle,
                          }}
                        >
                          {u.role}
                        </span>
                      </td>
                      <td style={{ padding: '14px 16px', color: 'var(--text-secondary)' }} className="font-mono">
                        {u.org_id}
                      </td>
                      <td style={{ padding: '14px 16px' }}>
                        <span
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '6px',
                            fontSize: '0.74rem',
                            color: u.is_active ? '#10b981' : '#ef4444',
                          }}
                        >
                          <span
                            style={{
                              width: '6px',
                              height: '6px',
                              borderRadius: '50%',
                              background: u.is_active ? '#10b981' : '#ef4444',
                            }}
                          />
                          {u.is_active ? 'Active' : 'Disabled'}
                        </span>
                      </td>
                      <td style={{ padding: '14px 16px', color: 'var(--text-muted)', fontSize: '0.74rem' }}>
                        {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Never'}
                      </td>
                      <td style={{ padding: '14px 20px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                          <button
                            title={isSelf ? 'Cannot disable self' : u.is_active ? 'Disable account' : 'Activate account'}
                            disabled={isSelf}
                            onClick={() => handleToggleActive(u)}
                            style={{
                              background: 'transparent',
                              border: 'none',
                              color: isSelf ? 'var(--text-muted)' : 'var(--text-secondary)',
                              cursor: isSelf ? 'not-allowed' : 'pointer',
                              padding: '4px',
                            }}
                          >
                            {u.is_active ? <ToggleRight size={18} color="#10b981" /> : <ToggleLeft size={18} color="#ef4444" />}
                          </button>
                          <button
                            title={isSelf ? 'Cannot delete self' : 'Permanently remove account'}
                            disabled={isSelf}
                            onClick={() => handleDeleteUser(u)}
                            style={{
                              background: 'transparent',
                              border: 'none',
                              color: isSelf ? 'var(--text-muted)' : '#ef4444',
                              cursor: isSelf ? 'not-allowed' : 'pointer',
                              padding: '4px',
                            }}
                          >
                            <Trash2 size={16} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Permission Matrix Explainer */}
      <div className="card" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-primary)', borderRadius: 'var(--radius-md)', padding: '20px' }}>
        <h3 style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 12px' }}>
          Role-Based Access Control (RBAC) Permission Matrix
        </h3>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', margin: '0 0 16px' }}>
          DataShield AI enforces strict backend authorization on every protected route. Client-side navigation reflects this matrix.
        </p>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.78rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '8px 12px' }}>CAPABILITY / RESOURCE</th>
                <th style={{ padding: '8px 12px' }}>ADMIN</th>
                <th style={{ padding: '8px 12px' }}>ANALYST</th>
                <th style={{ padding: '8px 12px' }}>VIEWER</th>
              </tr>
            </thead>
            <tbody style={{ color: 'var(--text-secondary)' }}>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                <td style={{ padding: '8px 12px', fontWeight: 500 }}>Run Content & File Scans</td>
                <td style={{ padding: '8px 12px', color: '#10b981' }}>✓ Allowed</td>
                <td style={{ padding: '8px 12px', color: '#10b981' }}>✓ Allowed</td>
                <td style={{ padding: '8px 12px', color: '#ef4444' }}>✕ Forbidden (403)</td>
              </tr>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                <td style={{ padding: '8px 12px', fontWeight: 500 }}>Inspect Scan History & Records</td>
                <td style={{ padding: '8px 12px', color: '#10b981' }}>✓ Allowed</td>
                <td style={{ padding: '8px 12px', color: '#10b981' }}>✓ Allowed</td>
                <td style={{ padding: '8px 12px', color: '#10b981' }}>✓ Read-Only</td>
              </tr>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                <td style={{ padding: '8px 12px', fontWeight: 500 }}>Inspect Audit Events & Cryptographic Verification</td>
                <td style={{ padding: '8px 12px', color: '#10b981' }}>✓ Allowed</td>
                <td style={{ padding: '8px 12px', color: '#10b981' }}>✓ Allowed</td>
                <td style={{ padding: '8px 12px', color: '#ef4444' }}>✕ Forbidden (403)</td>
              </tr>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                <td style={{ padding: '8px 12px', fontWeight: 500 }}>Create / Modify / Delete DLP Policies</td>
                <td style={{ padding: '8px 12px', color: '#10b981' }}>✓ Full Mutation</td>
                <td style={{ padding: '8px 12px', color: '#ef4444' }}>✕ Read-Only</td>
                <td style={{ padding: '8px 12px', color: '#ef4444' }}>✕ Read-Only</td>
              </tr>
              <tr>
                <td style={{ padding: '8px 12px', fontWeight: 500 }}>User Management & Identity Provisioning</td>
                <td style={{ padding: '8px 12px', color: '#10b981' }}>✓ Full Management</td>
                <td style={{ padding: '8px 12px', color: '#ef4444' }}>✕ Forbidden (403)</td>
                <td style={{ padding: '8px 12px', color: '#ef4444' }}>✕ Forbidden (403)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Provision User Modal */}
      {showCreateModal && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(4px)',
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
            <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <UserPlus size={18} color="#ffffff" />
              <div style={{ fontWeight: 700, fontSize: '1rem', color: 'var(--text-primary)' }}>
                Provision New SOC Identity
              </div>
            </div>

            <form onSubmit={handleCreateUser} style={{ padding: '24px' }}>
              {createError && (
                <div
                  style={{
                    marginBottom: '16px',
                    padding: '10px 14px',
                    borderRadius: 'var(--radius-sm)',
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    color: '#fca5a5',
                    fontSize: '0.8rem',
                  }}
                >
                  {createError}
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '5px' }}>
                    Username
                  </label>
                  <input
                    type="text"
                    required
                    value={newUsername}
                    onChange={(e) => setNewUsername(e.target.value)}
                    placeholder="e.g. analyst_sarah"
                    style={{
                      width: '100%',
                      padding: '8px 12px',
                      borderRadius: 'var(--radius-sm)',
                      background: '#151515',
                      border: '1px solid var(--border-strong)',
                      color: 'var(--text-primary)',
                      fontSize: '0.84rem',
                    }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '5px' }}>
                    Email Address
                  </label>
                  <input
                    type="email"
                    required
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    placeholder="sarah@corp.com"
                    style={{
                      width: '100%',
                      padding: '8px 12px',
                      borderRadius: 'var(--radius-sm)',
                      background: '#151515',
                      border: '1px solid var(--border-strong)',
                      color: 'var(--text-primary)',
                      fontSize: '0.84rem',
                    }}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '5px' }}>
                    Initial Password (min 8 chars)
                  </label>
                  <input
                    type="password"
                    required
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="••••••••••••"
                    style={{
                      width: '100%',
                      padding: '8px 12px',
                      borderRadius: 'var(--radius-sm)',
                      background: '#151515',
                      border: '1px solid var(--border-strong)',
                      color: 'var(--text-primary)',
                      fontSize: '0.84rem',
                    }}
                  />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '5px' }}>
                      Assigned Role
                    </label>
                    <select
                      value={newRole}
                      onChange={(e) => setNewRole(e.target.value as UserRole)}
                      style={{
                        width: '100%',
                        padding: '8px 10px',
                        borderRadius: 'var(--radius-sm)',
                        background: '#151515',
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-primary)',
                        fontSize: '0.84rem',
                      }}
                    >
                      <option value="analyst">Analyst (Scan + Audit)</option>
                      <option value="viewer">Viewer (Read-Only)</option>
                      <option value="admin">Admin (Full Control)</option>
                    </select>
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '5px' }}>
                      Tenant Org ID
                    </label>
                    <input
                      type="text"
                      disabled={Boolean(currentUser?.org_id && currentUser.org_id !== 'default')}
                      value={currentUser?.org_id && currentUser.org_id !== 'default' ? currentUser.org_id : newOrgId}
                      onChange={(e) => setNewOrgId(e.target.value)}
                      placeholder="default"
                      style={{
                        width: '100%',
                        padding: '8px 12px',
                        borderRadius: 'var(--radius-sm)',
                        background: '#151515',
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-primary)',
                        fontSize: '0.84rem',
                        opacity: currentUser?.org_id && currentUser.org_id !== 'default' ? 0.7 : 1,
                        cursor: currentUser?.org_id && currentUser.org_id !== 'default' ? 'not-allowed' : 'text',
                      }}
                    />
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '14px' }}>
                  <button
                    type="button"
                    onClick={() => setShowCreateModal(false)}
                    className="btn btn-secondary"
                    style={{ fontSize: '0.82rem' }}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isCreating}
                    className="btn btn-primary"
                    style={{ fontSize: '0.82rem' }}
                  >
                    {isCreating ? 'Provisioning...' : 'Create Account'}
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
