import React, { useState, useEffect, useCallback } from 'react';
import { ShieldAlert, Shield } from 'lucide-react';
import { checkBackendHealth, HealthCheckResult } from './api/client';
import { AuthProvider, useAuth } from './context/AuthContext';
import { LoginModal } from './components/LoginModal';
import { Navbar, SOCTab } from './components/Navbar';
import { OverviewDashboard } from './components/OverviewDashboard';
import { ScanWorkbench } from './components/ScanWorkbench';
import { ScanHistoryView } from './components/ScanHistoryView';
import { PolicyExplorerView } from './components/PolicyExplorerView';
import { AuditTrailView } from './components/AuditTrailView';
import { UserManagementView } from './components/UserManagementView';
import { SettingsView } from './components/SettingsView';

const AccessRestrictedCard: React.FC<{ resourceName: string; requiredRole: string }> = ({ resourceName, requiredRole }) => (
  <div
    className="card"
    style={{
      padding: '48px 32px',
      textAlign: 'center',
      background: 'var(--bg-surface)',
      border: '1px solid var(--border-strong)',
      borderRadius: 'var(--radius-md)',
      maxWidth: '600px',
      margin: '60px auto',
    }}
  >
    <div
      style={{
        width: '48px',
        height: '48px',
        borderRadius: '50%',
        background: 'rgba(239, 68, 68, 0.1)',
        border: '1px solid rgba(239, 68, 68, 0.3)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        margin: '0 auto 16px',
      }}
    >
      <ShieldAlert size={24} color="#ef4444" />
    </div>
    <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 8px' }}>
      Access Restricted: {resourceName}
    </h2>
    <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', margin: '0 0 20px', lineHeight: 1.5 }}>
      Your authenticated account role does not have permission to view or execute operations on this resource. Required role level: <strong style={{ color: '#f87171' }}>{requiredRole}</strong>.
    </p>
    <div className="font-mono" style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
      Enforced Server-Side (HTTP 403 Forbidden)
    </div>
  </div>
);

const SOCAppContent: React.FC = () => {
  const { user, isLoading, canScan, canViewAudit, canManageUsers } = useAuth();
  const [activeTab, setActiveTab] = useState<SOCTab>('overview');
  const [healthResult, setHealthResult] = useState<HealthCheckResult | null>(null);

  const fetchHealth = useCallback(async () => {
    const res = await checkBackendHealth();
    setHealthResult(res);
  }, []);

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 15000); // 15s heartbeat
    return () => clearInterval(interval);
  }, [fetchHealth]);

  // Adjust active tab if user lacks permission for current selection
  useEffect(() => {
    if (activeTab === 'workbench' && !canScan) {
      setActiveTab('overview');
    } else if (activeTab === 'audit' && !canViewAudit) {
      setActiveTab('overview');
    } else if (activeTab === 'users' && !canManageUsers) {
      setActiveTab('overview');
    }
  }, [activeTab, canScan, canViewAudit, canManageUsers]);

  const renderActiveTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewDashboard onNavigate={setActiveTab} />;
      case 'workbench':
        return canScan ? <ScanWorkbench /> : <AccessRestrictedCard resourceName="Scan Workbench" requiredRole="Analyst or Admin" />;
      case 'history':
        return <ScanHistoryView />;
      case 'policies':
        return <PolicyExplorerView />;
      case 'audit':
        return canViewAudit ? <AuditTrailView /> : <AccessRestrictedCard resourceName="Audit Trail Verification" requiredRole="Analyst or Admin" />;
      case 'users':
        return canManageUsers ? <UserManagementView /> : <AccessRestrictedCard resourceName="Access Control & User Registry" requiredRole="Administrator" />;
      case 'settings':
        return <SettingsView health={healthResult} onRefreshHealth={fetchHealth} />;
      default:
        return <OverviewDashboard onNavigate={setActiveTab} />;
    }
  };

  if (isLoading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-main)' }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              width: '42px',
              height: '42px',
              borderRadius: 'var(--radius-sm)',
              background: '#1c1c1c',
              border: '1px solid var(--border-strong)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Shield size={24} color="#ffffff" />
          </div>
          <div style={{ fontSize: '0.86rem', color: 'var(--text-muted)' }}>
            Initializing DataShield AI Security Gateway...
          </div>
        </div>
      </div>
    );
  }

  // Guard: If unauthenticated, render LoginModal directly as the primary gateway view.
  // This guarantees that protected workspace views and their authenticated API calls
  // (e.g. OverviewDashboard, ScanHistoryView) do not mount or run before credentials exist.
  if (!user) {
    return <LoginModal />;
  }

  return (
    <div className="soc-layout" style={{ minHeight: '100vh', display: 'flex', background: 'var(--bg-main)' }}>
      {/* Sidebar Navigation */}
      <Navbar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        health={healthResult}
      />

      {/* Main Content Workspace */}
      <div
        className="soc-main-area"
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          minWidth: 0,
          background: 'var(--bg-main)',
        }}
      >
        {/* Workspace Top Header Bar */}
        <header
          style={{
            height: '48px',
            borderBottom: '1px solid var(--border-subtle)',
            padding: '0 32px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'var(--bg-surface)',
            fontSize: '0.78rem',
            color: 'var(--text-muted)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ color: 'var(--text-secondary)' }}>Console</span>
            <span>/</span>
            <span style={{ color: 'var(--text-primary)', fontWeight: 600, textTransform: 'capitalize' }}>
              {activeTab === 'workbench'
                ? 'Scan Workbench'
                : activeTab === 'audit'
                ? 'Audit Trail'
                : activeTab === 'users'
                ? 'Identity & RBAC'
                : activeTab}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            {user && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  background: '#181818',
                  padding: '3px 10px',
                  borderRadius: '12px',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <span
                  style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    background: '#10b981',
                  }}
                />
                <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{user.username}</span>
                <span
                  style={{
                    fontSize: '0.66rem',
                    color:
                      user.role === 'admin'
                        ? '#f87171'
                        : user.role === 'analyst'
                        ? '#60a5fa'
                        : '#9ca3af',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                  }}
                >
                  [{user.role}]
                </span>
              </div>
            )}
            <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              Bound: 127.0.0.1:8001
            </span>
            <div
              style={{
                width: '1px',
                height: '14px',
                background: 'var(--border-strong)',
              }}
            />
            <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
              Deterministic Engine Active
            </span>
          </div>
        </header>

        {/* Content Body */}
        <main
          style={{
            flex: 1,
            padding: '32px',
            maxWidth: '1360px',
            margin: '0 auto',
            width: '100%',
          }}
        >
          {renderActiveTabContent()}
        </main>

        {/* Minimal Enterprise Footer */}
        <footer
          style={{
            borderTop: '1px solid var(--border-subtle)',
            padding: '14px 32px',
            fontSize: '0.74rem',
            color: 'var(--text-muted)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            maxWidth: '1360px',
            margin: '0 auto',
            width: '100%',
            flexWrap: 'wrap',
            gap: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span>DataShield AI • Enterprise SOC Platform</span>
            <span>•</span>
            <span>Deterministic Policy Invariance & Tamper-Evident SHA-256 Audit Trail</span>
          </div>
          <div className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            Argon2id & RBAC Security Profile • v0.2.0
          </div>
        </footer>
      </div>

      <style>{`
        @media (max-width: 899px) {
          .soc-layout {
            flex-direction: column !important;
          }
          .soc-main-area main {
            padding: 20px 16px !important;
          }
        }
      `}</style>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <SOCAppContent />
    </AuthProvider>
  );
};

export default App;

