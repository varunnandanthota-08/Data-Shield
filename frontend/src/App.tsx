import React, { useState, useEffect, useCallback } from 'react';
import { checkBackendHealth, HealthCheckResult } from './api/client';
import { Navbar, SOCTab } from './components/Navbar';
import { OverviewDashboard } from './components/OverviewDashboard';
import { ScanWorkbench } from './components/ScanWorkbench';
import { ScanHistoryView } from './components/ScanHistoryView';
import { PolicyExplorerView } from './components/PolicyExplorerView';
import { AuditTrailView } from './components/AuditTrailView';
import { SettingsView } from './components/SettingsView';

export const App: React.FC = () => {
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

  const renderActiveTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewDashboard onNavigate={setActiveTab} />;
      case 'workbench':
        return <ScanWorkbench />;
      case 'history':
        return <ScanHistoryView />;
      case 'policies':
        return <PolicyExplorerView />;
      case 'audit':
        return <AuditTrailView />;
      case 'settings':
        return <SettingsView health={healthResult} onRefreshHealth={fetchHealth} />;
      default:
        return <OverviewDashboard onNavigate={setActiveTab} />;
    }
  };

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
              {activeTab === 'workbench' ? 'Scan Workbench' : activeTab === 'audit' ? 'Audit Trail' : activeTab}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
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
            Loopback Development Profile • v0.1.0
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

export default App;
