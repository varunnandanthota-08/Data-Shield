import React, { useState, useEffect, useCallback } from 'react';
import { checkBackendHealth, HealthCheckResult } from './api/client';
import { HealthStatus } from './components/HealthStatus';
import { ScanWorkbench } from './components/ScanWorkbench';
import { Shield, Lock, Terminal, CheckCircle2 } from 'lucide-react';

export const App: React.FC = () => {
  const [healthResult, setHealthResult] = useState<HealthCheckResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchHealth = useCallback(async () => {
    setLoading(true);
    const res = await checkBackendHealth();
    setHealthResult(res);
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 15000); // 15s heartbeat
    return () => clearInterval(interval);
  }, [fetchHealth]);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navbar */}
      <header
        style={{
          borderBottom: '1px solid var(--border-subtle)',
          padding: '16px 32px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          backdropFilter: 'blur(12px)',
          background: 'rgba(7, 11, 18, 0.8)',
          position: 'sticky',
          top: 0,
          zIndex: 50,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div
            style={{
              width: '38px',
              height: '38px',
              borderRadius: '10px',
              background: 'linear-gradient(135deg, rgba(0, 242, 254, 0.2), rgba(2, 132, 199, 0.3))',
              border: '1px solid rgba(0, 242, 254, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 16px rgba(0, 242, 254, 0.2)',
            }}
          >
            <Shield size={20} color="var(--accent-cyan)" />
          </div>
          <div>
            <div style={{ fontWeight: 800, fontSize: '1.15rem', letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>DataShield</span>
              <span style={{ color: 'var(--accent-cyan)', fontSize: '0.85rem', fontWeight: 600, padding: '2px 6px', background: 'rgba(0, 242, 254, 0.1)', borderRadius: '4px' }}>AI</span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              GenAI DLP & Sensitive Data Exposure Gateway
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div className="badge badge-success font-mono" style={{ fontSize: '0.75rem' }}>
            Phase 3 Policy & Audit Engine Active
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            <Lock size={14} color="var(--accent-emerald)" />
            <span>Deterministic Redactor</span>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main style={{ flex: 1, padding: '40px 24px', maxWidth: '1150px', margin: '0 auto', width: '100%' }}>
        {/* Hero Section */}
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div
            className="badge badge-info"
            style={{ marginBottom: '14px', padding: '6px 14px', fontSize: '0.8rem' }}
          >
            Phase 3 Active • Contextual Policies • Composite Risk Scoring • Tamper-Evident Audit Trails
          </div>
          <h1
            style={{
              fontSize: '2.4rem',
              fontWeight: 800,
              letterSpacing: '-0.03em',
              lineHeight: 1.2,
              marginBottom: '14px',
              background: 'linear-gradient(135deg, #ffffff 40%, var(--accent-blue) 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}
          >
            Policy Engine, Risk Scoring & Audit Gateway
          </h1>
          <p
            style={{
              fontSize: '1rem',
              color: 'var(--text-secondary)',
              maxWidth: '680px',
              margin: '0 auto',
              lineHeight: 1.6,
            }}
          >
            Inspect sensitive content, enforce destination-aware security boundaries,
            compute 0-100 composite risk scores, and log SHA-256 hash-chained audit events.
          </p>
        </div>

        {/* Live Interactive Detection & Redaction Workbench */}
        <div style={{ marginBottom: '36px' }}>
          <ScanWorkbench />
        </div>

        {/* Live Backend Connectivity Widget */}
        <div style={{ marginBottom: '36px' }}>
          <HealthStatus result={healthResult} loading={loading} onRefresh={fetchHealth} />
        </div>

        {/* System Architecture Roadmap Progress */}
        <div className="glass-panel" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '18px' }}>
            <Terminal size={18} color="var(--accent-cyan)" />
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Implementation Roadmap Status</h3>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px' }}>
            <div
              style={{
                padding: '16px',
                borderRadius: 'var(--radius-md)',
                background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <CheckCircle2 size={16} color="var(--accent-emerald)" />
                <span style={{ fontWeight: 600, fontSize: '0.9rem', color: '#34d399' }}>Phase 1 (Complete)</span>
              </div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                FastAPI backend, Vite + React TypeScript client, design system tokens, and connectivity telemetry.
              </div>
            </div>

            <div
              style={{
                padding: '16px',
                borderRadius: 'var(--radius-md)',
                background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <CheckCircle2 size={16} color="var(--accent-emerald)" />
                <span style={{ fontWeight: 600, fontSize: '0.9rem', color: '#34d399' }}>Phase 2 (Complete)</span>
              </div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                Multi-tier Detection & Redaction Engine: Regex, Luhn checksums, Shannon entropy, and non-destructive redaction.
              </div>
            </div>

            <div
              style={{
                padding: '16px',
                borderRadius: 'var(--radius-md)',
                background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <CheckCircle2 size={16} color="var(--accent-emerald)" />
                <span style={{ fontWeight: 600, fontSize: '0.9rem', color: '#34d399' }}>Phase 3 (Complete)</span>
              </div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                Deterministic policy engine, composite risk scoring (0-100), and SHA-256 hash-chained audit trails.
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer
        style={{
          borderTop: '1px solid var(--border-subtle)',
          padding: '20px 32px',
          textAlign: 'center',
          fontSize: '0.8rem',
          color: 'var(--text-muted)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          maxWidth: '1100px',
          margin: '0 auto',
          width: '100%',
        }}
      >
        <div>DataShield AI • GenAI DLP & Sensitive Data Exposure</div>
        <div className="font-mono" style={{ fontSize: '0.75rem' }}>
          Loopback API: http://127.0.0.1:8001/api/health
        </div>
      </footer>
    </div>
  );
};

export default App;
