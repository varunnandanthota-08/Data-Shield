import React from 'react';
import { HealthCheckResult } from '../api/client';
import {
  Server,
  Database,
  ShieldCheck,
  Cpu,
  CheckCircle2,
  RefreshCw,
  Terminal,
} from 'lucide-react';

interface SettingsViewProps {
  health: HealthCheckResult | null;
  onRefreshHealth: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ health, onRefreshHealth }) => {
  const isHealthy = health?.data?.status === 'healthy';
  const isLLM = health?.data?.environment?.llm_configured ?? false;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '22px' }}>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <h1 style={{ fontSize: '1.45rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
              System Configuration & Invariants
            </h1>
            <span className="badge badge-mono font-mono" style={{ fontSize: '0.68rem' }}>
              Runtime Telemetry
            </span>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', maxWidth: '660px' }}>
            DataShield AI runtime environment, detector inventory, AI safety boundaries, and persistence configuration.
          </p>
        </div>

        <button
          className="btn-secondary"
          onClick={onRefreshHealth}
          style={{ fontSize: '0.78rem', padding: '6px 12px' }}
        >
          <RefreshCw size={12} />
          Check Connectivity
        </button>
      </div>

      {/* Grid of Configuration Panels */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        {/* Backend Runtime Panel */}
        <div className="card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
            <Server size={16} color="#ffffff" strokeWidth={1.8} />
            <h3 style={{ fontSize: '0.96rem', fontWeight: 600, margin: 0 }}>Backend Runtime Service</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '0.8rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span className="text-muted">Service Status</span>
              <span style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span className={isHealthy ? 'beacon-dot-live' : 'beacon-dot-offline'} />
                <span className="font-mono">{isHealthy ? 'ONLINE (Healthy)' : 'OFFLINE'}</span>
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span className="text-muted">Host & Gateway Port</span>
              <span className="font-mono text-primary">FastAPI :8001 (Loopback)</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span className="text-muted">Frontend Dev Port</span>
              <span className="font-mono text-primary">Vite :5173</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span className="text-muted">Gateway Latency</span>
              <span className="font-mono text-primary">
                {health?.latencyMs !== undefined ? `${health.latencyMs} ms` : '—'}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span className="text-muted">Framework Version</span>
              <span className="font-mono text-secondary">
                {health?.data?.version || '0.1.0'}
              </span>
            </div>
          </div>
        </div>

        {/* Gemini AI Integration Panel */}
        <div className="card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
            <Cpu size={16} color="#ffffff" strokeWidth={1.8} />
            <h3 style={{ fontSize: '0.96rem', fontWeight: 600, margin: 0 }}>Google GenAI Integration</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '0.8rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span className="text-muted">SDK Driver</span>
              <span className="font-mono text-primary">google-genai v2.30.0</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span className="text-muted">Configured Model</span>
              <span className="font-mono text-primary">gemini-2.5-flash</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span className="text-muted">AI Configuration</span>
              <span className="badge badge-mono">
                {isLLM ? 'API KEY ACTIVE' : 'FALLBACK MODE'}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span className="text-muted">Transient Retries</span>
              <span className="font-mono text-secondary">Max 2 retries with backoff</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span className="text-muted">Remediation Authority</span>
              <span className="text-primary font-mono" style={{ fontWeight: 600 }}>Strictly Advisory</span>
            </div>
          </div>
        </div>

        {/* SQLite Database Panel */}
        <div className="card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
            <Database size={16} color="#ffffff" strokeWidth={1.8} />
            <h3 style={{ fontSize: '0.96rem', fontWeight: 600, margin: 0 }}>Persistence & Cryptography</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '0.8rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span className="text-muted">Database Engine</span>
              <span className="text-primary" style={{ fontWeight: 600 }}>SQLite 3 (WAL Mode)</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span className="text-muted">Ledger Storage</span>
              <span className="font-mono text-primary">backend/datashield.db</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span className="text-muted">Concurrency Control</span>
              <span className="text-secondary font-mono">Thread Lock + Atomic Tx</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span className="text-muted">Audit Cryptography</span>
              <span className="font-mono text-primary">SHA-256 Hash Chain</span>
            </div>
          </div>
        </div>

        {/* Detector Engine Modules */}
        <div className="card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
            <Terminal size={16} color="#ffffff" strokeWidth={1.8} />
            <h3 style={{ fontSize: '0.96rem', fontWeight: 600, margin: 0 }}>DLP Detector Engine Inventory</h3>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '0.78rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <CheckCircle2 size={13} color="#ffffff" />
              <span>Regex Patterns (Email, Phone, US SSN, AWS Key, OpenAI, GitHub Token)</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <CheckCircle2 size={13} color="#ffffff" />
              <span>Luhn Mod-10 Algorithm (Payment Cards with length & check digit validation)</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <CheckCircle2 size={13} color="#ffffff" />
              <span>Shannon Entropy Analyzer (Threshold: 4.2 bits/char for high-randomness secrets)</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <CheckCircle2 size={13} color="#ffffff" />
              <span>Position-Aware Redactor (Span conflict resolution, placeholder & synthetic modes)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Verified Security Invariants Checklist */}
      <div className="card" style={{ padding: '22px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
          <ShieldCheck size={18} color="#ffffff" strokeWidth={2} />
          <h2 style={{ fontSize: '1rem', fontWeight: 600, margin: 0 }}>
            Non-Negotiable Security Invariants
          </h2>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '12px' }}>
          <div className="card-inset" style={{ padding: '12px 14px', display: 'flex', gap: '10px' }}>
            <CheckCircle2 size={15} color="#ffffff" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ fontSize: '0.78rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>Hard-Block Invariance:</strong> BLOCK always overrides ALLOW, WARN, and REQUIRE_APPROVAL regardless of rule priority or AI recommendations.
            </div>
          </div>

          <div className="card-inset" style={{ padding: '12px 14px', display: 'flex', gap: '10px' }}>
            <CheckCircle2 size={15} color="#ffffff" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ fontSize: '0.78rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>Zero Raw Secret Exposure:</strong> Raw credentials and sensitive payloads are never persisted in SQLite audit logs, model prompts, or client responses.
            </div>
          </div>

          <div className="card-inset" style={{ padding: '12px 14px', display: 'flex', gap: '10px' }}>
            <CheckCircle2 size={15} color="#ffffff" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ fontSize: '0.78rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>Advisory Remediation:</strong> AI remediations are strictly non-mutating recommendations; no real ACLs, credentials, or keys are modified automatically.
            </div>
          </div>

          <div className="card-inset" style={{ padding: '12px 14px', display: 'flex', gap: '10px' }}>
            <CheckCircle2 size={15} color="#ffffff" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ fontSize: '0.78rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>Deterministic Fallback:</strong> If Gemini is unconfigured, rate-limited, or returns invalid JSON, the system safely computes explainability from active policies.
            </div>
          </div>

          <div className="card-inset" style={{ padding: '12px 14px', display: 'flex', gap: '10px' }}>
            <CheckCircle2 size={15} color="#ffffff" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ fontSize: '0.78rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>Zero-Trust Context Escalation:</strong> Unspecified egress destinations or unknown recipients with confidential data escalate to REQUIRE_APPROVAL (POL-004).
            </div>
          </div>

          <div className="card-inset" style={{ padding: '12px 14px', display: 'flex', gap: '10px' }}>
            <CheckCircle2 size={15} color="#ffffff" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ fontSize: '0.78rem' }}>
              <strong style={{ color: 'var(--text-primary)' }}>Atomic Hash Chaining:</strong> Scan records and audit events are saved inside a single atomic database transaction with thread-safe sequence locking.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
