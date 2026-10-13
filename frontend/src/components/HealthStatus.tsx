import React from 'react';
import { HealthCheckResult } from '../api/client';
import { ShieldAlert, Cpu, Activity, RefreshCw } from 'lucide-react';

interface Props {
  result: HealthCheckResult | null;
  loading: boolean;
  onRefresh: () => void;
}

export const HealthStatus: React.FC<Props> = ({ result, loading, onRefresh }) => {
  const isHealthy = result?.data?.status === 'healthy';

  return (
    <div className="glass-panel" style={{ padding: '28px', maxWidth: '800px', margin: '0 auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div className={isHealthy ? 'beacon-online' : 'beacon-offline'} />
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700, letterSpacing: '-0.02em' }}>
            Gateway Health & Node Status
          </h2>
        </div>
        <button
          className="btn-secondary"
          onClick={onRefresh}
          disabled={loading}
          style={{ padding: '8px 14px', fontSize: '0.85rem' }}
        >
          <RefreshCw size={15} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
          {loading ? 'Pinging...' : 'Ping Node'}
        </button>
      </div>

      {result?.error ? (
        <div
          style={{
            background: 'rgba(244, 63, 94, 0.1)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            borderRadius: 'var(--radius-md)',
            padding: '16px',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            color: '#fb7185',
          }}
        >
          <ShieldAlert size={22} />
          <div>
            <div style={{ fontWeight: 600 }}>Backend Connection Unreachable</div>
            <div style={{ fontSize: '0.85rem', color: '#fda4af' }}>{result.error}</div>
          </div>
        </div>
      ) : result?.data ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
          <div
            style={{
              background: 'rgba(15, 23, 42, 0.6)',
              padding: '16px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '6px' }}>CORE SERVICE</div>
            <div style={{ fontWeight: 600, fontSize: '1.05rem', color: 'var(--text-primary)' }}>
              {result.data.service}
            </div>
            <div style={{ marginTop: '8px' }}>
              <span className="badge badge-success">v{result.data.version}</span>
            </div>
          </div>

          <div
            style={{
              background: 'rgba(15, 23, 42, 0.6)',
              padding: '16px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '6px' }}>ROUNDTRIP LATENCY</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
              <span style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                {result.latencyMs}
              </span>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>ms</span>
            </div>
            <div style={{ marginTop: '8px' }}>
              <span className="badge badge-info">Direct Loopback</span>
            </div>
          </div>

          <div
            style={{
              background: 'rgba(15, 23, 42, 0.6)',
              padding: '16px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '6px' }}>AI ENGINE STATUS</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
              <Cpu size={18} color={result.data.environment.llm_configured ? 'var(--accent-emerald)' : 'var(--accent-amber)'} />
              <span style={{ fontWeight: 600 }}>
                {result.data.environment.llm_configured ? 'Ready (Gemini API)' : 'Not Configured'}
              </span>
            </div>
            <div style={{ marginTop: '8px' }}>
              <span className={result.data.environment.llm_configured ? 'badge badge-success' : 'badge badge-neutral'}>
                {result.data.environment.llm_configured ? 'Copilot Active' : 'Fallback Engine'}
              </span>
            </div>
          </div>

          <div
            style={{
              background: 'rgba(15, 23, 42, 0.6)',
              padding: '16px',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginBottom: '6px' }}>ENVIRONMENT</div>
            <div style={{ fontWeight: 600, fontSize: '1.05rem', textTransform: 'capitalize' }}>
              {result.data.environment.mode}
            </div>
            <div style={{ marginTop: '8px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              {new Date(result.data.timestamp).toLocaleTimeString()}
            </div>
          </div>
        </div>
      ) : (
        <div style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
          <Activity size={32} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
          <div>Checking gateway health...</div>
        </div>
      )}
    </div>
  );
};
