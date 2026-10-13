import React, { useState, useEffect, useCallback } from 'react';
import { fetchPolicies, PolicyRule, PolicyAction } from '../api/client';
import {
  RefreshCw,
  Lock,
  Info,
  ShieldAlert,
  Clock,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';

export const PolicyExplorerView: React.FC = () => {
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [enabledOnly, setEnabledOnly] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadPolicies = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchPolicies(enabledOnly);
      // Sort by priority descending
      setPolicies(data.sort((a, b) => b.priority - a.priority));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch policy rules');
    } finally {
      setLoading(false);
    }
  }, [enabledOnly]);

  useEffect(() => {
    loadPolicies();
  }, [loadPolicies]);

  const renderDecisionBadge = (action: PolicyAction | string) => {
    switch (action) {
      case 'BLOCK':
        return (
          <span className="badge badge-block">
            <ShieldAlert size={10} strokeWidth={2.5} />
            BLOCK
          </span>
        );
      case 'REQUIRE_APPROVAL':
        return (
          <span className="badge badge-approval">
            <Clock size={10} strokeWidth={2} />
            REQUIRE APPROVAL
          </span>
        );
      case 'WARN':
        return (
          <span className="badge badge-warn">
            <AlertTriangle size={10} strokeWidth={2} />
            WARN
          </span>
        );
      default:
        return (
          <span className="badge badge-allow">
            <CheckCircle2 size={10} strokeWidth={2} />
            ALLOW
          </span>
        );
    }
  };

  const blockCount = policies.filter((p) => p.action === 'BLOCK').length;
  const approvalCount = policies.filter((p) => p.action === 'REQUIRE_APPROVAL').length;
  const warnCount = policies.filter((p) => p.action === 'WARN').length;
  const allowCount = policies.filter((p) => p.action === 'ALLOW').length;

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
              Policy Explorer
            </h1>
            <span className="badge badge-mono font-mono" style={{ fontSize: '0.68rem' }}>
              {policies.length} Registered Rules
            </span>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', maxWidth: '660px' }}>
            Deterministic DLP rules evaluated against findings, destination perimeters, and recipient trust boundaries.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.78rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={enabledOnly}
              onChange={(e) => setEnabledOnly(e.target.checked)}
              style={{ cursor: 'pointer' }}
            />
            Enabled Only
          </label>

          <button
            className="btn-secondary"
            onClick={loadPolicies}
            disabled={loading}
            style={{ fontSize: '0.78rem', padding: '6px 12px' }}
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Summary KPI Strip */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '12px' }}>
        <div className="card" style={{ padding: '14px 16px' }}>
          <div style={{ fontSize: '0.68rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Total Rules
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
            {policies.length}
          </div>
        </div>
        <div className="card" style={{ padding: '14px 16px' }}>
          <div style={{ fontSize: '0.68rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Hard Blocks
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
            {blockCount}
          </div>
        </div>
        <div className="card" style={{ padding: '14px 16px' }}>
          <div style={{ fontSize: '0.68rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Approval Required
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
            {approvalCount}
          </div>
        </div>
        <div className="card" style={{ padding: '14px 16px' }}>
          <div style={{ fontSize: '0.68rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Warnings
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
            {warnCount}
          </div>
        </div>
        <div className="card" style={{ padding: '14px 16px' }}>
          <div style={{ fontSize: '0.68rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Explicit Allows
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
            {allowCount}
          </div>
        </div>
      </div>

      {/* Non-Negotiable Hard-Block Invariant Notice */}
      <div
        className="card"
        style={{
          padding: '14px 18px',
          background: 'var(--bg-surface)',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '12px',
          fontSize: '0.8rem',
          lineHeight: 1.5,
        }}
      >
        <Lock size={16} color="#ffffff" style={{ flexShrink: 0, marginTop: '2px' }} />
        <div>
          <strong style={{ color: '#ffffff' }}>Hard-Block Invariance Principle:</strong>{' '}
          In accordance with deterministic zero-trust DLP enforcement, any triggered <strong>BLOCK</strong> action unconditionally
          overrides ALLOW, WARN, and REQUIRE_APPROVAL regardless of rule priority or advisory AI recommendations. Missing or ambiguous metadata escalates according to POL-004.
        </div>
      </div>

      {error && (
        <div className="card" style={{ padding: '12px', border: '1px solid #737373', fontSize: '0.8rem' }}>
          {error}
        </div>
      )}

      {/* Policy Rules List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        {policies.map((p) => (
          <div key={p.id} className="card" style={{ padding: '18px 20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span className="font-mono text-primary" style={{ fontSize: '0.9rem', fontWeight: 700 }}>
                  {p.id}
                </span>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 600, margin: 0, color: 'var(--text-primary)' }}>
                  {p.name}
                </h3>
                <span className="badge badge-mono font-mono" style={{ fontSize: '0.64rem' }}>
                  v{p.version}
                </span>
                {p.action === 'BLOCK' && (
                  <span className="badge badge-mono" style={{ fontSize: '0.64rem' }}>
                    Hard Invariant
                  </span>
                )}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {renderDecisionBadge(p.action)}
                <span className="badge badge-outline font-mono" style={{ fontSize: '0.68rem' }}>
                  Priority: {p.priority}
                </span>
              </div>
            </div>

            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '14px', lineHeight: 1.45 }}>
              {p.description}
            </p>

            {/* Conditions Tags Grid */}
            <div
              className="card-inset"
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))',
                gap: '12px',
                padding: '12px 14px',
                marginBottom: '12px',
                fontSize: '0.76rem',
              }}
            >
              <div>
                <div style={{ color: 'var(--text-muted)', marginBottom: '4px', fontWeight: 600, textTransform: 'uppercase', fontSize: '0.66rem' }}>
                  Applicable Categories:
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                  {p.applicable_categories.length > 0 ? (
                    p.applicable_categories.map((c, i) => (
                      <span key={i} className="badge badge-mono" style={{ fontSize: '0.66rem' }}>
                        {c}
                      </span>
                    ))
                  ) : (
                    <span style={{ color: 'var(--text-muted)' }}>Any Category</span>
                  )}
                </div>
              </div>

              <div>
                <div style={{ color: 'var(--text-muted)', marginBottom: '4px', fontWeight: 600, textTransform: 'uppercase', fontSize: '0.66rem' }}>
                  Target Destinations:
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                  {p.target_destinations.length > 0 ? (
                    p.target_destinations.map((d, i) => (
                      <span key={i} className="badge badge-outline font-mono" style={{ fontSize: '0.66rem' }}>
                        {d}
                      </span>
                    ))
                  ) : (
                    <span style={{ color: 'var(--text-muted)' }}>Any Destination</span>
                  )}
                </div>
              </div>

              <div>
                <div style={{ color: 'var(--text-muted)', marginBottom: '4px', fontWeight: 600, textTransform: 'uppercase', fontSize: '0.66rem' }}>
                  Target Recipients:
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                  {p.target_recipients.length > 0 ? (
                    p.target_recipients.map((r, i) => (
                      <span key={i} className="badge badge-mono font-mono" style={{ fontSize: '0.66rem' }}>
                        {r}
                      </span>
                    ))
                  ) : (
                    <span style={{ color: 'var(--text-muted)' }}>Any Recipient</span>
                  )}
                </div>
              </div>

              <div>
                <div style={{ color: 'var(--text-muted)', marginBottom: '4px', fontWeight: 600, textTransform: 'uppercase', fontSize: '0.66rem' }}>
                  Sensitivity Tiers:
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                  {p.applicable_sensitivities.length > 0 ? (
                    p.applicable_sensitivities.map((s, i) => (
                      <span key={i} className="badge badge-outline" style={{ fontSize: '0.66rem' }}>
                        {s}
                      </span>
                    ))
                  ) : (
                    <span style={{ color: 'var(--text-muted)' }}>Any Sensitivity</span>
                  )}
                </div>
              </div>
            </div>

            {/* Audit Intent Explanation */}
            <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Info size={13} color="var(--text-muted)" />
              <span>Audit Rationale: {p.intent_explanation}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
