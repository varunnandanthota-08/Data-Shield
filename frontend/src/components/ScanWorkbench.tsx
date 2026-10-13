import React, { useState } from 'react';
import {
  scanTextPayload,
  verifyAuditChain,
  ScanResponse,
  Finding,
  DestinationType,
  RecipientType,
  DataClassification,
  PolicyAction,
  AuditVerificationResult,
} from '../api/client';
import {
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Search,
  Eye,
  Lock,
  Copy,
  Check,
  Zap,
  Sparkles,
  AlertTriangle,
  FileCheck2,
  CheckCircle2,
  Layers,
  Fingerprint,
} from 'lucide-react';

const SYNTHETIC_SAMPLE_LEAK = `Incident Report #4092:
Developer submitted customer issue notes:
- Customer Name: Jane Doe
- Contact: jane.doe.sec@example.com, Phone: +1 (555) 349-1102
- SSN on file: 123-45-6789
- Billing Account: 4111-1111-1111-1111 (Visa card via checkout)
- CI/CD Deployment log excerpt:
  export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
  export OPENAI_API_KEY="sk-proj-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"
  export GITHUB_TOKEN="ghp_111122223333444455556666777788889999"
  db_password = 'ProductionMasterSecretKey2026!'
`;

const SYNTHETIC_SAMPLE_CLEAN = `Summary of Quarterly Security Training:
All engineering teams completed the GenAI security protocol refresher.
No credentials, private API tokens, or customer personal identifiers
should ever be passed into unverified public prompts or vector embeddings.`;

export const ScanWorkbench: React.FC = () => {
  const [inputText, setInputText] = useState<string>(SYNTHETIC_SAMPLE_LEAK);
  const [redactionMode, setRedactionMode] = useState<'placeholder' | 'synthetic'>('placeholder');
  const [destination, setDestination] = useState<DestinationType>('PUBLIC_LLM');
  const [recipient, setRecipient] = useState<RecipientType>('PUBLIC');
  const [classification, setClassification] = useState<DataClassification>('CONFIDENTIAL');

  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  // Audit chain verification state
  const [verifyingAudit, setVerifyingAudit] = useState<boolean>(false);
  const [auditResult, setAuditResult] = useState<AuditVerificationResult | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!inputText.trim()) {
      setError('Please provide text to analyze.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const data = await scanTextPayload(
        inputText,
        {
          enable_entropy: true,
          redaction_mode: redactionMode,
        },
        {
          destination,
          recipient,
          classification,
          actor_id: 'analyst_workbench',
        }
      );
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyChain = async () => {
    setVerifyingAudit(true);
    setAuditError(null);
    try {
      const res = await verifyAuditChain();
      setAuditResult(res);
    } catch (err) {
      setAuditError(err instanceof Error ? err.message : 'Audit chain verification failed');
    } finally {
      setVerifyingAudit(false);
    }
  };

  const handleCopyRedacted = () => {
    if (result?.redacted_text) {
      navigator.clipboard.writeText(result.redacted_text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getSeverityStyle = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return { background: 'rgba(244, 63, 94, 0.15)', color: '#fb7185', border: '1px solid rgba(244, 63, 94, 0.4)' };
      case 'HIGH':
        return { background: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.4)' };
      case 'MEDIUM':
        return { background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.4)' };
      default:
        return { background: 'rgba(148, 163, 184, 0.1)', color: '#94a3b8', border: '1px solid rgba(148, 163, 184, 0.2)' };
    }
  };

  const getDecisionBadge = (decision?: PolicyAction | string) => {
    switch (decision) {
      case 'BLOCK':
        return {
          label: 'BLOCK',
          icon: <ShieldX size={16} />,
          style: { background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.5)' },
        };
      case 'REQUIRE_APPROVAL':
        return {
          label: 'REQUIRE APPROVAL',
          icon: <AlertTriangle size={16} />,
          style: { background: 'rgba(245, 158, 11, 0.2)', color: '#fbbf24', border: '1px solid rgba(245, 158, 11, 0.5)' },
        };
      case 'REDACT':
        return {
          label: 'REDACT',
          icon: <Eye size={16} />,
          style: { background: 'rgba(234, 179, 8, 0.2)', color: '#facc15', border: '1px solid rgba(234, 179, 8, 0.5)' },
        };
      case 'WARN':
        return {
          label: 'WARN',
          icon: <AlertTriangle size={16} />,
          style: { background: 'rgba(59, 130, 246, 0.2)', color: '#60a5fa', border: '1px solid rgba(59, 130, 246, 0.5)' },
        };
      default:
        return {
          label: 'ALLOW',
          icon: <CheckCircle2 size={16} />,
          style: { background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.5)' },
        };
    }
  };

  const getRiskBandColor = (band?: string) => {
    switch (band) {
      case 'CRITICAL':
        return '#f43f5e';
      case 'HIGH':
        return '#f59e0b';
      case 'MEDIUM':
        return '#0284c7';
      default:
        return '#10b981';
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Input Workbench Panel */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Search size={18} color="var(--accent-cyan)" />
            <h2 style={{ fontSize: '1.2rem', fontWeight: 700 }}>DLP Inspection & Policy Decision Workbench</h2>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              id="btn-load-leak"
              className="btn-secondary"
              style={{ fontSize: '0.8rem', padding: '6px 12px' }}
              onClick={() => {
                setInputText(SYNTHETIC_SAMPLE_LEAK);
                setDestination('PUBLIC_LLM');
                setRecipient('PUBLIC');
                setClassification('CONFIDENTIAL');
                setResult(null);
              }}
            >
              <Sparkles size={13} color="var(--accent-cyan)" />
              Load Leak Sample
            </button>
            <button
              id="btn-load-clean"
              className="btn-secondary"
              style={{ fontSize: '0.8rem', padding: '6px 12px' }}
              onClick={() => {
                setInputText(SYNTHETIC_SAMPLE_CLEAN);
                setDestination('INTERNAL_SERVICE');
                setRecipient('INTERNAL_EMPLOYEE');
                setClassification('INTERNAL');
                setResult(null);
              }}
            >
              Load Clean Sample
            </button>
          </div>
        </div>

        {/* Text Input Area */}
        <div style={{ marginBottom: '16px' }}>
          <textarea
            id="workbench-prompt-input"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            rows={8}
            placeholder="Paste prompt, source code snippet, or text payload to analyze..."
            style={{
              width: '100%',
              background: 'rgba(7, 11, 18, 0.9)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              color: 'var(--text-primary)',
              padding: '14px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.88rem',
              lineHeight: 1.5,
              resize: 'vertical',
              outline: 'none',
            }}
          />
        </div>

        {/* Phase 3 Sharing Context Controls */}
        <div
          style={{
            background: 'rgba(15, 23, 42, 0.6)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
            padding: '16px',
            marginBottom: '18px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Layers size={15} color="var(--accent-cyan)" />
            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Transfer & Authorization Context (Policy Engine Inputs)
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '5px' }}>
                Target Destination
              </label>
              <select
                id="select-destination"
                value={destination}
                onChange={(e) => setDestination(e.target.value as DestinationType)}
                style={{
                  width: '100%',
                  background: 'rgba(7, 11, 18, 0.85)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  color: 'var(--text-primary)',
                  padding: '8px 10px',
                  fontSize: '0.85rem',
                  outline: 'none',
                }}
              >
                <option value="PUBLIC_LLM">PUBLIC_LLM (OpenAI, Anthropic, Public Prompts)</option>
                <option value="EXTERNAL_SAAS">EXTERNAL_SAAS (Third-party Cloud Software)</option>
                <option value="INTERNAL_SERVICE">INTERNAL_SERVICE (On-premise / VPC Service)</option>
                <option value="INTERNAL_VECTOR_DB">INTERNAL_VECTOR_DB (Internal RAG Store)</option>
                <option value="UNSPECIFIED">UNSPECIFIED (Ambiguous / Missing)</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '5px' }}>
                Recipient Trust Level
              </label>
              <select
                id="select-recipient"
                value={recipient}
                onChange={(e) => setRecipient(e.target.value as RecipientType)}
                style={{
                  width: '100%',
                  background: 'rgba(7, 11, 18, 0.85)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  color: 'var(--text-primary)',
                  padding: '8px 10px',
                  fontSize: '0.85rem',
                  outline: 'none',
                }}
              >
                <option value="PUBLIC">PUBLIC (Untrusted / External Public)</option>
                <option value="THIRD_PARTY_CONTRACTOR">THIRD_PARTY_CONTRACTOR (External Vendor)</option>
                <option value="INTERNAL_EMPLOYEE">INTERNAL_EMPLOYEE (Verified Org Member)</option>
                <option value="AUTHORIZED_ANALYST">AUTHORIZED_ANALYST (Compliance & Security Tier)</option>
                <option value="UNKNOWN">UNKNOWN (Ambiguous / Unverified)</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '5px' }}>
                Data Classification
              </label>
              <select
                id="select-classification"
                value={classification}
                onChange={(e) => setClassification(e.target.value as DataClassification)}
                style={{
                  width: '100%',
                  background: 'rgba(7, 11, 18, 0.85)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  color: 'var(--text-primary)',
                  padding: '8px 10px',
                  fontSize: '0.85rem',
                  outline: 'none',
                }}
              >
                <option value="PUBLIC">PUBLIC (Low sensitivity)</option>
                <option value="INTERNAL">INTERNAL (Internal business use)</option>
                <option value="CONFIDENTIAL">CONFIDENTIAL (Proprietary / Regulated)</option>
                <option value="RESTRICTED">RESTRICTED (Critical PII, Keys, PCI)</option>
              </select>
            </div>
          </div>
        </div>

        {/* Action Controls & Redaction Strategy */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            <span>Redaction Mode:</span>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
              <input
                type="radio"
                name="mode"
                checked={redactionMode === 'placeholder'}
                onChange={() => setRedactionMode('placeholder')}
              />
              Placeholders ([REDACTED_API_KEY])
            </label>
            <label style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
              <input
                type="radio"
                name="mode"
                checked={redactionMode === 'synthetic'}
                onChange={() => setRedactionMode('synthetic')}
              />
              Synthetic Tokens ([SECRET_TOKEN_01])
            </label>
          </div>

          <button
            id="btn-analyze-payload"
            className="btn-primary"
            onClick={handleAnalyze}
            disabled={loading}
            style={{ minWidth: '170px' }}
          >
            {loading ? (
              <>Scanning & Evaluating...</>
            ) : (
              <>
                <Zap size={16} />
                Analyze, Score & Enforce
              </>
            )}
          </button>
        </div>

        {error && (
          <div
            style={{
              marginTop: '16px',
              padding: '12px 16px',
              background: 'rgba(244, 63, 94, 0.1)',
              border: '1px solid rgba(244, 63, 94, 0.3)',
              borderRadius: 'var(--radius-md)',
              color: '#fb7185',
              fontSize: '0.85rem',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
            }}
          >
            <ShieldAlert size={18} />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Analysis Results View */}
      {result && (
        <>
          {/* Phase 3 Security Executive Summary Bar: Decision, Risk Score, Audit Event */}
          <div
            className="glass-panel"
            style={{
              padding: '20px 24px',
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
              gap: '20px',
              alignItems: 'center',
            }}
          >
            {/* Final Policy Decision */}
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
                Policy Enforcement Decision
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                {(() => {
                  const b = getDecisionBadge(result.policy_decision);
                  return (
                    <div
                      id="policy-decision-badge"
                      style={{
                        padding: '6px 14px',
                        borderRadius: 'var(--radius-sm)',
                        fontWeight: 700,
                        fontSize: '0.92rem',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '8px',
                        ...b.style,
                      }}
                    >
                      {b.icon}
                      <span>{b.label}</span>
                    </div>
                  );
                })()}
              </div>
            </div>

            {/* Composite Risk Score Indicator */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Composite Risk Score
                </span>
                <span
                  id="risk-band-badge"
                  style={{
                    fontSize: '0.75rem',
                    fontWeight: 700,
                    color: getRiskBandColor(result.risk_band),
                  }}
                >
                  {result.risk_band || 'LOW'} ({result.risk_score ?? 0}/100)
                </span>
              </div>
              <div
                style={{
                  height: '8px',
                  background: 'rgba(255, 255, 255, 0.1)',
                  borderRadius: '4px',
                  overflow: 'hidden',
                }}
              >
                <div
                  id="risk-score-bar"
                  style={{
                    width: `${result.risk_score ?? 0}%`,
                    height: '100%',
                    background: getRiskBandColor(result.risk_band),
                    transition: 'width 0.4s ease',
                  }}
                />
              </div>
            </div>

            {/* Audit Trail Linkage & Integrity Verification */}
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
                Tamper-Evident Audit Link
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.75rem',
                    color: 'var(--accent-cyan)',
                    background: 'rgba(7, 11, 18, 0.8)',
                    padding: '4px 8px',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border-subtle)',
                  }}
                  title={result.audit_event_hash || ''}
                >
                  hash: {result.audit_event_hash ? `${result.audit_event_hash.slice(0, 12)}...` : 'N/A'}
                </div>
                <button
                  id="btn-verify-audit"
                  className="btn-secondary"
                  onClick={handleVerifyChain}
                  disabled={verifyingAudit}
                  style={{ fontSize: '0.75rem', padding: '4px 10px' }}
                >
                  <Fingerprint size={12} color="var(--accent-cyan)" />
                  {verifyingAudit ? 'Verifying...' : 'Verify Chain'}
                </button>
              </div>
            </div>
          </div>

          {/* Audit Verification Result Alert if checked */}
          {auditResult && (
            <div
              style={{
                padding: '12px 16px',
                borderRadius: 'var(--radius-md)',
                background: auditResult.is_valid ? 'rgba(16, 185, 129, 0.1)' : 'rgba(244, 63, 94, 0.15)',
                border: auditResult.is_valid ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(244, 63, 94, 0.4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '0.85rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <FileCheck2 size={18} color={auditResult.is_valid ? '#34d399' : '#fb7185'} />
                <span>
                  <strong>Audit Chain Status:</strong> {auditResult.details} ({auditResult.verified_events} events verified)
                </span>
              </div>
              <span className="badge font-mono" style={{ fontSize: '0.75rem' }}>
                Head: {auditResult.chain_head_hash ? `${auditResult.chain_head_hash.slice(0, 10)}...` : 'None'}
              </span>
            </div>
          )}

          {auditError && (
            <div style={{ padding: '10px 14px', background: 'rgba(244, 63, 94, 0.1)', color: '#fb7185', borderRadius: 'var(--radius-sm)', fontSize: '0.82rem' }}>
              {auditError}
            </div>
          )}

          {/* Triggered Policies & Decision Explanations Panel */}
          {result.triggered_policies && result.triggered_policies.length > 0 && (
            <div className="glass-panel" style={{ padding: '20px 24px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
                <AlertTriangle size={17} color="var(--accent-cyan)" />
                <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>
                  Triggered Policy Rules & Rationale ({result.triggered_policies.length})
                </h3>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {result.triggered_policies.map((p) => (
                  <div
                    key={p.id}
                    style={{
                      background: 'rgba(15, 23, 42, 0.7)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '12px 16px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="font-mono" style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                          {p.id}
                        </span>
                        <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>{p.name}</span>
                      </div>
                      <span
                        style={{
                          fontSize: '0.72rem',
                          fontWeight: 700,
                          padding: '2px 8px',
                          borderRadius: '4px',
                          ...getDecisionBadge(p.action).style,
                        }}
                      >
                        {p.action}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                      {p.description}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      🛡️ <em>Intent: {p.intent_explanation}</em>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Findings & Redaction Panels */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '24px' }}>
            {/* Findings List Panel */}
            <div className="glass-panel" style={{ padding: '24px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <ShieldAlert size={18} color={result.findings.length > 0 ? '#fb7185' : 'var(--accent-emerald)'} />
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>
                    Detected Entities ({result.counts.total})
                  </h3>
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {result.processing_duration_ms} ms
                </div>
              </div>

              {result.findings.length === 0 ? (
                <div
                  style={{
                    padding: '32px 16px',
                    textAlign: 'center',
                    background: 'rgba(16, 185, 129, 0.05)',
                    border: '1px solid rgba(16, 185, 129, 0.2)',
                    borderRadius: 'var(--radius-md)',
                    color: '#34d399',
                  }}
                >
                  <ShieldCheck size={32} style={{ margin: '0 auto 8px', opacity: 0.9 }} />
                  <div style={{ fontWeight: 600 }}>Zero Sensitive Entities Detected</div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                    No high-confidence PII, PCI cards, cloud tokens, or hardcoded credentials detected in payload.
                  </div>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', maxHeight: '520px', overflowY: 'auto' }}>
                  {result.findings.map((f: Finding) => (
                    <div
                      key={f.id}
                      style={{
                        background: 'rgba(15, 23, 42, 0.7)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-md)',
                        padding: '14px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{ fontSize: '0.72rem', fontWeight: 700, padding: '2px 8px', borderRadius: '4px', ...getSeverityStyle(f.severity) }}>
                            {f.severity}
                          </span>
                          <span className="badge badge-info" style={{ fontSize: '0.7rem' }}>
                            {f.category}
                          </span>
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          conf: {(f.confidence * 100).toFixed(0)}% ({f.confidence_band})
                        </div>
                      </div>

                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                          {f.rule_id}
                        </span>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          offset: [{f.start_offset}:{f.end_offset}]
                        </span>
                      </div>

                      <div
                        style={{
                          background: 'rgba(7, 11, 18, 0.8)',
                          padding: '6px 10px',
                          borderRadius: 'var(--radius-sm)',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.8rem',
                          color: 'var(--accent-cyan)',
                          marginBottom: '8px',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                        }}
                      >
                        <Lock size={12} color="var(--accent-cyan)" />
                        <span>Evidence: {f.masked_evidence}</span>
                      </div>

                      <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                        💡 {f.suggested_remediation}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Redacted Preview Panel */}
            <div className="glass-panel" style={{ padding: '24px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Eye size={18} color="var(--accent-cyan)" />
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Non-Destructive Redacted Output</h3>
                </div>
                <button
                  id="btn-copy-redacted"
                  className="btn-secondary"
                  onClick={handleCopyRedacted}
                  style={{ padding: '6px 12px', fontSize: '0.78rem' }}
                >
                  {copied ? <Check size={13} color="var(--accent-emerald)" /> : <Copy size={13} />}
                  {copied ? 'Copied!' : 'Copy Redacted'}
                </button>
              </div>

              <pre
                style={{
                  background: 'rgba(7, 11, 18, 0.95)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  padding: '16px',
                  color: 'var(--text-code)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.85rem',
                  lineHeight: 1.55,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  maxHeight: '520px',
                  overflowY: 'auto',
                }}
              >
                {result.redacted_text}
              </pre>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
