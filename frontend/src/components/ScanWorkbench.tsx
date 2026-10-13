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
  Lock,
  Copy,
  Check,
  Zap,
  AlertTriangle,
  FileCheck2,
  CheckCircle2,
  Layers,
  Fingerprint,
  Bot,
  UserCheck,
  Clock,
  Eye,
  RefreshCw,
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

const SYNTHETIC_SAMPLE_CLEAN = `Sprint Retrospective & Architectural Notes:
Engineering velocity was 42 story points for the sprint.
Team refactored the in-memory redis cache and improved index compaction latency.
All integration smoke tests passed. Deployed build 2.14.0 to internal staging cluster.`;

const SYNTHETIC_SAMPLE_PII = `Patient Intake Form:
Full Name: Michael R. Henderson
Primary Email: m.henderson@example.org
Phone: (206) 555-0194
Government ID (SSN): 987-65-4320
Insurance Account Number: INS-99482-TX`;

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

  const renderDecisionBadge = (decision?: PolicyAction | string) => {
    switch (decision) {
      case 'BLOCK':
        return (
          <span className="badge badge-block" style={{ fontSize: '0.82rem', padding: '5px 12px' }}>
            <ShieldAlert size={14} strokeWidth={2.5} />
            BLOCK
          </span>
        );
      case 'REQUIRE_APPROVAL':
        return (
          <span className="badge badge-approval" style={{ fontSize: '0.82rem', padding: '5px 12px' }}>
            <Clock size={14} strokeWidth={2} />
            REQUIRE APPROVAL
          </span>
        );
      case 'WARN':
        return (
          <span className="badge badge-warn" style={{ fontSize: '0.82rem', padding: '5px 12px' }}>
            <AlertTriangle size={14} strokeWidth={2} />
            WARN
          </span>
        );
      default:
        return (
          <span className="badge badge-allow" style={{ fontSize: '0.82rem', padding: '5px 12px' }}>
            <CheckCircle2 size={14} strokeWidth={2} />
            ALLOW
          </span>
        );
    }
  };

  const renderSeverityBadge = (sev: string) => {
    let className = 'badge-allow';
    if (sev === 'CRITICAL') className = 'badge-block';
    else if (sev === 'HIGH') className = 'badge-approval';
    else if (sev === 'MEDIUM') className = 'badge-warn';

    return <span className={`badge ${className}`}>{sev}</span>;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Workbench Header */}
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
              Scan Workbench
            </h1>
            <span className="badge badge-mono" style={{ fontSize: '0.68rem' }}>
              Egress Sandbox
            </span>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', maxWidth: '680px', lineHeight: 1.45 }}>
            Evaluate sensitive text payloads against deterministic DLP policies, inspect redactions, and receive advisory least-privilege guidance.
          </p>
        </div>

        {/* Sample Presets */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, marginRight: '4px' }}>
            Presets:
          </span>
          <button
            className="btn-ghost"
            onClick={() => {
              setInputText(SYNTHETIC_SAMPLE_LEAK);
              setDestination('PUBLIC_LLM');
              setRecipient('PUBLIC');
              setClassification('CONFIDENTIAL');
            }}
            style={{ fontSize: '0.75rem', padding: '4px 10px', border: '1px solid var(--border-subtle)' }}
          >
            Credential Leak
          </button>
          <button
            className="btn-ghost"
            onClick={() => {
              setInputText(SYNTHETIC_SAMPLE_PII);
              setDestination('EXTERNAL_SAAS');
              setRecipient('THIRD_PARTY_CONTRACTOR');
              setClassification('RESTRICTED');
            }}
            style={{ fontSize: '0.75rem', padding: '4px 10px', border: '1px solid var(--border-subtle)' }}
          >
            PII & Intake
          </button>
          <button
            className="btn-ghost"
            onClick={() => {
              setInputText(SYNTHETIC_SAMPLE_CLEAN);
              setDestination('INTERNAL_SERVICE');
              setRecipient('INTERNAL_EMPLOYEE');
              setClassification('INTERNAL');
            }}
            style={{ fontSize: '0.75rem', padding: '4px 10px', border: '1px solid var(--border-subtle)' }}
          >
            Clean Notes
          </button>
        </div>
      </div>

      {/* Payload Editor Card */}
      <div className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
          <label style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Payload Content
          </label>
          <span className="font-mono text-muted" style={{ fontSize: '0.72rem' }}>
            {inputText.length.toLocaleString()} / 1,000,000 characters
          </span>
        </div>

        {/* Inset Textarea */}
        <textarea
          id="payload-input"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder="Paste code snippet, prompt payload, or document text for sensitive data inspection..."
          rows={7}
          className="font-mono"
          style={{
            width: '100%',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-primary)',
            borderRadius: 'var(--radius-sm)',
            color: 'var(--text-primary)',
            padding: '12px 14px',
            fontSize: '0.82rem',
            lineHeight: 1.5,
            resize: 'vertical',
            marginBottom: '16px',
          }}
        />

        {/* Context Controls Grid */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: '12px',
            padding: '14px',
            background: 'var(--bg-surface)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
            marginBottom: '16px',
          }}
        >
          {/* Destination */}
          <div>
            <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
              Destination Perimeter
            </label>
            <select
              id="select-destination"
              value={destination}
              onChange={(e) => setDestination(e.target.value as DestinationType)}
              style={{ width: '100%', fontSize: '0.82rem' }}
            >
              <option value="PUBLIC_LLM">PUBLIC_LLM (OpenAI, Public Models)</option>
              <option value="EXTERNAL_SAAS">EXTERNAL_SAAS (Third-party Cloud)</option>
              <option value="INTERNAL_SERVICE">INTERNAL_SERVICE (On-prem / VPC)</option>
              <option value="INTERNAL_VECTOR_DB">INTERNAL_VECTOR_DB (Internal RAG)</option>
              <option value="UNSPECIFIED">UNSPECIFIED (Ambiguous)</option>
            </select>
          </div>

          {/* Recipient Trust */}
          <div>
            <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
              Recipient Trust Level
            </label>
            <select
              id="select-recipient"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value as RecipientType)}
              style={{ width: '100%', fontSize: '0.82rem' }}
            >
              <option value="PUBLIC">PUBLIC (Untrusted / External)</option>
              <option value="THIRD_PARTY_CONTRACTOR">THIRD_PARTY_CONTRACTOR (External)</option>
              <option value="INTERNAL_EMPLOYEE">INTERNAL_EMPLOYEE (Verified Org)</option>
              <option value="AUTHORIZED_ANALYST">AUTHORIZED_ANALYST (Compliance Tier)</option>
              <option value="UNKNOWN">UNKNOWN (Ambiguous)</option>
            </select>
          </div>

          {/* Classification */}
          <div>
            <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
              Data Classification
            </label>
            <select
              id="select-classification"
              value={classification}
              onChange={(e) => setClassification(e.target.value as DataClassification)}
              style={{ width: '100%', fontSize: '0.82rem' }}
            >
              <option value="PUBLIC">PUBLIC (Low sensitivity)</option>
              <option value="INTERNAL">INTERNAL (Internal business use)</option>
              <option value="CONFIDENTIAL">CONFIDENTIAL (Proprietary / Regulated)</option>
              <option value="RESTRICTED">RESTRICTED (Critical Keys, PCI)</option>
            </select>
          </div>

          {/* Redaction Strategy */}
          <div>
            <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
              Redaction Strategy
            </label>
            <select
              id="select-redaction-mode"
              value={redactionMode}
              onChange={(e) => setRedactionMode(e.target.value as 'placeholder' | 'synthetic')}
              style={{ width: '100%', fontSize: '0.82rem' }}
            >
              <option value="placeholder">Placeholders ([REDACTED_AWS_KEY])</option>
              <option value="synthetic">Synthetic Tokens ([SECRET_TOKEN_01])</option>
            </select>
          </div>
        </div>

        {/* Scan Action Row */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Shannon entropy, Luhn verification, regex detectors, and deterministic policy precedence active.
          </div>

          <button
            id="btn-analyze-payload"
            className="btn-primary"
            onClick={handleAnalyze}
            disabled={loading}
            style={{ padding: '9px 20px', minWidth: '160px' }}
          >
            {loading ? (
              <>
                <RefreshCw size={14} className="animate-spin" />
                <span>Evaluating...</span>
              </>
            ) : (
              <>
                <Zap size={14} strokeWidth={2} />
                <span>Scan Payload</span>
              </>
            )}
          </button>
        </div>

        {error && (
          <div
            className="card"
            style={{
              marginTop: '14px',
              padding: '12px 16px',
              border: '1px solid #737373',
              color: '#f5f5f5',
              fontSize: '0.82rem',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
            }}
          >
            <AlertTriangle size={15} color="#ffffff" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Analysis Results View */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Executive Summary Bar */}
          <div
            className="card"
            style={{
              padding: '18px 22px',
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))',
              gap: '18px',
              alignItems: 'center',
              background: 'var(--bg-surface)',
            }}
          >
            {/* Policy Enforcement Decision */}
            <div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '6px' }}>
                Deterministic Policy Decision
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {renderDecisionBadge(result.policy_decision)}
                {result.policy_decision === 'BLOCK' && (
                  <span className="badge badge-mono" style={{ fontSize: '0.66rem' }}>
                    Hard-Block Invariant
                  </span>
                )}
              </div>
            </div>

            {/* Risk Score */}
            <div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '6px' }}>
                Heuristic Risk Score
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
                <span style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                  {result.risk_score}
                </span>
                <span className="font-mono text-muted" style={{ fontSize: '0.8rem' }}>/ 100</span>
                <span className="badge badge-outline" style={{ fontSize: '0.68rem' }}>
                  {result.risk_band}
                </span>
              </div>
            </div>

            {/* Audit Chain Link */}
            <div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '6px' }}>
                Cryptographic Audit Seal
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <span
                  className="font-mono text-muted"
                  style={{
                    fontSize: '0.72rem',
                    background: '#151515',
                    padding: '3px 6px',
                    borderRadius: 'var(--radius-xs)',
                    border: '1px solid var(--border-primary)',
                  }}
                  title={result.audit_event_hash || ''}
                >
                  {result.audit_event_hash ? `${result.audit_event_hash.slice(0, 14)}...` : 'N/A'}
                </span>
                <button
                  id="btn-verify-audit"
                  className="btn-secondary"
                  onClick={handleVerifyChain}
                  disabled={verifyingAudit}
                  style={{ fontSize: '0.72rem', padding: '3px 8px' }}
                >
                  <Fingerprint size={11} />
                  {verifyingAudit ? 'Verifying...' : 'Verify Chain'}
                </button>
              </div>
            </div>
          </div>

          {/* Audit Verification Alert Banner */}
          {auditResult && (
            <div
              className="card"
              style={{
                padding: '12px 16px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '0.82rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <FileCheck2 size={16} color="#ffffff" />
                <span>
                  <strong>Audit Status:</strong> {auditResult.details} ({auditResult.verified_events} verified events)
                </span>
              </div>
              <span className="badge badge-mono font-mono" style={{ fontSize: '0.7rem' }}>
                Head: {auditResult.chain_head_hash ? `${auditResult.chain_head_hash.slice(0, 12)}...` : 'None'}
              </span>
            </div>
          )}

          {auditError && (
            <div className="card" style={{ padding: '10px 14px', color: '#f5f5f5', border: '1px solid #737373', fontSize: '0.8rem' }}>
              {auditError}
            </div>
          )}

          {/* Two-Column Core Layout */}
          <div className="soc-workbench-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
            {/* LEFT COLUMN: Deterministic Findings & Triggered Policies */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* Findings Panel */}
              <div className="card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <ShieldAlert size={16} color="#ffffff" strokeWidth={1.8} />
                    <h3 style={{ fontSize: '0.96rem', fontWeight: 600, margin: 0, color: 'var(--text-primary)' }}>
                      Detected Entities ({result.counts.total})
                    </h3>
                  </div>
                  <span className="font-mono text-muted" style={{ fontSize: '0.72rem' }}>
                    Latency: {result.processing_duration_ms} ms
                  </span>
                </div>

                {result.findings.length === 0 ? (
                  <div style={{ padding: '30px 16px', textAlign: 'center', background: 'var(--bg-surface)', borderRadius: 'var(--radius-sm)' }}>
                    <ShieldCheck size={28} color="#ffffff" style={{ margin: '0 auto 8px', opacity: 0.8 }} />
                    <div style={{ fontWeight: 600, fontSize: '0.86rem' }}>Zero Sensitive Entities Detected</div>
                    <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                      No credentials, private tokens, or customer personal identifiers detected.
                    </div>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '420px', overflowY: 'auto' }}>
                    {result.findings.map((f: Finding) => (
                      <div
                        key={f.id}
                        style={{
                          background: 'var(--bg-surface)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 'var(--radius-sm)',
                          padding: '12px 14px',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            {renderSeverityBadge(f.severity)}
                            <span className="badge badge-mono" style={{ fontSize: '0.68rem' }}>
                              {f.category}
                            </span>
                          </div>
                          <span className="font-mono text-muted" style={{ fontSize: '0.72rem' }}>
                            conf: {(f.confidence * 100).toFixed(0)}%
                          </span>
                        </div>

                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <span style={{ fontSize: '0.84rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                            {f.rule_id}
                          </span>
                          <span className="font-mono text-muted" style={{ fontSize: '0.7rem' }}>
                            [{f.start_offset}:{f.end_offset}]
                          </span>
                        </div>

                        {/* Masked Evidence */}
                        <div
                          className="font-mono"
                          style={{
                            background: '#0c0c0c',
                            padding: '5px 8px',
                            borderRadius: 'var(--radius-xs)',
                            fontSize: '0.76rem',
                            color: 'var(--text-primary)',
                            marginBottom: '6px',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px',
                            border: '1px solid var(--border-subtle)',
                          }}
                        >
                          <Lock size={11} color="var(--text-muted)" />
                          <span>Evidence: {f.masked_evidence}</span>
                        </div>

                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {f.suggested_remediation}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Triggered Policies Panel */}
              {result.triggered_policies && result.triggered_policies.length > 0 && (
                <div className="card" style={{ padding: '20px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
                    <Layers size={16} color="#ffffff" strokeWidth={1.8} />
                    <h3 style={{ fontSize: '0.96rem', fontWeight: 600, margin: 0 }}>
                      Triggered Policy Rules ({result.triggered_policies.length})
                    </h3>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {result.triggered_policies.map((p) => (
                      <div
                        key={p.id}
                        style={{
                          background: 'var(--bg-surface)',
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 'var(--radius-sm)',
                          padding: '12px 14px',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span className="font-mono text-primary" style={{ fontSize: '0.8rem', fontWeight: 700 }}>
                              {p.id}
                            </span>
                            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                              {p.name}
                            </span>
                          </div>
                          <span className="badge badge-mono">{p.action}</span>
                        </div>
                        <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                          {p.description}
                        </div>
                        <div style={{ fontSize: '0.73rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
                          Intent: {p.intent_explanation}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* RIGHT COLUMN: Redacted Text Preview & Advisory AI Context Analysis */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              {/* Redacted Preview */}
              <div className="card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Eye size={16} color="#ffffff" strokeWidth={1.8} />
                    <h3 style={{ fontSize: '0.96rem', fontWeight: 600, margin: 0 }}>
                      Non-Destructive Redacted Output
                    </h3>
                  </div>
                  <button
                    className="btn-secondary"
                    onClick={handleCopyRedacted}
                    style={{ fontSize: '0.76rem', padding: '4px 10px' }}
                  >
                    {copied ? (
                      <>
                        <Check size={12} />
                        <span>Copied</span>
                      </>
                    ) : (
                      <>
                        <Copy size={12} />
                        <span>Copy Redacted</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Monospaced Code Panel */}
                <div
                  className="font-mono card-inset"
                  style={{
                    padding: '14px',
                    fontSize: '0.8rem',
                    lineHeight: 1.5,
                    color: 'var(--text-primary)',
                    maxHeight: '260px',
                    overflowY: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                  }}
                >
                  {result.redacted_text}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '8px' }}>
                  Zero raw secrets or sensitive tokens exposed. Safe for downstream logging and audit archival.
                </div>
              </div>

              {/* Advisory AI Context Analysis Panel */}
              {result.ai_analysis && (
                <div className="card" style={{ padding: '20px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Bot size={16} color="#ffffff" strokeWidth={1.8} />
                      <h3 style={{ fontSize: '0.96rem', fontWeight: 600, margin: 0 }}>
                        Advisory AI Context Analysis
                      </h3>
                    </div>

                    <span className="badge badge-mono" style={{ fontSize: '0.68rem' }}>
                      {result.ai_analysis.is_ai_assisted
                        ? `Gemini Active (${result.ai_analysis.model_identifier || 'gemini-2.5-flash'})`
                        : `Fallback Mode (${result.ai_analysis.ai_status})`}
                    </span>
                  </div>

                  {/* Incident Context Summary */}
                  <div
                    style={{
                      padding: '12px 14px',
                      background: 'var(--bg-surface)',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-subtle)',
                      marginBottom: '14px',
                    }}
                  >
                    <div style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '4px' }}>
                      Context Assessment
                    </div>
                    <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                      {result.ai_analysis.incident_summary}
                    </div>
                  </div>

                  {/* Human Review & Risk Factors */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px', marginBottom: '14px' }}>
                    <div
                      style={{
                        padding: '10px 12px',
                        background: 'var(--bg-surface)',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--border-subtle)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                      }}
                    >
                      {result.ai_analysis.human_review_recommended ? (
                        <UserCheck size={16} color="#ffffff" />
                      ) : (
                        <CheckCircle2 size={16} color="var(--text-muted)" />
                      )}
                      <div>
                        <div style={{ fontSize: '0.76rem', fontWeight: 600 }}>
                          {result.ai_analysis.human_review_recommended ? 'Human Review Advised' : 'Automated Clearance'}
                        </div>
                        <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                          {result.ai_analysis.human_review_recommended ? 'Analyst sign-off required' : 'Low risk profile'}
                        </div>
                      </div>
                    </div>

                    {result.ai_analysis.relevant_risk_factors.length > 0 && (
                      <div
                        style={{
                          padding: '10px 12px',
                          background: 'var(--bg-surface)',
                          borderRadius: 'var(--radius-sm)',
                          border: '1px solid var(--border-subtle)',
                        }}
                      >
                        <div style={{ fontSize: '0.68rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>
                          Risk Factors
                        </div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                          {result.ai_analysis.relevant_risk_factors.map((rf, idx) => (
                            <span key={idx} className="badge badge-mono" style={{ fontSize: '0.65rem' }}>
                              {rf}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Advisory Least-Privilege Remediation Plan */}
                  {result.ai_analysis.remediation_recommendations && result.ai_analysis.remediation_recommendations.length > 0 && (
                    <div style={{ marginBottom: '14px' }}>
                      <div style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '8px' }}>
                        Advisory Remediation ({result.ai_analysis.remediation_recommendations.length})
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {result.ai_analysis.remediation_recommendations.map((rec) => (
                          <div
                            key={rec.id}
                            style={{
                              background: 'var(--bg-surface)',
                              border: '1px solid var(--border-subtle)',
                              borderRadius: 'var(--radius-sm)',
                              padding: '10px 12px',
                            }}
                          >
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                              <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                                {rec.title}
                              </span>
                              <span className="badge badge-outline" style={{ fontSize: '0.64rem' }}>
                                {rec.action_type.replace(/_/g, ' ')}
                              </span>
                            </div>
                            <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                              {rec.explanation}
                            </div>
                            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                              🛡️ Expected Benefit: {rec.expected_security_benefit}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Legal/Architectural Invariance Disclaimer */}
                  <div
                    style={{
                      paddingTop: '10px',
                      borderTop: '1px solid var(--border-subtle)',
                      fontSize: '0.7rem',
                      color: 'var(--text-muted)',
                      fontStyle: 'italic',
                    }}
                  >
                    {result.ai_analysis.disclaimer}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <style>{`
        @media (max-width: 960px) {
          .soc-workbench-grid {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </div>
  );
};
