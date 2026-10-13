import React, { useState, useEffect, useCallback } from 'react';
import { fetchAuditEvents, verifyAuditChain, AuditEvent, AuditVerificationResult } from '../api/client';
import {
  FileCheck2,
  RefreshCw,
  Lock,
  X,
  ShieldCheck,
  ShieldAlert,
  Clock,
  AlertTriangle,
  CheckCircle2,
  Copy,
  Check,
} from 'lucide-react';

export const AuditTrailView: React.FC = () => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [verificationResult, setVerificationResult] = useState<AuditVerificationResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [verifying, setVerifying] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Selected event modal
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const loadAuditData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [eventsRes, verifyRes] = await Promise.all([
        fetchAuditEvents(50, 0),
        verifyAuditChain().catch(() => null),
      ]);
      setEvents(eventsRes.items);
      setTotal(eventsRes.total);
      setVerificationResult(verifyRes);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit trail events');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAuditData();
  }, [loadAuditData]);

  const handleManualVerify = async () => {
    setVerifying(true);
    try {
      const res = await verifyAuditChain();
      setVerificationResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Audit chain verification failed');
    } finally {
      setVerifying(false);
    }
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const renderDecisionBadge = (decision?: string) => {
    switch (decision) {
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
      case 'ALLOW':
        return (
          <span className="badge badge-allow">
            <CheckCircle2 size={10} strokeWidth={2} />
            ALLOW
          </span>
        );
      default:
        return <span className="text-muted">—</span>;
    }
  };

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
              Forensic Audit Trail
            </h1>
            <span className="badge badge-mono font-mono" style={{ fontSize: '0.68rem' }}>
              {total} Chained Events
            </span>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', maxWidth: '660px' }}>
            Tamper-evident SHA-256 hash-chained security log. Each evaluation node cryptographically seals the digest of the preceding event.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            id="btn-verify-audit-trail"
            className="btn-primary"
            onClick={handleManualVerify}
            disabled={verifying}
            style={{ fontSize: '0.8rem', padding: '7px 14px' }}
          >
            <FileCheck2 size={13} strokeWidth={2} />
            {verifying ? 'Verifying Integrity...' : 'Verify Chain Integrity'}
          </button>
          <button
            className="btn-secondary"
            onClick={loadAuditData}
            disabled={loading}
            style={{ fontSize: '0.8rem', padding: '6px 12px' }}
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Verification Status Banner */}
      {verificationResult && (
        <div
          className="card"
          style={{
            padding: '16px 20px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '14px',
            background: 'var(--bg-card)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: 'var(--radius-sm)',
                background: '#101010',
                border: '1px solid var(--border-strong)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              {verificationResult.is_valid ? (
                <ShieldCheck size={18} color="#ffffff" strokeWidth={2} />
              ) : (
                <ShieldAlert size={18} color="#ffffff" strokeWidth={2} />
              )}
            </div>
            <div>
              <div style={{ fontSize: '0.88rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span>{verificationResult.is_valid ? 'Cryptographic Chain Validated' : 'Integrity Compromise Flagged'}</span>
                <span className={`badge ${verificationResult.is_valid ? 'badge-mono' : 'badge-block'}`}>
                  {verificationResult.is_valid ? 'VALIDATED' : 'CORRUPTED'}
                </span>
              </div>
              <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                {verificationResult.details} ({verificationResult.verified_events} sequential events verified)
              </div>
            </div>
          </div>

          <div className="font-mono text-muted" style={{ fontSize: '0.72rem' }}>
            Head Digest: {verificationResult.chain_head_hash ? `${verificationResult.chain_head_hash.slice(0, 18)}...` : 'N/A'}
          </div>
        </div>
      )}

      {/* Architectural Disclaimer Notice */}
      <div
        className="card"
        style={{
          padding: '12px 16px',
          background: 'var(--bg-surface)',
          display: 'flex',
          alignItems: 'flex-start',
          gap: '10px',
          fontSize: '0.78rem',
          color: 'var(--text-muted)',
          lineHeight: 1.5,
        }}
      >
        <Lock size={15} color="#ffffff" style={{ flexShrink: 0, marginTop: '2px' }} />
        <div>
          <strong style={{ color: '#ffffff' }}>Tamper-Evidence Architectural Scope:</strong> Local SHA-256 hash chaining detects
          intermediate payload modification, row deletion, and event reordering within the application runtime. It does not provide hardware-anchored
          WORM storage against an attacker with root direct filesystem rewrite access. Sanitized metadata only; zero raw secrets stored.
        </div>
      </div>

      {error && (
        <div className="card" style={{ padding: '12px', border: '1px solid #737373', fontSize: '0.8rem' }}>
          {error}
        </div>
      )}

      {/* Audit Events Table */}
      <div className="card" style={{ overflow: 'hidden' }}>
        {events.length === 0 ? (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            No audit events found. Run scans in the Workbench to generate audit trail records.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Seq #</th>
                  <th>Timestamp</th>
                  <th>Event Type</th>
                  <th>Scan Reference</th>
                  <th>Decision</th>
                  <th>Chained SHA-256 Digest</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.event_id}>
                    <td className="font-mono text-primary" style={{ fontSize: '0.76rem', fontWeight: 700 }}>
                      #{e.sequence_number.toString().padStart(4, '0')}
                    </td>
                    <td className="font-mono text-muted" style={{ fontSize: '0.73rem' }}>
                      {new Date(e.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span className="badge badge-mono font-mono" style={{ fontSize: '0.66rem' }}>
                        {e.event_type}
                      </span>
                    </td>
                    <td className="font-mono text-secondary" style={{ fontSize: '0.74rem' }}>
                      {e.scan_id ? `${e.scan_id.slice(0, 10)}...` : '—'}
                    </td>
                    <td>{renderDecisionBadge(e.policy_decision)}</td>
                    <td className="font-mono" style={{ fontSize: '0.72rem' }}>
                      <span className="text-muted">{e.prev_event_hash.slice(0, 6)}...</span>
                      <span className="text-muted" style={{ margin: '0 4px' }}>→</span>
                      <span className="text-primary" style={{ fontWeight: 600 }}>{e.event_hash.slice(0, 10)}...</span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn-secondary"
                        onClick={() => setSelectedEvent(e)}
                        style={{ fontSize: '0.72rem', padding: '3px 8px' }}
                      >
                        Metadata
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Sanitized Metadata Inspection Modal */}
      {selectedEvent && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.85)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px',
          }}
          onClick={() => setSelectedEvent(null)}
        >
          <div
            className="card"
            style={{
              maxWidth: '740px',
              width: '100%',
              maxHeight: '85vh',
              overflowY: 'auto',
              padding: '24px',
              background: '#0d0d0d',
              border: '1px solid var(--border-strong)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div>
                <h2 style={{ fontSize: '1.15rem', fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
                  Audit Event #{selectedEvent.sequence_number} Inspection
                </h2>
                <span className="font-mono text-muted" style={{ fontSize: '0.7rem' }}>
                  Event UUID: {selectedEvent.event_id}
                </span>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                aria-label="Close modal"
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Hash Display */}
            <div style={{ marginBottom: '14px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <span style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Event SHA-256 Digest
                </span>
                <button
                  className="btn-ghost"
                  onClick={() => handleCopyHash(selectedEvent.event_hash)}
                  style={{ fontSize: '0.7rem', padding: '2px 6px' }}
                >
                  {copiedHash === selectedEvent.event_hash ? <Check size={11} /> : <Copy size={11} />}
                  <span>{copiedHash === selectedEvent.event_hash ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <div
                className="font-mono card-inset"
                style={{ padding: '8px 10px', fontSize: '0.75rem', color: 'var(--text-primary)', wordBreak: 'break-all' }}
              >
                {selectedEvent.event_hash}
              </div>
            </div>

            {/* Parent Hash */}
            <div style={{ marginBottom: '14px' }}>
              <span style={{ display: 'block', fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px' }}>
                Parent Block Digest (Prev Hash)
              </span>
              <div
                className="font-mono card-inset"
                style={{ padding: '8px 10px', fontSize: '0.75rem', color: 'var(--text-secondary)', wordBreak: 'break-all' }}
              >
                {selectedEvent.prev_event_hash}
              </div>
            </div>

            {/* Sanitized Metadata JSON */}
            <div>
              <span style={{ display: 'block', fontSize: '0.72rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px' }}>
                Sanitized Event Payload Metadata (JSON)
              </span>
              <pre
                className="card-inset font-mono"
                style={{
                  padding: '12px',
                  fontSize: '0.78rem',
                  lineHeight: 1.5,
                  color: 'var(--text-primary)',
                  maxHeight: '300px',
                  overflowY: 'auto',
                }}
              >
                {JSON.stringify(selectedEvent.sanitized_metadata, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
