import React, { useState, useEffect, useCallback } from 'react';
import {
  fetchSOCMetrics,
  fetchScanRecords,
  verifyAuditChain,
  getAuthToken,
  SOCMetrics,
  ScanRecordItem,
  AuditVerificationResult,
} from '../api/client';
import { useAuth } from '../context/AuthContext';
import {
  ShieldAlert,
  Fingerprint,
  RefreshCw,
  Terminal,
  ArrowRight,
  FileCheck2,
  AlertTriangle,
  Clock,
  Layers,
  Activity,
  CheckCircle2,
  Shield,
} from 'lucide-react';
import { SOCTab } from './Navbar';

interface OverviewDashboardProps {
  onNavigate: (tab: SOCTab) => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({ onNavigate }) => {
  const { token } = useAuth();
  const [metrics, setMetrics] = useState<SOCMetrics | null>(null);
  const [recentScans, setRecentScans] = useState<ScanRecordItem[]>([]);
  const [auditStatus, setAuditStatus] = useState<AuditVerificationResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [verifyingChain, setVerifyingChain] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());

  const loadDashboardData = useCallback(async () => {
    const activeToken = token || getAuthToken();
    if (!activeToken) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const [m, scansPage, auditRes] = await Promise.all([
        fetchSOCMetrics(),
        fetchScanRecords(5, 0),
        verifyAuditChain().catch(() => null),
      ]);
      setMetrics(m);
      setRecentScans(scansPage.items);
      setAuditStatus(auditRes);
      setLastRefreshed(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load SOC dashboard data');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    if (token || getAuthToken()) {
      loadDashboardData();
    }
  }, [token, loadDashboardData]);

  const handleVerifyChain = async () => {
    setVerifyingChain(true);
    try {
      const res = await verifyAuditChain();
      setAuditStatus(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Audit chain verification failed');
    } finally {
      setVerifyingChain(false);
    }
  };

  const renderDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'BLOCK':
        return (
          <span className="badge badge-block">
            <ShieldAlert size={11} strokeWidth={2.5} />
            BLOCK
          </span>
        );
      case 'REQUIRE_APPROVAL':
        return (
          <span className="badge badge-approval">
            <Clock size={11} strokeWidth={2} />
            REQUIRE APPROVAL
          </span>
        );
      case 'WARN':
        return (
          <span className="badge badge-warn">
            <AlertTriangle size={11} strokeWidth={2} />
            WARN
          </span>
        );
      default:
        return (
          <span className="badge badge-allow">
            <CheckCircle2 size={11} strokeWidth={2} />
            ALLOW
          </span>
        );
    }
  };

  const renderRiskBadge = (band: string, score: number) => {
    let className = 'badge-allow';
    if (band === 'CRITICAL') className = 'badge-block';
    else if (band === 'HIGH') className = 'badge-approval';
    else if (band === 'MEDIUM') className = 'badge-warn';

    return (
      <span className={`badge ${className} font-mono`} style={{ fontSize: '0.7rem' }}>
        {score} • {band}
      </span>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Page Header */}
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
              Security Overview
            </h1>
            <span className="badge badge-mono" style={{ fontSize: '0.68rem' }}>
              Invariant Guard
            </span>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', maxWidth: '640px', lineHeight: 1.45 }}>
            Continuous monitoring of sensitive data egress, deterministic policy enforcement, and tamper-evident SHA-256 audit logs.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="font-mono text-muted" style={{ fontSize: '0.72rem' }}>
            Updated: {lastRefreshed.toLocaleTimeString()}
          </span>
          <button
            className="btn-secondary"
            onClick={loadDashboardData}
            disabled={loading}
            style={{ fontSize: '0.8rem', padding: '6px 12px' }}
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          <button
            className="btn-primary"
            onClick={() => onNavigate('workbench')}
            style={{ fontSize: '0.8rem', padding: '7px 14px' }}
          >
            <Terminal size={13} strokeWidth={2} />
            Scan Workbench
          </button>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div
          className="card"
          style={{
            padding: '12px 16px',
            border: '1px solid #737373',
            background: '#141414',
            color: '#f5f5f5',
            fontSize: '0.84rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertTriangle size={16} color="#ffffff" />
            <span>{error}</span>
          </div>
          <button className="btn-secondary" onClick={loadDashboardData} style={{ fontSize: '0.75rem', padding: '4px 10px' }}>
            Retry
          </button>
        </div>
      )}

      {/* Audit Integrity Banner */}
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
              width: '34px',
              height: '34px',
              borderRadius: 'var(--radius-sm)',
              background: '#101010',
              border: '1px solid var(--border-strong)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <FileCheck2 size={18} color="#ffffff" strokeWidth={1.8} />
          </div>
          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>Tamper-Evident Audit Trail</span>
              <span
                className={`badge ${auditStatus?.is_valid ? 'badge-mono' : 'badge-block'}`}
                style={{ fontSize: '0.66rem' }}
              >
                {auditStatus ? (auditStatus.is_valid ? 'CHAIN VERIFIED' : 'TAMPER DETECTED') : 'PENDING'}
              </span>
            </div>
            <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
              {auditStatus
                ? `${auditStatus.verified_events} sequential events cryptographically linked via SHA-256 digests.`
                : 'Cryptographic hash chain seals every scan decision, policy action, and timestamp.'}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {auditStatus?.chain_head_hash && (
            <div
              className="font-mono text-muted"
              style={{
                fontSize: '0.7rem',
                background: '#101010',
                padding: '4px 8px',
                borderRadius: 'var(--radius-xs)',
                border: '1px solid var(--border-primary)',
              }}
              title={auditStatus.chain_head_hash}
            >
              Head: {auditStatus.chain_head_hash.slice(0, 16)}...
            </div>
          )}
          <button
            className="btn-secondary"
            onClick={handleVerifyChain}
            disabled={verifyingChain}
            style={{ fontSize: '0.76rem', padding: '5px 12px' }}
          >
            <Fingerprint size={12} strokeWidth={2} />
            {verifyingChain ? 'Verifying...' : 'Verify Chain'}
          </button>
        </div>
      </div>

      {/* KPI Stat Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '14px' }}>
        {/* Total Scans */}
        <div className="card" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Total Scans
            </span>
            <Activity size={14} color="var(--text-muted)" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.1, marginBottom: '4px' }}>
            {metrics ? metrics.total_scans : '—'}
          </div>
          <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)' }}>
            Recorded in local SQLite ledger
          </div>
        </div>

        {/* Policy Blocks */}
        <div className="card" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Policy Blocks
            </span>
            <ShieldAlert size={14} color="var(--text-muted)" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.1, marginBottom: '4px' }}>
            {metrics ? metrics.blocked_count : '—'}
          </div>
          <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)' }}>
            Deterministic invariant enforcement
          </div>
        </div>

        {/* Approvals Required */}
        <div className="card" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Approval Required
            </span>
            <Clock size={14} color="var(--text-muted)" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.1, marginBottom: '4px' }}>
            {metrics ? metrics.approval_count : '—'}
          </div>
          <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)' }}>
            Elevated risk or external PII
          </div>
        </div>

        {/* High Risk Scans */}
        <div className="card" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              High-Risk Scans
            </span>
            <AlertTriangle size={14} color="var(--text-muted)" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.1, marginBottom: '4px' }}>
            {metrics ? metrics.high_count : '—'}
          </div>
          <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)' }}>
            Score ≥ 70 / 100 severity band
          </div>
        </div>

        {/* Average Risk Score */}
        <div className="card" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.7rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Average Risk Score
            </span>
            <Layers size={14} color="var(--text-muted)" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.1, marginBottom: '4px' }}>
            {metrics ? `${metrics.avg_risk_score}` : '—'}
            <span style={{ fontSize: '0.9rem', fontWeight: 500, color: 'var(--text-muted)', marginLeft: '4px' }}>/ 100</span>
          </div>
          <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)' }}>
            Multi-factor composite index
          </div>
        </div>
      </div>

      {/* Security Activity: Recent Scans */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <div
          style={{
            padding: '16px 20px',
            borderBottom: '1px solid var(--border-primary)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            background: 'var(--bg-surface)',
          }}
        >
          <div>
            <h2 style={{ fontSize: '0.95rem', fontWeight: 600, margin: 0, color: 'var(--text-primary)' }}>
              Recent Security Evaluations
            </h2>
            <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
              Actual scan records persisted in datashield.db
            </span>
          </div>

          <button
            className="btn-ghost"
            onClick={() => onNavigate('history')}
            style={{ fontSize: '0.76rem' }}
          >
            <span>View All Records</span>
            <ArrowRight size={13} />
          </button>
        </div>

        {recentScans.length === 0 ? (
          <div style={{ padding: '40px 20px', textAlign: 'center' }}>
            <Shield size={32} color="var(--text-muted)" style={{ margin: '0 auto 10px' }} strokeWidth={1.5} />
            <div style={{ fontWeight: 600, fontSize: '0.88rem', marginBottom: '4px' }}>No Scans Recorded Yet</div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', maxWidth: '380px', margin: '0 auto 16px' }}>
              Execute sensitive data analysis in the Scan Workbench to test deterministic DLP and explainable remediation.
            </p>
            <button className="btn-secondary" onClick={() => onNavigate('workbench')}>
              <Terminal size={13} />
              Open Scan Workbench
            </button>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Scan ID</th>
                  <th>Destination</th>
                  <th>Policy Action</th>
                  <th>Risk Score</th>
                  <th>Entities</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan) => (
                  <tr key={scan.scan_id}>
                    <td className="font-mono text-muted" style={{ fontSize: '0.74rem' }}>
                      {new Date(scan.timestamp).toLocaleString()}
                    </td>
                    <td className="font-mono text-primary" style={{ fontSize: '0.76rem' }}>
                      {scan.scan_id.slice(0, 12)}...
                    </td>
                    <td>
                      <span className="badge badge-outline font-mono" style={{ fontSize: '0.68rem' }}>
                        {scan.destination}
                      </span>
                    </td>
                    <td>{renderDecisionBadge(scan.final_decision)}</td>
                    <td>{renderRiskBadge(scan.risk_band, scan.risk_score)}</td>
                    <td className="font-mono text-secondary" style={{ fontSize: '0.76rem' }}>
                      {scan.finding_count} detected
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn-ghost"
                        onClick={() => onNavigate('history')}
                        style={{ fontSize: '0.74rem', padding: '3px 8px' }}
                      >
                        Inspect
                        <ArrowRight size={11} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
