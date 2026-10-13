import React, { useState, useEffect, useCallback } from 'react';
import {
  fetchScanRecords,
  fetchScanRecordDetail,
  ScanRecordItem,
  ScanRecordDetail,
  PolicyAction,
} from '../api/client';
import {
  RefreshCw,
  Search,
  X,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Clock,
  AlertTriangle,
  CheckCircle2,
  Fingerprint,
} from 'lucide-react';

export const ScanHistoryView: React.FC = () => {
  const [records, setRecords] = useState<ScanRecordItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & Search
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [actionFilter, setActionFilter] = useState<string>('');
  const [riskBandFilter, setRiskBandFilter] = useState<string>('');
  const [destinationFilter, setDestinationFilter] = useState<string>('');

  // Pagination
  const [page, setPage] = useState<number>(0);
  const pageSize = 15;

  // Selected Record Detail Modal
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [detailRecord, setDetailRecord] = useState<ScanRecordDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState<boolean>(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const loadRecords = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchScanRecords(pageSize, page * pageSize, {
        action: actionFilter || undefined,
        risk_band: riskBandFilter || undefined,
        destination: destinationFilter || undefined,
      });
      setRecords(res.items);
      setTotal(res.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load historical scan records');
    } finally {
      setLoading(false);
    }
  }, [actionFilter, riskBandFilter, destinationFilter, page]);

  useEffect(() => {
    loadRecords();
  }, [loadRecords]);

  const handleOpenDetail = async (scanId: string) => {
    setSelectedScanId(scanId);
    setDetailRecord(null);
    setLoadingDetail(true);
    setDetailError(null);
    try {
      const detail = await fetchScanRecordDetail(scanId);
      setDetailRecord(detail);
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : 'Failed to load scan detail');
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleCloseDetail = () => {
    setSelectedScanId(null);
    setDetailRecord(null);
    setDetailError(null);
  };

  const renderDecisionBadge = (decision: PolicyAction | string) => {
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
      default:
        return (
          <span className="badge badge-allow">
            <CheckCircle2 size={10} strokeWidth={2} />
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
      <span className={`badge ${className} font-mono`} style={{ fontSize: '0.68rem' }}>
        {score} • {band}
      </span>
    );
  };

  // Filter records by client search query if entered
  const displayedRecords = searchTerm.trim()
    ? records.filter((r) => r.scan_id.toLowerCase().includes(searchTerm.toLowerCase().trim()))
    : records;

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: '14px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <h1 style={{ fontSize: '1.45rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
              Scan History
            </h1>
            <span className="badge badge-mono font-mono" style={{ fontSize: '0.68rem' }}>
              {total} Total Evaluations
            </span>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', maxWidth: '640px' }}>
            Historical evaluation ledger persisted in SQLite. Contains sanitized metadata only; zero raw secrets stored.
          </p>
        </div>

        {/* Filter Controls Row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          {/* Search by Scan ID */}
          <div style={{ position: 'relative' }}>
            <Search
              size={13}
              color="var(--text-muted)"
              style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }}
            />
            <input
              type="text"
              placeholder="Filter by Scan ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                paddingLeft: '28px',
                fontSize: '0.78rem',
                width: '180px',
                paddingTop: '6px',
                paddingBottom: '6px',
              }}
            />
          </div>

          {/* Action Filter */}
          <select
            id="filter-action"
            value={actionFilter}
            onChange={(e) => {
              setActionFilter(e.target.value);
              setPage(0);
            }}
            style={{ fontSize: '0.78rem', padding: '6px 10px' }}
          >
            <option value="">All Actions</option>
            <option value="BLOCK">BLOCK</option>
            <option value="REQUIRE_APPROVAL">REQUIRE APPROVAL</option>
            <option value="WARN">WARN</option>
            <option value="ALLOW">ALLOW</option>
          </select>

          {/* Risk Band Filter */}
          <select
            id="filter-risk-band"
            value={riskBandFilter}
            onChange={(e) => {
              setRiskBandFilter(e.target.value);
              setPage(0);
            }}
            style={{ fontSize: '0.78rem', padding: '6px 10px' }}
          >
            <option value="">All Risk Bands</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>

          {/* Destination Filter */}
          <select
            id="filter-destination"
            value={destinationFilter}
            onChange={(e) => {
              setDestinationFilter(e.target.value);
              setPage(0);
            }}
            style={{ fontSize: '0.78rem', padding: '6px 10px' }}
          >
            <option value="">All Destinations</option>
            <option value="PUBLIC_LLM">PUBLIC_LLM</option>
            <option value="EXTERNAL_SAAS">EXTERNAL_SAAS</option>
            <option value="INTERNAL_SERVICE">INTERNAL_SERVICE</option>
            <option value="INTERNAL_VECTOR_DB">INTERNAL_VECTOR_DB</option>
            <option value="UNSPECIFIED">UNSPECIFIED</option>
          </select>

          <button
            className="btn-secondary"
            onClick={loadRecords}
            disabled={loading}
            style={{ fontSize: '0.78rem', padding: '6px 12px' }}
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="card" style={{ padding: '10px 14px', border: '1px solid #737373', fontSize: '0.8rem' }}>
          {error}
        </div>
      )}

      {/* Main Records Table Card */}
      <div className="card" style={{ overflow: 'hidden' }}>
        {displayedRecords.length === 0 ? (
          <div style={{ padding: '48px 20px', textAlign: 'center' }}>
            <Search size={28} color="var(--text-muted)" style={{ margin: '0 auto 10px' }} strokeWidth={1.5} />
            <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>No Matching Records</div>
            <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: '4px' }}>
              No evaluation records match the selected filter criteria.
            </div>
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
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {displayedRecords.map((scan) => (
                  <tr key={scan.scan_id}>
                    <td className="font-mono text-muted" style={{ fontSize: '0.74rem' }}>
                      {new Date(scan.timestamp).toLocaleString()}
                    </td>
                    <td className="font-mono text-primary" style={{ fontSize: '0.76rem' }}>
                      {scan.scan_id.slice(0, 16)}...
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
                        className="btn-secondary"
                        onClick={() => handleOpenDetail(scan.scan_id)}
                        style={{ fontSize: '0.72rem', padding: '3px 9px' }}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        <div
          style={{
            padding: '12px 18px',
            borderTop: '1px solid var(--border-primary)',
            background: 'var(--bg-surface)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            fontSize: '0.75rem',
            color: 'var(--text-muted)',
          }}
        >
          <div>
            Showing {records.length > 0 ? page * pageSize + 1 : 0} – {Math.min((page + 1) * pageSize, total)} of {total} records
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <button
              className="btn-secondary"
              onClick={() => setPage(Math.max(0, page - 1))}
              disabled={page === 0 || loading}
              style={{ fontSize: '0.72rem', padding: '4px 8px' }}
            >
              <ChevronLeft size={13} />
              Prev
            </button>
            <span className="font-mono" style={{ padding: '0 6px' }}>
              Page {page + 1} of {Math.max(1, totalPages)}
            </span>
            <button
              className="btn-secondary"
              onClick={() => setPage(page + 1)}
              disabled={(page + 1) * pageSize >= total || loading}
              style={{ fontSize: '0.72rem', padding: '4px 8px' }}
            >
              Next
              <ChevronRight size={13} />
            </button>
          </div>
        </div>
      </div>

      {/* Detail Modal */}
      {selectedScanId && (
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
          onClick={handleCloseDetail}
        >
          <div
            className="card"
            style={{
              maxWidth: '820px',
              width: '100%',
              maxHeight: '88vh',
              overflowY: 'auto',
              padding: '24px',
              background: '#0d0d0d',
              border: '1px solid var(--border-strong)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '18px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <h2 style={{ fontSize: '1.15rem', fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
                    Scan Record Inspection
                  </h2>
                  <span className="badge badge-mono font-mono" style={{ fontSize: '0.7rem' }}>
                    {selectedScanId}
                  </span>
                </div>
                <div className="font-mono text-muted" style={{ fontSize: '0.72rem' }}>
                  Timestamp: {detailRecord?.timestamp ? new Date(detailRecord.timestamp).toUTCString() : '—'}
                </div>
              </div>

              <button
                onClick={handleCloseDetail}
                aria-label="Close modal"
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  padding: '4px',
                }}
              >
                <X size={18} />
              </button>
            </div>

            {loadingDetail ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                Loading persisted record...
              </div>
            ) : detailError ? (
              <div className="card" style={{ padding: '14px', border: '1px solid #737373', fontSize: '0.8rem' }}>
                {detailError}
              </div>
            ) : detailRecord ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
                {/* Metric Summary Grid */}
                <div
                  className="card-inset"
                  style={{
                    padding: '14px',
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                    gap: '12px',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                      Enforced Action
                    </div>
                    <div style={{ marginTop: '4px' }}>{renderDecisionBadge(detailRecord.final_decision)}</div>
                  </div>

                  <div>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                      Heuristic Risk Score
                    </div>
                    <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                      {detailRecord.risk_score} <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>({detailRecord.risk_band})</span>
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                      Destination / Recipient
                    </div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginTop: '4px' }}>
                      {detailRecord.destination} / {detailRecord.recipient}
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                      Classification
                    </div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginTop: '4px' }}>
                      {detailRecord.classification}
                    </div>
                  </div>
                </div>

                {/* Audit Hash Seal */}
                <div
                  className="card-inset"
                  style={{
                    padding: '10px 14px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    fontSize: '0.76rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Fingerprint size={14} color="var(--text-muted)" />
                    <span style={{ color: 'var(--text-muted)' }}>Audit Block Hash:</span>
                    <span className="font-mono text-primary">{detailRecord.audit_event_hash || 'Recorded in chain'}</span>
                  </div>
                  <span className="badge badge-mono">Tamper-Evident</span>
                </div>

                {/* Categories Detected */}
                <div>
                  <div style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '8px' }}>
                    Categories Detected ({detailRecord.categories_detected.length})
                  </div>

                  {detailRecord.categories_detected.length === 0 ? (
                    <div className="card-inset" style={{ padding: '16px', textAlign: 'center', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      Zero sensitive categories detected.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                      {detailRecord.categories_detected.map((cat, idx) => (
                        <span key={idx} className="badge badge-mono font-mono" style={{ padding: '4px 8px' }}>
                          {cat}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Persisted Audit Metadata */}
                <div>
                  <div style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '8px' }}>
                    Sanitized Ledger Attributes
                  </div>
                  <div
                    className="card-inset font-mono"
                    style={{
                      padding: '12px',
                      fontSize: '0.78rem',
                      lineHeight: 1.5,
                      maxHeight: '180px',
                      overflowY: 'auto',
                    }}
                  >
                    <div>Actor: {detailRecord.actor_id}</div>
                    <div>Processing Latency: {detailRecord.processing_duration_ms} ms</div>
                    <div>Finding Count: {detailRecord.finding_count}</div>
                  </div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                    Safe sanitized representation stored in SQLite. Zero unredacted sensitive payload retained.
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
};
