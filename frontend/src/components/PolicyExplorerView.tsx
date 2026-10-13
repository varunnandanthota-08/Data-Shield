import React, { useState, useEffect, useCallback } from 'react';
import {
  fetchPolicies,
  createPolicy,
  togglePolicy,
  deletePolicy,
  PolicyRule,
  PolicyAction,
  FindingCategory,
  DestinationType,
  RecipientType,
  DataClassification,
} from '../api/client';
import {
  RefreshCw,
  Lock,
  Info,
  ShieldAlert,
  Clock,
  AlertTriangle,
  CheckCircle2,
  Plus,
  Trash2,
  ToggleLeft,
  ToggleRight,
  X,
  Building,
  Check,
} from 'lucide-react';

const PROTECTED_BASELINE_IDS = ['POL-001', 'POL-002', 'POL-003', 'POL-004', 'POL-005'];

const ALL_CATEGORIES: FindingCategory[] = [
  'SECRET',
  'CREDENTIAL',
  'HIGH_ENTROPY_TOKEN',
  'PAYMENT_CARD',
  'PII',
];

const ALL_DESTINATIONS: DestinationType[] = [
  'PUBLIC_LLM',
  'EXTERNAL_SAAS',
  'INTERNAL_SERVICE',
  'INTERNAL_VECTOR_DB',
  'UNSPECIFIED',
];

const ALL_RECIPIENTS: RecipientType[] = [
  'PUBLIC',
  'THIRD_PARTY_CONTRACTOR',
  'INTERNAL_EMPLOYEE',
  'AUTHORIZED_ANALYST',
  'UNKNOWN',
];

const ALL_CLASSIFICATIONS: DataClassification[] = [
  'RESTRICTED',
  'CONFIDENTIAL',
  'INTERNAL',
  'PUBLIC',
];

export const PolicyExplorerView: React.FC = () => {
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [selectedOrg, setSelectedOrg] = useState<string>('all');
  const [enabledOnly, setEnabledOnly] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Policy Builder Modal State
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [creating, setCreating] = useState<boolean>(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [createSuccess, setCreateSuccess] = useState<string | null>(null);

  // Form Fields
  const [formId, setFormId] = useState<string>('');
  const [formName, setFormName] = useState<string>('');
  const [formDescription, setFormDescription] = useState<string>('');
  const [formOrgId, setFormOrgId] = useState<string>('org_acme');
  const [formAction, setFormAction] = useState<PolicyAction>('BLOCK');
  const [formPriority, setFormPriority] = useState<number>(50);
  const [formIntent, setFormIntent] = useState<string>('');
  const [formCategories, setFormCategories] = useState<FindingCategory[]>(['SECRET']);
  const [formDestinations, setFormDestinations] = useState<DestinationType[]>(['PUBLIC_LLM']);
  const [formRecipients, setFormRecipients] = useState<RecipientType[]>(['PUBLIC']);
  const [formSensitivities, setFormSensitivities] = useState<DataClassification[]>(['RESTRICTED']);

  // Action status message
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const loadPolicies = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchPolicies(selectedOrg, enabledOnly);
      // Sort by priority descending
      setPolicies(data.sort((a, b) => b.priority - a.priority));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch policy rules');
    } finally {
      setLoading(false);
    }
  }, [selectedOrg, enabledOnly]);

  useEffect(() => {
    loadPolicies();
  }, [loadPolicies]);

  const handleOpenCreateModal = () => {
    const randomSuffix = Math.floor(100 + Math.random() * 900);
    setFormId(`POL-ORG-${randomSuffix}`);
    setFormName('');
    setFormDescription('');
    setFormOrgId(selectedOrg !== 'all' ? selectedOrg : 'org_acme');
    setFormAction('BLOCK');
    setFormPriority(60);
    setFormIntent('');
    setFormCategories(['SECRET']);
    setFormDestinations(['PUBLIC_LLM']);
    setFormRecipients(['PUBLIC']);
    setFormSensitivities(['RESTRICTED']);
    setCreateError(null);
    setCreateSuccess(null);
    setShowCreateModal(true);
  };

  const handleToggleCategory = (cat: FindingCategory) => {
    setFormCategories((prev) =>
      prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat]
    );
  };

  const handleToggleDestination = (dest: DestinationType) => {
    setFormDestinations((prev) =>
      prev.includes(dest) ? prev.filter((d) => d !== dest) : [...prev, dest]
    );
  };

  const handleToggleRecipient = (rec: RecipientType) => {
    setFormRecipients((prev) =>
      prev.includes(rec) ? prev.filter((r) => r !== rec) : [...prev, rec]
    );
  };

  const handleToggleSensitivity = (sens: DataClassification) => {
    setFormSensitivities((prev) =>
      prev.includes(sens) ? prev.filter((s) => s !== sens) : [...prev, sens]
    );
  };

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError(null);
    setCreateSuccess(null);

    // Validation
    const idRegex = /^[A-Za-z0-9_\-.]{3,64}$/;
    if (!idRegex.test(formId.trim())) {
      setCreateError('Policy ID must be 3-64 characters alphanumeric, dashes, dots, or underscores.');
      return;
    }
    if (!formName.trim()) {
      setCreateError('Policy Name is required.');
      return;
    }
    if (!formDescription.trim()) {
      setCreateError('Policy Description is required.');
      return;
    }
    if (formPriority < 1 || formPriority > 100) {
      setCreateError('Priority must be between 1 and 100.');
      return;
    }

    setCreating(true);
    try {
      await createPolicy({
        id: formId.trim(),
        version: '1.0.0',
        name: formName.trim(),
        description: formDescription.trim(),
        enabled: true,
        org_id: formOrgId.trim() || 'default',
        action: formAction,
        priority: Number(formPriority),
        intent_explanation: formIntent.trim() || `Company-specific rule for ${formOrgId}`,
        applicable_categories: formCategories,
        applicable_sensitivities: formSensitivities,
        target_destinations: formDestinations,
        target_recipients: formRecipients,
      });

      setCreateSuccess(`Policy ${formId} created successfully.`);
      setTimeout(() => {
        setShowCreateModal(false);
        loadPolicies();
      }, 900);
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'Failed to create policy');
    } finally {
      setCreating(false);
    }
  };

  const handleTogglePolicy = async (policy: PolicyRule) => {
    try {
      const res = await togglePolicy(policy.id, !policy.enabled);
      setActionNotice(`Policy ${res.policy_id} is now ${res.enabled ? 'ENABLED' : 'DISABLED'}`);
      loadPolicies();
      setTimeout(() => setActionNotice(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Toggle failed');
    }
  };

  const handleDeletePolicy = async (policyId: string) => {
    if (PROTECTED_BASELINE_IDS.includes(policyId)) {
      alert(`Policy ${policyId} is a core security baseline rule and cannot be deleted.`);
      return;
    }
    if (!confirm(`Are you sure you want to permanently delete custom policy ${policyId}?`)) {
      return;
    }
    try {
      await deletePolicy(policyId);
      setActionNotice(`Policy ${policyId} deleted successfully.`);
      loadPolicies();
      setTimeout(() => setActionNotice(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed');
    }
  };

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
      case 'REDACT':
        return (
          <span className="badge badge-approval">
            <Lock size={10} strokeWidth={2} />
            REDACT
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '22px', maxWidth: '1440px', margin: '0 auto', width: '100%' }}>
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
              Policy Explorer & Builder
            </h1>
            <span className="badge badge-mono font-mono" style={{ fontSize: '0.68rem' }}>
              {policies.length} Rules Active
            </span>
          </div>
          <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', maxWidth: '720px', lineHeight: 1.45 }}>
            Manage organization-specific and global DLP security policies. Deterministic precedence ensures zero-trust protection across egress channels.
          </p>
        </div>

        {/* Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {/* Tenant Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Building size={14} color="var(--text-muted)" />
            <select
              value={selectedOrg}
              onChange={(e) => setSelectedOrg(e.target.value)}
              style={{ fontSize: '0.78rem', padding: '5px 10px' }}
            >
              <option value="all">All Organizations</option>
              <option value="default">Global / Default Only</option>
              <option value="org_acme">Acme Corp</option>
              <option value="org_cybershield">CyberShield</option>
              <option value="org_fintech">FinTech Secure</option>
            </select>
          </div>

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

          <button
            id="btn-create-policy"
            className="btn-primary"
            onClick={handleOpenCreateModal}
            style={{ fontSize: '0.78rem', padding: '6px 14px' }}
          >
            <Plus size={13} strokeWidth={2.5} />
            Create Policy
          </button>
        </div>
      </div>

      {/* Summary KPI Strip */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '12px' }}>
        <div className="card" style={{ padding: '14px 16px' }}>
          <div style={{ fontSize: '0.68rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Total Loaded
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

      {/* Non-Negotiable Hard-Block Invariant & Demo Notice */}
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
          overrides ALLOW, WARN, and REQUIRE_APPROVAL regardless of custom rule priority or advisory AI recommendations.
          <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            * Note: Organization selector operates as a demo/development tenant context. Authenticated tenant-scoped isolation and IAM authorization are required before production deployment.
          </div>
        </div>
      </div>

      {actionNotice && (
        <div className="card" style={{ padding: '10px 14px', background: '#171717', color: '#f5f5f5', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Check size={14} color="#ffffff" />
          <span>{actionNotice}</span>
        </div>
      )}

      {error && (
        <div className="card" style={{ padding: '12px', border: '1px solid #737373', fontSize: '0.8rem' }}>
          {error}
        </div>
      )}

      {/* Policy Rules List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
        {policies.map((p) => {
          const isBaseline = PROTECTED_BASELINE_IDS.includes(p.id);
          return (
            <div key={p.id} className="card" style={{ padding: '18px 20px', opacity: p.enabled ? 1 : 0.6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px', flexWrap: 'wrap', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                  <span className="font-mono text-primary" style={{ fontSize: '0.9rem', fontWeight: 700 }}>
                    {p.id}
                  </span>
                  <h3 style={{ fontSize: '0.95rem', fontWeight: 600, margin: 0, color: 'var(--text-primary)' }}>
                    {p.name}
                  </h3>
                  <span className="badge badge-mono font-mono" style={{ fontSize: '0.64rem' }}>
                    v{p.version}
                  </span>
                  {p.org_id && p.org_id !== 'default' ? (
                    <span className="badge badge-outline" style={{ fontSize: '0.64rem' }}>
                      Tenant: {p.org_id}
                    </span>
                  ) : (
                    <span className="badge badge-mono" style={{ fontSize: '0.64rem' }}>
                      Global
                    </span>
                  )}
                  {p.action === 'BLOCK' && (
                    <span className="badge badge-mono" style={{ fontSize: '0.64rem' }}>
                      Hard Invariant
                    </span>
                  )}
                  {!p.enabled && (
                    <span className="badge badge-warn" style={{ fontSize: '0.64rem' }}>
                      Disabled
                    </span>
                  )}
                </div>

                {/* Badges & Actions */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {renderDecisionBadge(p.action)}
                  <span className="badge badge-outline font-mono" style={{ fontSize: '0.68rem' }}>
                    Priority: {p.priority}
                  </span>

                  {/* Toggle Enable/Disable Button */}
                  <button
                    className="btn-ghost"
                    onClick={() => handleTogglePolicy(p)}
                    title={p.enabled ? 'Click to disable' : 'Click to enable'}
                    style={{ fontSize: '0.75rem', padding: '4px 6px' }}
                  >
                    {p.enabled ? (
                      <ToggleRight size={18} color="#ffffff" />
                    ) : (
                      <ToggleLeft size={18} color="var(--text-muted)" />
                    )}
                  </button>

                  {/* Delete button (only for custom rules) */}
                  {!isBaseline && (
                    <button
                      className="btn-ghost"
                      onClick={() => handleDeletePolicy(p.id)}
                      title="Delete custom rule"
                      style={{ fontSize: '0.75rem', padding: '4px 6px', color: '#a3a3a3' }}
                    >
                      <Trash2 size={13} />
                    </button>
                  )}
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
                <Info size={13} color="var(--text-muted)" style={{ flexShrink: 0 }} />
                <span>Audit Rationale: {p.intent_explanation}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Create Policy Modal */}
      {showCreateModal && (
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
        >
          <div
            className="card"
            style={{
              maxWidth: '680px',
              width: '100%',
              maxHeight: '90vh',
              overflowY: 'auto',
              padding: '24px',
              background: 'var(--bg-card)',
              position: 'relative',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldAlert size={18} color="#ffffff" />
                <h2 style={{ fontSize: '1.2rem', fontWeight: 700, margin: 0 }}>Create Custom Company Policy</h2>
              </div>
              <button
                className="btn-ghost"
                onClick={() => setShowCreateModal(false)}
                style={{ padding: '4px' }}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleCreatePolicy} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {/* Row 1: ID, Name, Org */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                    Policy ID *
                  </label>
                  <input
                    type="text"
                    value={formId}
                    onChange={(e) => setFormId(e.target.value)}
                    placeholder="POL-ACME-001"
                    style={{ width: '100%', fontSize: '0.82rem' }}
                    required
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                    Tenant Organization *
                  </label>
                  <select
                    value={formOrgId}
                    onChange={(e) => setFormOrgId(e.target.value)}
                    style={{ width: '100%', fontSize: '0.82rem' }}
                  >
                    <option value="org_acme">Acme Corp (org_acme)</option>
                    <option value="org_cybershield">CyberShield (org_cybershield)</option>
                    <option value="org_fintech">FinTech Secure (org_fintech)</option>
                    <option value="default">Global (default)</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                    Priority (1-100) *
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={100}
                    value={formPriority}
                    onChange={(e) => setFormPriority(Number(e.target.value))}
                    style={{ width: '100%', fontSize: '0.82rem' }}
                    required
                  />
                </div>
              </div>

              {/* Policy Name */}
              <div>
                <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                  Policy Name *
                </label>
                <input
                  type="text"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder="e.g. Acme Strict Secret Sharing Restriction"
                  style={{ width: '100%', fontSize: '0.82rem' }}
                  required
                />
              </div>

              {/* Description */}
              <div>
                <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                  Description & Business Justification *
                </label>
                <textarea
                  rows={2}
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  placeholder="Explain what the policy enforces and the business security reason..."
                  style={{ width: '100%', fontSize: '0.82rem' }}
                  required
                />
              </div>

              {/* Enforcement Action */}
              <div>
                <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                  Enforcement Action *
                </label>
                <select
                  value={formAction}
                  onChange={(e) => setFormAction(e.target.value as PolicyAction)}
                  style={{ width: '100%', fontSize: '0.82rem' }}
                >
                  <option value="BLOCK">BLOCK (Strict zero-trust hard block)</option>
                  <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL (Analyst sign-off)</option>
                  <option value="REDACT">REDACT (Enforce redaction before transmission)</option>
                  <option value="WARN">WARN (Log advisory compliance warning)</option>
                  <option value="ALLOW">ALLOW (Permit sharing)</option>
                </select>

                {formAction === 'BLOCK' && (
                  <div style={{ fontSize: '0.72rem', color: '#f5f5f5', marginTop: '4px' }}>
                    ⚠️ Note: Under deterministic precedence, a triggered BLOCK unconditionally overrides any ALLOW, WARN, or REQUIRE_APPROVAL.
                  </div>
                )}
                {formAction === 'ALLOW' && (
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                    🛡️ Security invariant: A custom ALLOW cannot override any triggered mandatory BLOCK.
                  </div>
                )}
              </div>

              {/* Applicable Categories Checkboxes */}
              <div>
                <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
                  Applicable Data Categories (Match any)
                </label>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {ALL_CATEGORIES.map((cat) => (
                    <label key={cat} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.76rem', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={formCategories.includes(cat)}
                        onChange={() => handleToggleCategory(cat)}
                      />
                      <span>{cat}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Target Destinations Checkboxes */}
              <div>
                <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
                  Target Destinations (Match any)
                </label>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {ALL_DESTINATIONS.map((dest) => (
                    <label key={dest} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.76rem', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={formDestinations.includes(dest)}
                        onChange={() => handleToggleDestination(dest)}
                      />
                      <span>{dest}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Target Recipients Checkboxes */}
              <div>
                <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
                  Target Recipients (Match any)
                </label>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {ALL_RECIPIENTS.map((rec) => (
                    <label key={rec} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.76rem', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={formRecipients.includes(rec)}
                        onChange={() => handleToggleRecipient(rec)}
                      />
                      <span>{rec}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Sensitivities */}
              <div>
                <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '6px' }}>
                  Sensitivity Tiers (Match any)
                </label>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {ALL_CLASSIFICATIONS.map((sens) => (
                    <label key={sens} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '0.76rem', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={formSensitivities.includes(sens)}
                        onChange={() => handleToggleSensitivity(sens)}
                      />
                      <span>{sens}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Intent Explanation */}
              <div>
                <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '4px' }}>
                  Audit Intent Rationale
                </label>
                <input
                  type="text"
                  value={formIntent}
                  onChange={(e) => setFormIntent(e.target.value)}
                  placeholder="e.g. Enforce strict NDA restrictions for Acme contract compliance"
                  style={{ width: '100%', fontSize: '0.82rem' }}
                />
              </div>

              {createError && (
                <div style={{ padding: '8px 12px', background: '#1c1c1c', border: '1px solid #737373', color: '#ffffff', fontSize: '0.78rem', borderRadius: 'var(--radius-xs)' }}>
                  {createError}
                </div>
              )}

              {createSuccess && (
                <div style={{ padding: '8px 12px', background: '#171717', border: '1px solid #ffffff', color: '#ffffff', fontSize: '0.78rem', borderRadius: 'var(--radius-xs)' }}>
                  {createSuccess}
                </div>
              )}

              {/* Submit / Cancel Buttons */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '10px' }}>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setShowCreateModal(false)}
                  disabled={creating}
                  style={{ fontSize: '0.82rem' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-primary"
                  disabled={creating}
                  style={{ fontSize: '0.82rem' }}
                >
                  {creating ? 'Saving Policy...' : 'Save & Register Policy'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
