export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  timestamp: string;
  environment: {
    mode: string;
    llm_configured: boolean;
  };
}

export interface HealthCheckResult {
  data: HealthResponse | null;
  latencyMs: number;
  error: string | null;
}

export async function checkBackendHealth(): Promise<HealthCheckResult> {
  const start = performance.now();
  try {
    const response = await fetch('/api/health', {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    const latencyMs = Math.round(performance.now() - start);

    if (!response.ok) {
      return {
        data: null,
        latencyMs,
        error: `HTTP ${response.status}: ${response.statusText}`,
      };
    }

    const data: HealthResponse = await response.json();
    return {
      data,
      latencyMs,
      error: null,
    };
  } catch (err) {
    const latencyMs = Math.round(performance.now() - start);
    return {
      data: null,
      latencyMs,
      error: err instanceof Error ? err.message : 'Failed to connect to backend',
    };
  }
}

export type FindingCategory = 'PII' | 'PAYMENT_CARD' | 'SECRET' | 'CREDENTIAL' | 'HIGH_ENTROPY_TOKEN';
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type ConfidenceBand = 'VERY_HIGH' | 'HIGH' | 'MEDIUM' | 'LOW';

export type PolicyAction = 'ALLOW' | 'WARN' | 'REQUIRE_APPROVAL' | 'REDACT' | 'BLOCK';
export type DestinationType = 'PUBLIC_LLM' | 'EXTERNAL_SAAS' | 'INTERNAL_SERVICE' | 'INTERNAL_VECTOR_DB' | 'UNSPECIFIED';
export type RecipientType = 'PUBLIC' | 'THIRD_PARTY_CONTRACTOR' | 'INTERNAL_EMPLOYEE' | 'AUTHORIZED_ANALYST' | 'UNKNOWN';
export type DataClassification = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';

export interface SharingContext {
  destination: DestinationType;
  recipient: RecipientType;
  classification: DataClassification;
  actor_id?: string;
  purpose?: string;
}

export interface PolicyRule {
  id: string;
  version: string;
  name: string;
  description: string;
  enabled: boolean;
  applicable_categories: FindingCategory[];
  applicable_sensitivities: DataClassification[];
  target_destinations: DestinationType[];
  target_recipients: RecipientType[];
  action: PolicyAction;
  priority: number;
  intent_explanation: string;
}

export interface Finding {
  id: string;
  category: FindingCategory;
  detector_name: string;
  rule_id: string;
  severity: SeverityLevel;
  confidence: number;
  confidence_band: ConfidenceBand;
  start_offset: number;
  end_offset: number;
  masked_evidence: string;
  suggested_remediation: string;
  validation_metadata: Record<string, unknown>;
}

export interface FindingCounts {
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
  total: number;
}

export type RemediationActionType =
  | 'REDACT_SENSITIVE_VALUES'
  | 'RESTRICT_PUBLIC_SHARING'
  | 'LIMIT_AUTHORIZED_RECIPIENTS'
  | 'REQUEST_APPROVAL'
  | 'REMOVE_UNNECESSARY_PERMISSIONS'
  | 'ROTATE_CREDENTIAL'
  | 'REQUEST_HUMAN_REVIEW';

export interface RemediationRecommendation {
  id: string;
  action_type: RemediationActionType;
  title: string;
  explanation: string;
  reason: string;
  expected_security_benefit: string;
  requires_human_approval: boolean;
  is_advisory: boolean;
}

export interface AIContextAnalysisResult {
  incident_summary: string;
  relevant_risk_factors: string[];
  policy_rationales: Record<string, string>;
  ambiguities_and_uncertainty: string[];
  remediation_recommendations: RemediationRecommendation[];
  human_review_recommended: boolean;
  ai_status: 'SUCCESS' | 'FALLBACK' | 'UNAVAILABLE';
  model_identifier?: string;
  is_ai_assisted: boolean;
  disclaimer: string;
}

export interface ScanResponse {
  scan_id: string;
  findings: Finding[];
  redacted_text: string;
  counts: FindingCounts;
  detector_metadata: Record<string, unknown>;
  processing_duration_ms: number;
  context?: SharingContext;
  risk_score?: number;
  risk_band?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  policy_decision?: PolicyAction;
  triggered_policies?: PolicyRule[];
  decision_reasons?: string[];
  audit_event_id?: string;
  audit_event_hash?: string;
  ai_analysis?: AIContextAnalysisResult;
}

export interface AuditVerificationResult {
  is_valid: boolean;
  total_events: number;
  verified_events: number;
  tampered_event_id: string | null;
  errors: string[];
  chain_head_hash: string | null;
  details: string;
}

export interface AuditEvent {
  event_id: string;
  sequence_number: number;
  timestamp: string;
  event_type: string;
  scan_id?: string;
  actor_id?: string;
  policy_decision?: string;
  policy_references: string[];
  sanitized_metadata: Record<string, unknown>;
  prev_event_hash: string;
  event_hash: string;
}

export interface AuditEventsPage {
  items: AuditEvent[];
  total: number;
  limit: number;
  offset: number;
}

export interface ScanRecordItem {
  scan_id: string;
  timestamp: string;
  actor_id: string;
  destination: DestinationType;
  recipient: RecipientType;
  classification: DataClassification;
  risk_score: number;
  risk_band: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  final_decision: PolicyAction;
  finding_count: number;
  categories_detected: FindingCategory[];
  processing_duration_ms: number;
}

export interface ScanRecordDetail extends ScanRecordItem {
  audit_event_id?: string;
  audit_event_hash?: string;
  audit_metadata?: Record<string, unknown>;
}

export interface ScanRecordsPage {
  items: ScanRecordItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface SOCMetrics {
  total_scans: number;
  blocked_count: number;
  approval_count: number;
  warn_count: number;
  allow_count: number;
  critical_count: number;
  high_count: number;
  avg_risk_score: number;
  total_findings: number;
}

export async function scanTextPayload(
  text: string,
  options?: { enable_entropy?: boolean; redaction_mode?: string },
  context?: SharingContext
): Promise<ScanResponse> {
  const response = await fetch('/api/v1/scan/text', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({
      text,
      options: options || { enable_entropy: true, redaction_mode: 'placeholder' },
      context: context || {
        destination: 'UNSPECIFIED',
        recipient: 'UNKNOWN',
        classification: 'INTERNAL',
      },
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Scan failed (${response.status}): ${errorBody || response.statusText}`);
  }

  return response.json();
}

export async function verifyAuditChain(): Promise<AuditVerificationResult> {
  const response = await fetch('/api/v1/audit/verify', {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Verification failed (${response.status}): ${errorBody || response.statusText}`);
  }

  return response.json();
}

export async function fetchPolicies(enabledOnly: boolean = false): Promise<PolicyRule[]> {
  const query = enabledOnly ? '?enabled_only=true' : '';
  const response = await fetch(`/api/v1/policies${query}`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to load policies (${response.status}): ${errorBody || response.statusText}`);
  }

  return response.json();
}

export async function fetchAuditEvents(limit: number = 50, offset: number = 0): Promise<AuditEventsPage> {
  const response = await fetch(`/api/v1/audit/events?limit=${limit}&offset=${offset}`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to load audit events (${response.status}): ${errorBody || response.statusText}`);
  }

  return response.json();
}

export async function fetchScanRecords(
  limit: number = 20,
  offset: number = 0,
  filters?: { action?: string; risk_band?: string; destination?: string }
): Promise<ScanRecordsPage> {
  const params = new URLSearchParams({
    limit: limit.toString(),
    offset: offset.toString(),
  });
  if (filters?.action) params.append('action', filters.action);
  if (filters?.risk_band) params.append('risk_band', filters.risk_band);
  if (filters?.destination) params.append('destination', filters.destination);

  const response = await fetch(`/api/v1/scan/records?${params.toString()}`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to load scan records (${response.status}): ${errorBody || response.statusText}`);
  }

  return response.json();
}

export async function fetchScanRecordDetail(scanId: string): Promise<ScanRecordDetail> {
  const response = await fetch(`/api/v1/scan/records/${encodeURIComponent(scanId)}`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to load scan record detail (${response.status}): ${errorBody || response.statusText}`);
  }

  return response.json();
}

export async function fetchSOCMetrics(): Promise<SOCMetrics> {
  const response = await fetch('/api/v1/scan/metrics', {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Failed to load SOC metrics (${response.status}): ${errorBody || response.statusText}`);
  }

  return response.json();
}
