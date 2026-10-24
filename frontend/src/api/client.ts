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

export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface UserResponse {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  org_id: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login_at?: string | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in_minutes: number;
  user: UserResponse;
}

export interface BootstrapStatusResponse {
  requires_bootstrap: boolean;
  user_count: number;
}

export interface RegistrationStatusResponse {
  allow_public_registration: boolean;
  registration_mode: 'public' | 'admin_provisioned';
  message: string;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  org_id?: string;
}

// In-memory token management with sessionStorage fallback (safe against CSRF and cross-tab persistence)
const AUTH_TOKEN_KEY = 'datashield_soc_auth_token';
let inMemoryToken: string | null = typeof window !== 'undefined' ? sessionStorage.getItem(AUTH_TOKEN_KEY) : null;

export function getAuthToken(): string | null {
  return inMemoryToken;
}

export function setAuthToken(token: string | null): void {
  inMemoryToken = token;
  if (typeof window !== 'undefined') {
    if (token) {
      sessionStorage.setItem(AUTH_TOKEN_KEY, token);
    } else {
      sessionStorage.removeItem(AUTH_TOKEN_KEY);
    }
  }
}

let onUnauthorizedCallback: (() => void) | null = null;
export function setOnUnauthorizedCallback(cb: (() => void) | null) {
  onUnauthorizedCallback = cb;
}

async function authenticatedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const token = getAuthToken();
  if (!token) {
    throw new Error('Authentication required: No active session token.');
  }

  const headers = new Headers(init?.headers || {});
  if (!headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(input, {
    ...init,
    headers,
  });

  if (response.status === 401) {
    if (onUnauthorizedCallback) {
      onUnauthorizedCallback();
    }
  }

  return response;
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
  org_id?: string;
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
  org_id?: string;
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

export interface AIUsageTelemetry {
  prompt_tokens?: number | null;
  candidates_tokens?: number | null;
  total_tokens?: number | null;
  cached_tokens?: number | null;
  is_estimated: boolean;
  operation: string;
  api_calls_count: number;
  latency_ms?: number | null;
  retries_attempted: number;
  rate_limit_encountered: boolean;
  timeout_encountered: boolean;
  error_type?: string | null;
  fallback_reason?: string | null;
  provider_status: string;
  provider_response_id?: string | null;
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
  usage?: AIUsageTelemetry;
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
  source_type?: string;
  filename?: string;
  file_size_bytes?: number;
  extraction_note?: string;
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
  const response = await authenticatedFetch('/api/v1/scan/text', {
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

export async function scanFilePayload(
  file: File,
  options?: { enable_entropy?: boolean; redaction_mode?: string },
  context?: SharingContext
): Promise<ScanResponse> {
  const formData = new FormData();
  formData.append('file', file);
  if (options) {
    formData.append('options_json', JSON.stringify(options));
  }
  if (context) {
    formData.append('context_json', JSON.stringify(context));
  }

  const response = await authenticatedFetch('/api/v1/scan/file', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
    },
    body: formData,
  });

  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || JSON.stringify(errJson);
    } catch {
      const errorBody = await response.text();
      if (errorBody) errorDetail = errorBody;
    }
    throw new Error(`File scan failed (${response.status}): ${errorDetail}`);
  }

  return response.json();
}

export async function verifyAuditChain(): Promise<AuditVerificationResult> {
  const response = await authenticatedFetch('/api/v1/audit/verify', {
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

export async function fetchPolicies(orgId?: string, enabledOnly: boolean = false): Promise<PolicyRule[]> {
  const params = new URLSearchParams();
  if (enabledOnly) params.append('enabled_only', 'true');
  if (orgId && orgId !== 'all') params.append('org_id', orgId);
  const queryStr = params.toString() ? `?${params.toString()}` : '';

  const response = await authenticatedFetch(`/api/v1/policies${queryStr}`, {
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

export async function createPolicy(rule: Partial<PolicyRule> & { id: string; name: string; action: PolicyAction }): Promise<PolicyRule> {
  const response = await authenticatedFetch('/api/v1/policies', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(rule),
  });

  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || JSON.stringify(errJson);
    } catch {
      const errorBody = await response.text();
      if (errorBody) errorDetail = errorBody;
    }
    throw new Error(`Failed to create policy (${response.status}): ${errorDetail}`);
  }

  return response.json();
}

export async function togglePolicy(policyId: string, enabled?: boolean): Promise<{ message: string; policy_id: string; enabled: boolean }> {
  const query = enabled !== undefined ? `?enabled=${enabled}` : '';
  const response = await authenticatedFetch(`/api/v1/policies/${encodeURIComponent(policyId)}/toggle${query}`, {
    method: 'PATCH',
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || JSON.stringify(errJson);
    } catch {
      const errorBody = await response.text();
      if (errorBody) errorDetail = errorBody;
    }
    throw new Error(`Failed to toggle policy (${response.status}): ${errorDetail}`);
  }

  return response.json();
}

export async function deletePolicy(policyId: string): Promise<{ message: string; policy_id: string }> {
  const response = await authenticatedFetch(`/api/v1/policies/${encodeURIComponent(policyId)}`, {
    method: 'DELETE',
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || JSON.stringify(errJson);
    } catch {
      const errorBody = await response.text();
      if (errorBody) errorDetail = errorBody;
    }
    throw new Error(`Failed to delete policy (${response.status}): ${errorDetail}`);
  }

  return response.json();
}

export async function fetchAuditEvents(limit: number = 50, offset: number = 0): Promise<AuditEventsPage> {
  const response = await authenticatedFetch(`/api/v1/audit/events?limit=${limit}&offset=${offset}`, {
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

  const response = await authenticatedFetch(`/api/v1/scan/records?${params.toString()}`, {
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
  const response = await authenticatedFetch(`/api/v1/scan/records/${encodeURIComponent(scanId)}`, {
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
  const response = await authenticatedFetch('/api/v1/scan/metrics', {
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

// ---------------------------------------------------------------------------
// Authentication & User Management API Methods
// ---------------------------------------------------------------------------

export async function checkBootstrapStatus(): Promise<BootstrapStatusResponse> {
  const res = await fetch('/api/v1/auth/bootstrap-status');
  if (!res.ok) {
    throw new Error(`Failed to verify bootstrap status: ${res.statusText}`);
  }
  return res.json();
}

export async function checkRegistrationStatus(): Promise<RegistrationStatusResponse> {
  const res = await fetch('/api/v1/auth/registration-status');
  if (!res.ok) {
    throw new Error(`Failed to verify registration status: ${res.statusText}`);
  }
  return res.json();
}

export async function registerUser(payload: RegisterRequest): Promise<UserResponse> {
  const res = await fetch('/api/v1/auth/register', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    let detail = 'Registration failed';
    try {
      const err = await res.json();
      detail = err.detail || detail;
    } catch {
      // fallback
    }
    throw new Error(detail);
  }

  return res.json();
}

export async function setupInitialAdmin(payload: {
  username: string;
  email: string;
  password: string;
}): Promise<TokenResponse> {
  const res = await fetch('/api/v1/auth/setup-admin', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const err = await res.json();
      detail = err.detail || JSON.stringify(err);
    } catch {
      // fallback
    }
    throw new Error(detail);
  }

  const data: TokenResponse = await res.json();
  setAuthToken(data.access_token);
  return data;
}

export async function loginUser(payload: {
  username: string;
  password: string;
}): Promise<TokenResponse> {
  const res = await fetch('/api/v1/auth/login', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    let detail = 'Authentication failed';
    try {
      const err = await res.json();
      detail = err.detail || detail;
    } catch {
      // fallback
    }
    throw new Error(detail);
  }

  const data: TokenResponse = await res.json();
  setAuthToken(data.access_token);
  return data;
}

export async function logoutUser(): Promise<void> {
  try {
    await authenticatedFetch('/api/v1/auth/logout', { method: 'POST' });
  } catch {
    // Ignore network errors on logout
  } finally {
    setAuthToken(null);
  }
}

export async function getCurrentUser(): Promise<UserResponse> {
  const res = await authenticatedFetch('/api/v1/auth/me');
  if (!res.ok) {
    throw new Error('Not authenticated');
  }
  return res.json();
}

export async function fetchUsers(): Promise<UserResponse[]> {
  const res = await authenticatedFetch('/api/v1/users');
  if (!res.ok) {
    let detail = 'Failed to load user list';
    try {
      const err = await res.json();
      detail = err.detail || detail;
    } catch {
      // fallback
    }
    throw new Error(detail);
  }
  return res.json();
}

export async function createUser(payload: {
  username: string;
  email: string;
  password: string;
  role: UserRole;
  org_id?: string;
}): Promise<UserResponse> {
  const res = await authenticatedFetch('/api/v1/users', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    let detail = 'Failed to create user';
    try {
      const err = await res.json();
      detail = err.detail || detail;
    } catch {
      // fallback
    }
    throw new Error(detail);
  }
  return res.json();
}

export async function updateUser(
  userId: string,
  payload: {
    email?: string;
    role?: UserRole;
    is_active?: boolean;
    password?: string;
    org_id?: string;
  }
): Promise<UserResponse> {
  const res = await authenticatedFetch(`/api/v1/users/${encodeURIComponent(userId)}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    let detail = 'Failed to update user';
    try {
      const err = await res.json();
      detail = err.detail || detail;
    } catch {
      // fallback
    }
    throw new Error(detail);
  }
  return res.json();
}

export async function deleteUser(userId: string): Promise<void> {
  const res = await authenticatedFetch(`/api/v1/users/${encodeURIComponent(userId)}`, {
    method: 'DELETE',
  });

  if (!res.ok) {
    let detail = 'Failed to delete user';
    try {
      const err = await res.json();
      detail = err.detail || detail;
    } catch {
      // fallback
    }
    throw new Error(detail);
  }
}
