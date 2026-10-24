# DataShield AI — Production Deployment Guide

## 1. Overview & Architecture Summary

DataShield AI is a GenAI Data Loss Prevention (DLP) and sensitive data exposure mitigation gateway. It features:
- **Frontend**: React 18, TypeScript, Vite SPA (`frontend/`).
- **Backend**: FastAPI (Python 3.11–3.14), Uvicorn ASGI server (`backend/app/`).
- **Persistence & Audit**: SQLite with Write-Ahead Logging (`WAL` mode) and SHA-256 cryptographic hash-chained audit logging (`datashield.db`).
- **Deterministic Enforcement**: Real-time regex and Shannon entropy detectors, deterministic policy matching hierarchy (mandatory `BLOCK` precedence), position-aware redaction, and multi-tenant isolation.
- **Advisory AI Layer**: Optional Google Gemini integration providing contextual risk commentary and least-privilege remediation advice without overriding deterministic enforcement.

---

## 2. Prerequisites & Supported Runtime Versions

| Component | Minimum Version | Recommended Version | Tested Environment |
| :--- | :--- | :--- | :--- |
| **Python** | 3.11+ | 3.12 or 3.14 | Python 3.14.5 |
| **Node.js** | 18.x LTS | 20.x or 22.x LTS | Node.js 20+ |
| **Package Managers** | `pip` (Python), `npm` (Node) | `pip` >= 24, `npm` >= 10 | Standard |
| **OS** | Linux (Ubuntu 22.04+, Debian 12, RHEL 9), Windows 11/Server | Linux (POSIX) | Windows 11 / Linux |
| **Memory** | 1 GB RAM | 2–4 GB RAM | 2 GB+ |
| **Disk** | 500 MB free space | 10 GB+ SSD (for audit logs) | SSD storage |

---

## 3. Environment Configuration & Reference

Configure environment variables via `.env` in the `backend/` root directory.

### Environment Variable Reference

| Variable Name | Default Value | Production Requirement | Description |
| :--- | :--- | :--- | :--- |
| `ENVIRONMENT` | `development` | **`production`** | Operating mode. Enforces strict cryptographic validation when set to `production`. |
| `DEBUG` | `true` | **`false`** | Disables tracebacks and verbose stack prints. Server returns safe correlation `error_id`. |
| `HOST` | `127.0.0.1` | `127.0.0.1` | ASGI bind IP. In production, bind locally behind a reverse proxy. |
| `PORT` | `8001` | `8001` (or custom) | ASGI bind port. |
| `JWT_SECRET_KEY` | *(dev key)* | **Required (Min 32 chars)** | Secret key for signing HMAC-SHA256 JWT access tokens. Must not contain `dev`, `replace`, `default`. |
| `JWT_ALGORITHM` | `HS256` | `HS256` | Cryptographic algorithm for JWT signatures. |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | `15` to `60` | Token lifetime before re-authentication is required. |
| `CORS_ORIGINS` | `["http://localhost:5173", ...]` | Explicit production domains | Allowed origins. **Wildcard (`*`) is rejected in production** when credentials are enabled. |
| `SQLITE_DB_PATH` | `datashield.db` | Persistent volume path | Path to primary SQLite database file. Parent directory is created automatically. |
| `RATE_LIMIT_STORAGE_BACKEND` | `sqlite` | **`sqlite`** | Rate-limit storage mode (`sqlite` for multi-worker ACID consistency, `memory` for single-process test). |
| `AUTH_RATE_LIMIT_MAX_ATTEMPTS` | `5` | `5` | Maximum failed login attempts allowed within window before account/IP lockout. |
| `AUTH_RATE_LIMIT_WINDOW_SECONDS` | `60` | `60` | Time window for evaluating failed login attempts. |
| `AUTH_RATE_LIMIT_LOCKOUT_SECONDS` | `300` | `300` (5 minutes) | Lockout duration after exceeding failed login attempts. |
| `SCAN_RATE_LIMIT_PER_MINUTE` | `60` | `60` (or per tier) | Maximum scan API submissions permitted per user/tenant per minute (HTTP 429). |
| `COOKIE_SECURE` | Auto (`None`) | `true` (auto) | Enforces `Secure` flag on HttpOnly session cookies. Auto-enabled when `ENVIRONMENT=production`. |
| `COOKIE_SAMESITE` | `lax` | `lax` or `strict` | Cross-site cookie attribute for CSRF mitigation. |
| `TRUST_FORWARDED_FOR` | `false` | `true` (if behind proxy) | When `true`, accepts `X-Forwarded-For` client IP only if direct caller is in `TRUSTED_PROXIES`. |
| `TRUSTED_PROXIES` | `["127.0.0.1", "::1"]` | Reverse proxy IP(s) | Explicit IP whitelist of trusted internal reverse proxies. |
| `ENABLE_PROD_DOCS` | `false` | `false` | Disables `/docs` and `/redoc` Swagger endpoints in production. |
| `MAX_UPLOAD_SIZE_BYTES` | `5242880` (5 MB) | `5242880` | Maximum file size permitted for document extraction and scanning (HTTP 413). |
| `MAX_EXTRACTED_CHARS` | `500000` | `500000` | Maximum plain-text character budget to prevent buffer exhaustion. |
| `GEMINI_API_KEY` | `None` | Optional valid key | Google Gemini API key. If unset, engine falls back to deterministic explanations. |
| `GEMINI_MODEL` | `gemini-3.1-flash-lite` | `gemini-3.1-flash-lite` | Target Gemini model identifier. |
| `GEMINI_TIMEOUT_SECONDS` | `10.0` | `10.0` | Timeout deadline for advisory LLM calls before graceful degradation. |
| `GEMINI_MAX_RETRIES` | `2` | `2` | Number of retry attempts on transient LLM network failures. |

### Generating a Secure Production Secret
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## 4. Production Startup & Server Configuration

### 4.1 Backend Installation & Startup

1. **Create and activate a clean virtual environment**:
   ```bash
   cd backend
   python -m venv .venv
   # Windows:
   .\.venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```

2. **Install production dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Configure production environment**:
   Copy `.env.example` to `.env` and set `ENVIRONMENT=production`, a generated `JWT_SECRET_KEY`, and production `CORS_ORIGINS`:
   ```bash
   cp .env.example .env
   ```

4. **Start the ASGI server**:
   For single-node deployments using SQLite-backed rate limiting:
   ```bash
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --workers 2 --no-access-log
   ```
   *Note: In production, bind to `127.0.0.1` and route external traffic through a reverse proxy.*

### 4.2 Frontend Build & Static Serving

1. **Install dependencies and build production bundle**:
   ```bash
   cd frontend
   npm ci
   npm run build
   ```
   Output is emitted to `frontend/dist/` (HTML, hashed CSS, chunked JS).

2. **Serving static assets**:
   Serve `frontend/dist` using an HTTP server (e.g. Nginx, Caddy, or Cloudflare Pages) configured with single-page app fallback routing (`try_files $uri $uri/ /index.html;`).

### 4.3 Controlled Staging Deployment (Phase 8)

Staging provides a dedicated, production-equivalent environment with complete isolation:

1. **Dedicated Staging Configuration (`backend/.env.staging`)**:
   - `ENVIRONMENT=staging`
   - `DEBUG=false`
   - `SQLITE_DB_PATH=datashield_staging.db` (anchored safely inside `backend/`)
   - `ALLOW_PUBLIC_REGISTRATION=false`
   - Dedicated cryptographically secure staging `JWT_SECRET_KEY`

2. **Start Backend in Staging Mode (PowerShell)**:
   ```powershell
   cd backend
   # Load staging environment file and run Uvicorn
   .\.venv\Scripts\python.exe -m uvicorn app.main:app --env-file .env.staging --host 127.0.0.1 --port 8001
   ```

3. **Database Isolation Guarantee**:
   The backend resolves `datashield_staging.db` relative to `backend/`. The primary development database (`backend/datashield.db`) and obsolete root database (`datashield.db`) remain untouched.

4. **Staging Smoke & Health Probe**:
   ```powershell
   Invoke-RestMethod -Uri "http://127.0.0.1:8001/api/health/ready" | ConvertTo-Json
   ```
   Expected response:
   ```json
   {
     "status": "ready",
     "database": "connected",
     "resolved_db_path": "...\\backend\\datashield_staging.db"
   }
   ```

---

## 5. Reverse Proxy, TLS, & Security Headers

### Architecture
```
[Client / Browser]
       │
       │ HTTPS (Port 443) / TLS Termination
       ▼
[Reverse Proxy (Nginx / Caddy / Cloudflare)]
       │
       ├─► /api/* ────────► http://127.0.0.1:8001 (FastAPI ASGI)
       └─► /* (Static) ───► /var/www/datashield/frontend/dist/
```

### Recommended Nginx Configuration
```nginx
server {
    listen 443 ssl http2;
    server_name datashield.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/datashield.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/datashield.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Maximum file upload size aligned with backend limit (5MB + headers)
    client_max_body_size 6M;

    # Security headers (supplementing FastAPI middleware)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Static Frontend SPA
    location / {
        root /var/www/datashield/frontend/dist;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    # Backend API Proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8001;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 6. Database Lifecycle, Backups, & Audit Verification

### Database Location & Initialization
- Default database file: `backend/datashield.db`.
- Database initialization is strictly **non-destructive**. On startup, `init_db()` executes `CREATE TABLE IF NOT EXISTS`, adds missing columns via schema introspection (`ALTER TABLE ADD COLUMN`), and seeds baseline policies only if the policy table is empty.
- Write-Ahead Logging (`PRAGMA journal_mode = WAL;`) and busy timeout (`10.0s`) are automatically enabled on connection.

### Safe Online Backup & Isolated Restore Procedure
Because SQLite operates in `WAL` mode, standard file-copying tools (`cp`, `xcopy`) during active writes can cause partial reads. Use the built-in backup CLI utility, which leverages SQLite's online backup API with transactional locking:

```powershell
# Windows / PowerShell:
cd backend
.\.venv\Scripts\python.exe scripts/db_verify_and_backup.py --backup-to backups/datashield_backup.db --verify-audit
```

### Safe Restore Procedure (Non-Destructive)
> [!IMPORTANT]
> DataShield AI strictly blocks restoring directly over an active database. Restoration must always be directed to a separate, dedicated staging or test database path:

```powershell
# Restore to an isolated target location and automatically verify integrity and audit chain:
.\.venv\Scripts\python.exe scripts/db_verify_and_backup.py `
  --restore-from backups/datashield_backup.db `
  --restore-to backups/restored_staging_verify.db `
  --verify-audit
```
Expected output:
- `Safe Restore Succeeded: ...\backups\restored_staging_verify.db`
- `Restored Integrity: HEALTHY`
- `Restored Audit Chain: VALID`

### Recovery Steps if Verification Fails
1. Check error details in the CLI output (`errors` array and `tampered_event_id`).
2. Do not copy corrupt files over the active database.
3. Validate against the previous rotation point or run `PRAGMA integrity_check` on the candidate backup.
4. If a specific tenant chain shows anomalies, check server logs for the matching correlation error IDs.

---

## 7. Rate Limiting & Resource Controls

### Storage Backends
1. **`RATE_LIMIT_STORAGE_BACKEND=sqlite` (Recommended for single-node / multi-worker)**:
   - Maintains rate-limiting counters in the `auth_rate_limits` table inside SQLite.
   - Fully ACID-compliant and shared across multiple Uvicorn worker processes on the same host.
2. **`RATE_LIMIT_STORAGE_BACKEND=memory` (Testing Only)**:
   - In-memory sliding window counters bound strictly to a single Python process. Not shared across workers.

### Distributed / Multi-Node Deployments
If deploying DataShield AI across multiple physical virtual machines or container instances behind a round-robin load balancer, a centralized key-value store (such as Redis) is required for distributed sliding-window counters. For single-host deployments, `sqlite` mode provides full multi-worker coverage without external infrastructure.

---

## 8. Logging, Observability, & Health Probes

### Endpoints
- **Liveness Probe**: `GET /api/health`
  - Returns `200 OK` with service name, version, timestamp, environment mode, and LLM configuration state.
  - Zero secrets or internal configuration values are exposed.
- **Readiness Probe**: `GET /api/health/ready`
  - Returns `200 OK` if the SQLite database is responsive. Returns `503 Service Unavailable` if database queries fail.
- **Root Discoverability**: `GET /`
  - Returns metadata and links to `/api/health`, `/api/v1/policies`, and `/api/v1/audit/events`.

### Safe Logging Guidelines
- Passwords, authorization tokens, session cookies, unredacted raw document payloads, and API keys are strictly excluded from logging.
- Unhandled application exceptions generate a unique correlation ID (`err_<hex>`) returned in HTTP 500 responses and recorded in server logs for audit triage.

---

## 9. Security Verification & Pre-Flight Checklist

Before opening network traffic to users, verify the following checklist:

- [ ] `ENVIRONMENT` is set to `production` in `.env`.
- [ ] `DEBUG` is set to `false`.
- [ ] `JWT_SECRET_KEY` is set to a cryptographically strong random key (>= 32 chars).
- [ ] `CORS_ORIGINS` contains only trusted production frontend domains (no `*`).
- [ ] `TRUST_FORWARDED_FOR` is set to `true` only if trusted reverse proxies are defined in `TRUSTED_PROXIES`.
- [ ] Reverse proxy enforces TLS (HTTPS) and sets `Strict-Transport-Security` headers.
- [ ] Initial bootstrap completed (`POST /api/v1/auth/bootstrap`) with a strong password. Subsequent bootstrap attempts are locked.
- [ ] Regression test suite runs clean: `pytest -v` (0 failures).
- [ ] Frontend build succeeds: `npm run build` (exit code 0).
- [ ] Database backup schedule configured via `scripts/db_verify_and_backup.py`.
