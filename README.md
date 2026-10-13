# DataShield AI — GenAI Data Loss Prevention & Sensitive Data Exposure

DataShield AI is an enterprise-grade GenAI Data Loss Prevention (DLP) and policy enforcement gateway designed to detect, classify, redact, explain, and audit sensitive data in AI prompt pipelines, RAG ingestion flows, and LLM completions.

---

## Architecture Overview (Phase 1)

```
┌──────────────────────────────────────────────┐
│  DataShield AI SOC UI (Vite + React + TS)    │
│  - Modern Dark Mode Security Aesthetics      │
│  - Live Gateway Health & Latency Telemetry   │
└───────────────────────┬──────────────────────┘
                        │ Reverse Proxy /api/ -> :8001
┌───────────────────────▼──────────────────────┐
│  FastAPI Backend Core (Python 3.13)          │
│  - CORS Middleware                           │
│  - /api/health Endpoint                      │
│  - Safe Environment Key Detection            │
└──────────────────────────────────────────────┘
```

---

## Prerequisites

- **Python**: 3.10+ (Tested on Python 3.13.5)
- **Node.js**: 18+ (Tested on Node.js v22.18.0 & npm 10.9.3)

---

## Quickstart & Setup Commands

### 1. Backend Setup

```bash
# From workspace root (e:\DataShield)
python -m venv .venv

# On Windows:
.venv\Scripts\activate

# Install dependencies:
pip install -r backend/requirements.txt

# Start backend development server (runs on http://127.0.0.1:8001):
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8001 --reload
```

Interactive API documentation will be available at:
- Swagger UI: `http://127.0.0.1:8001/docs`
- Redoc: `http://127.0.0.1:8001/redoc`
- Direct Health Check: `http://127.0.0.1:8001/api/health`
- Scan & Redact API: `http://127.0.0.1:8001/api/v1/scan/text`

---

## Detection Engine (Phase 2)

### Supported Patterns & Rules

| Category | Rule ID | Pattern Details | Evidence Masking |
|---|---|---|---|
| **PII** | `pii_email_address` | RFC 5322 pragmatic candidate email addresses | `j***e@domain.com` |
| **PII** | `pii_phone_number` | North American Numbering Plan & International E.164 candidates | `***-***-4567` |
| **PII** | `pii_us_ssn` | US Social Security Numbers (rejects area `000`, `666`, `900+`, group `00`) | `***-**-6789` |
| **PII** | `pii_uk_nin` | UK National Insurance Numbers | `AB******D` |
| **PAYMENT_CARD** | `payment_card_luhn_valid` | 13-19 digit candidates with **Luhn algorithm checksum** validation & brand recognition (Visa, Mastercard, Amex, Discover, Diners, JCB) | `4111-****-****-1111` |
| **SECRET** | `secret_aws_access_key` | AWS Access Key ID (`AKIA...`) | `AKI****...****LE` |
| **SECRET** | `secret_aws_secret_key` | AWS Secret Access Key in variable assignments | `********` |
| **SECRET** | `secret_github_token` | GitHub PAT (`ghp_...`), OAuth (`gho_...`), Fine-grained (`github_pat_...`) | `ghp****...****99` |
| **SECRET** | `secret_openai_api_key` | OpenAI standard and project keys (`sk-...`, `sk-proj-...`) | `sk-****...****78` |
| **SECRET** | `secret_google_api_key` | Google Cloud & Gemini API keys (`AIza...`) | `AIz****...****35` |
| **SECRET** | `secret_slack_token` | Slack Bot/User tokens (`xox[baprs]-...`) | `xox****...****32` |
| **SECRET** | `secret_jwt_token` | Three-part base64url JSON Web Tokens starting with `eyJ...` | `eyJ****...****5c` |
| **SECRET** | `secret_private_key_block` | RSA / EC / DSA / OpenSSH private key header and body blocks | `[PROTECTED_KEY_BODY]` |
| **CREDENTIAL** | `credential_hardcoded_assignment` | Hardcoded passwords or credentials in assignments (`password = '...'`) | `********` |
| **HIGH_ENTROPY_TOKEN** | `entropy_high_token` | Shannon entropy $\ge 4.2$ bits on alphanumeric tokens ($\ge 20$ chars) | `k8J****...****8g` |

### Known Limitations

1. **Non-Formatted Numbers**: 10-digit phone numbers embedded without delimiters inside long alphanumeric product codes are rejected to prevent excessive false positives.
2. **Ambiguous Credentials**: Unquoted single-word passwords without explicit assignment keys (`password=`, `api_key=`) require semantic context analysis (handled in Phase 4 via LLM copilot).
3. **Card Numbers**: Passing Luhn validation indicates high card plausibility, but does not guarantee the existence of an active bank account.

---

## Implementation Roadmap

- [x] **Phase 1**: Scaffolding, FastAPI Core, Vite React Frontend, Cybersecurity Design Tokens, Connectivity Check.
- [x] **Phase 2**: Multi-Tier Detection Engine (Regex, Luhn Checksums, Shannon Entropy, Position-Aware Redactor, Studio UI).
- [ ] **Phase 3**: Contextual Policy Rules, Composite Risk Scoring (0–100), and Tamper-Evident Audit Trails.
- [ ] **Phase 4**: AI Context Disambiguation, Plain-Language Explanations, and Least-Privilege Remediation.
- [ ] **Phase 5**: Interactive SOC Studio UI (Side-by-side diff, policy editor, audit browser).
- [ ] **Phase 6**: End-to-End Hardening, Attack Payload Suite, and Hackathon Demo Readiness.
