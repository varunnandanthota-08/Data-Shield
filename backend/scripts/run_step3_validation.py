import json
import os
import sys
import time
import urllib.request
import urllib.error
import jwt

STAGING_URL = "http://127.0.0.1:8001"

def _load_staging_secret() -> str:
    secret = os.getenv("JWT_SECRET_KEY") or os.getenv("STAGING_JWT_SECRET")
    if secret:
        return secret
    staging_env = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env.staging")
    if os.path.exists(staging_env):
        with open(staging_env, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("JWT_SECRET_KEY="):
                    return line.strip().split("=", 1)[1].strip()
    return "datashield-staging-benchmark-placeholder-key-2026"

JWT_SECRET = _load_staging_secret()

def get_auth_token():
    now = time.time()
    payload = {
        "jti": f"step3-val-{int(now)}",
        "sub": "usr_analyst_08d2ce3c587b",
        "username": "staging_analyst",
        "role": "analyst",
        "org_id": "default",
        "token_type": "access",
        "iat": now,
        "exp": now + 7200,
        "iss": "datashield-ai"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def run_scan(text, context, token):
    url = f"{STAGING_URL}/api/v1/scan/text"
    req_body = json.dumps({
        "text": text,
        "context": context,
        "options": {
            "enable_entropy": True,
            "redaction_mode": "placeholder"
        }
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=req_body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    )

    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def fetch_scan_detail(scan_id, token):
    url = f"{STAGING_URL}/api/v1/scan/records/{scan_id}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def main():
    token = get_auth_token()

    scenarios = [
        {
            "name": "Scenario 1: Clean Internal Text",
            "description": "Clean engineering sprint notes with no sensitive entities",
            "text": "Sprint Retrospective Notes: Team completed refactoring of cache compaction and database indexing routines. All staging integration tests passed without errors. Next sprint starts Tuesday.",
            "context": {
                "destination": "INTERNAL_SERVICE",
                "recipient": "INTERNAL_EMPLOYEE",
                "classification": "INTERNAL",
                "actor_id": "staging_analyst",
                "purpose": "Internal sprint documentation"
            }
        },
        {
            "name": "Scenario 2: Single Email to External SaaS",
            "description": "Synthetic email address in an external ticket update transfer",
            "text": "Vendor Support Ticket #8841: Please reach out to customer contact alex.taylor.support@partner-example.com regarding access configuration for the external monitoring tool.",
            "context": {
                "destination": "EXTERNAL_SAAS",
                "recipient": "THIRD_PARTY_CONTRACTOR",
                "classification": "CONFIDENTIAL",
                "actor_id": "staging_analyst",
                "purpose": "Vendor coordination"
            }
        },
        {
            "name": "Scenario 3: Synthetic API Key to Public LLM",
            "description": "Synthetic API credential sent to an external/public AI service",
            "text": "Debugging OpenAI integration error: export OPENAI_API_KEY=\"sk-proj-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b\" in the worker environment.",
            "context": {
                "destination": "PUBLIC_LLM",
                "recipient": "PUBLIC",
                "classification": "CONFIDENTIAL",
                "actor_id": "staging_analyst",
                "purpose": "Public model query"
            }
        },
        {
            "name": "Scenario 4: Multi-Entity Payload (Email + SSN + Payment Card + Key)",
            "description": "Multiple synthetic sensitive-data types in one combined payload",
            "text": "Customer migration batch: Name: Jordan Smith; Contact: jordan.smith@example.org; SSN: 987-65-4320; Credit Card: 4111-1111-1111-1111; Cloud Key: AKIAIOSFODNN7EXAMPLE.",
            "context": {
                "destination": "PUBLIC_LLM",
                "recipient": "PUBLIC",
                "classification": "RESTRICTED",
                "actor_id": "staging_analyst",
                "purpose": "External batch processing"
            }
        },
        {
            "name": "Scenario 5: Missing / Ambiguous Metadata Context",
            "description": "Transfer with UNSPECIFIED destination and UNKNOWN recipient",
            "text": "Draft export file containing customer feedback and account notes for user sam.reed@domain.test.",
            "context": {
                "destination": "UNSPECIFIED",
                "recipient": "UNKNOWN",
                "classification": "INTERNAL",
                "actor_id": "staging_analyst"
            }
        }
    ]

    results = []

    print("=" * 80)
    print("RUNNING CONTROLLED SYNTHETIC SCENARIOS AGAINST LIVE STAGING ENVIRONMENT")
    print(f"Target URL: {STAGING_URL}")
    print("=" * 80)

    for sc in scenarios:
        print(f"\n---> Executing {sc['name']}...")
        start_t = time.perf_counter()
        res = run_scan(sc["text"], sc["context"], token)
        duration_ms = round((time.perf_counter() - start_t) * 1000, 2)

        scan_id = res.get("scan_id")
        policy_decision = res.get("policy_decision")
        risk_score = res.get("risk_score")
        risk_band = res.get("risk_band")
        finding_count = len(res.get("findings", []))
        triggered_policies = [p["id"] for p in res.get("triggered_policies", [])]

        ai_analysis = res.get("ai_analysis") or {}
        ai_status = ai_analysis.get("ai_status")
        model_id = ai_analysis.get("model_identifier")
        is_ai_assisted = ai_analysis.get("is_ai_assisted")
        incident_summary = ai_analysis.get("incident_summary", "")
        risk_factors = ai_analysis.get("relevant_risk_factors", [])
        policy_rationales = ai_analysis.get("policy_rationales", {})
        ambiguities = ai_analysis.get("ambiguities_and_uncertainty", [])
        remediations = ai_analysis.get("remediation_recommendations", [])

        # Fetch audit record to check security boundaries
        audit_detail = fetch_scan_detail(scan_id, token)
        audit_meta = audit_detail.get("audit_metadata", {})

        # Security boundary validations
        # 1. Deterministic authority
        decision_matches = (audit_detail.get("final_decision") == policy_decision)
        # 2. Policy IDs matching
        rationale_pids = list(policy_rationales.keys())
        pids_valid = all(pid in triggered_policies for pid in rationale_pids)
        # 3. No secrets in audit metadata
        raw_text_in_audit = (sc["text"] in json.dumps(audit_meta))
        
        # Check meaningful output
        has_meaningful_summary = len(incident_summary.strip()) > 10
        has_meaningful_output = has_meaningful_summary and (isinstance(risk_factors, list))

        record = {
            "scenario": sc["name"],
            "scan_id": scan_id,
            "deterministic_decision": policy_decision,
            "risk_score": risk_score,
            "risk_band": risk_band,
            "findings_detected": finding_count,
            "triggered_policy_ids": triggered_policies,
            "gemini_status": ai_status,
            "model_identifier": model_id,
            "is_ai_assisted": is_ai_assisted,
            "num_policy_rationales": len(policy_rationales),
            "num_remediations": len(remediations),
            "num_risk_factors": len(risk_factors),
            "num_ambiguities": len(ambiguities),
            "duration_ms": duration_ms,
            "meaningful_output": has_meaningful_output,
            "pids_valid": pids_valid,
            "decision_authoritative": decision_matches,
            "raw_text_leaked_in_audit": raw_text_in_audit,
            "summary_preview": incident_summary[:120],
            "ambiguities_list": ambiguities,
            "remediation_actions": [r.get("action_type") for r in remediations]
        }
        results.append(record)

        print(f"     Scan ID: {scan_id}")
        print(f"     Decision: {policy_decision} | Risk: {risk_score}/100 ({risk_band}) | Findings: {finding_count}")
        print(f"     AI Status: {ai_status} | Model: {model_id} | Assisted: {is_ai_assisted}")
        print(f"     Summary: {incident_summary[:100]}...")
        print(f"     Rationales ({len(policy_rationales)}): {list(policy_rationales.keys())}")
        print(f"     Remediations ({len(remediations)}): {[r.get('action_type') for r in remediations]}")
        print(f"     Ambiguities ({len(ambiguities)}): {ambiguities}")
        print(f"     Boundaries: pids_valid={pids_valid}, decision_auth={decision_matches}, audit_leak={raw_text_in_audit}")

    # Output JSON summary
    with open("scripts/step3_validation_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 80)
    print("ALL SCENARIOS COMPLETED AND SAVED TO scripts/step3_validation_results.json")
    print("=" * 80)

if __name__ == "__main__":
    main()
