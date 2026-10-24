import json
import math
import statistics
import time
import os
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
        "jti": f"step5-bench-{int(now)}",
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

def calculate_percentile(data, percentile):
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (percentile / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    d0 = sorted_data[int(f)] * (c - k)
    d1 = sorted_data[int(c)] * (k - f)
    return round(d0 + d1, 2)

def main():
    token = get_auth_token()

    # Controlled sequence of 5 distinct synthetic scenarios
    benchmark_payloads = [
        {
            "id": "SEQ-01",
            "name": "Clean Internal Memo",
            "text": "Internal architectural memo: Team completed Redis caching optimization. Zero customer data stored in cache. Staging smoke tests passed.",
            "context": {"destination": "INTERNAL_SERVICE", "recipient": "INTERNAL_EMPLOYEE", "classification": "INTERNAL"}
        },
        {
            "id": "SEQ-02",
            "name": "External SaaS Email Transfer",
            "text": "External vendor ticket: Please share technical contact sam.support@external-partner.org for the monitoring integration sync.",
            "context": {"destination": "EXTERNAL_SAAS", "recipient": "THIRD_PARTY_CONTRACTOR", "classification": "CONFIDENTIAL"}
        },
        {
            "id": "SEQ-03",
            "name": "Public LLM OpenAI Key Query",
            "text": "Troubleshooting API integration error in worker: export OPENAI_API_KEY='sk-proj-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b'.",
            "context": {"destination": "PUBLIC_LLM", "recipient": "PUBLIC", "classification": "CONFIDENTIAL"}
        },
        {
            "id": "SEQ-04",
            "name": "Unspecified Destination Missing Context",
            "text": "Customer feedback draft for user contact: pat.chen@example.com awaiting operational routing.",
            "context": {"destination": "UNSPECIFIED", "recipient": "UNKNOWN", "classification": "INTERNAL"}
        },
        {
            "id": "SEQ-05",
            "name": "Multi-Entity Exfiltration Check",
            "text": "Batch migration export note: Customer Jane Doe, SSN: 123-45-6789, Card: 4111-1111-1111-1111, AWS Key: AKIAIOSFODNN7EXAMPLE.",
            "context": {"destination": "PUBLIC_LLM", "recipient": "PUBLIC", "classification": "RESTRICTED"}
        }
    ]

    print("=" * 80)
    print("CONTROLLED LATENCY & RELIABILITY BENCHMARK (STEP 5)")
    print(f"Target Environment: {STAGING_URL} (Staging)")
    print(f"Controlled Sequence Size: {len(benchmark_payloads)} requests")
    print("=" * 80)

    e2e_latencies = []
    provider_latencies = []
    deterministic_latencies = []
    token_usage_records = []
    records = []

    for item in benchmark_payloads:
        print(f"\n--> Executing [{item['id']}] {item['name']}...")
        url = f"{STAGING_URL}/api/v1/scan/text"
        body = json.dumps({
            "text": item["text"],
            "context": item["context"],
            "options": {"enable_entropy": True, "redaction_mode": "placeholder"}
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
        )

        client_start_t = time.perf_counter()
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        e2e_ms = round((time.perf_counter() - client_start_t) * 1000, 2)

        det_ms = data.get("processing_duration_ms", 0.0)
        ai_analysis = data.get("ai_analysis") or {}
        usage = ai_analysis.get("usage") or {}

        prov_ms = usage.get("latency_ms")
        if prov_ms is None:
            # If server didn't return usage.latency_ms, provider took ~ e2e_ms - det_ms
            prov_ms = round(max(0.0, e2e_ms - det_ms), 2)

        prompt_tokens = usage.get("prompt_tokens")
        candidates_tokens = usage.get("candidates_tokens")
        total_tokens = usage.get("total_tokens")

        e2e_latencies.append(e2e_ms)
        provider_latencies.append(prov_ms)
        deterministic_latencies.append(det_ms)
        if total_tokens:
            token_usage_records.append(total_tokens)

        record = {
            "id": item["id"],
            "name": item["name"],
            "scan_id": data.get("scan_id"),
            "deterministic_decision": data.get("policy_decision"),
            "risk_score": data.get("risk_score"),
            "e2e_latency_ms": e2e_ms,
            "provider_latency_ms": prov_ms,
            "deterministic_latency_ms": det_ms,
            "ai_status": ai_analysis.get("ai_status"),
            "is_ai_assisted": ai_analysis.get("is_ai_assisted"),
            "prompt_tokens": prompt_tokens,
            "candidates_tokens": candidates_tokens,
            "total_tokens": total_tokens,
            "retries_attempted": usage.get("retries_attempted", 0),
            "actual_provider_attempts": 1 + usage.get("retries_attempted", 0) if ai_analysis.get("is_ai_assisted") else 0,
            "rate_limit_encountered": usage.get("rate_limit_encountered", False),
        }
        records.append(record)

        print(f"    E2E Latency: {e2e_ms} ms | Provider Latency: {prov_ms} ms | Engine Latency: {det_ms} ms")
        print(f"    Decision: {data.get('policy_decision')} | AI Status: {ai_analysis.get('ai_status')}")
        print(f"    Tokens: {prompt_tokens} in / {candidates_tokens} out (total: {total_tokens})")
        print(f"    Attempts: {record['actual_provider_attempts']} (retries: {record['retries_attempted']})")

        # Brief pause between sequential requests to prevent artificial burst rate limits
        time.sleep(1.5)

    # Statistical Analysis
    e2e_min = round(min(e2e_latencies), 2)
    e2e_median = round(statistics.median(e2e_latencies), 2)
    e2e_p95 = calculate_percentile(e2e_latencies, 95)
    e2e_max = round(max(e2e_latencies), 2)

    prov_min = round(min(provider_latencies), 2)
    prov_median = round(statistics.median(provider_latencies), 2)
    prov_p95 = calculate_percentile(provider_latencies, 95)
    prov_max = round(max(provider_latencies), 2)

    det_min = round(min(deterministic_latencies), 2)
    det_median = round(statistics.median(deterministic_latencies), 2)
    det_max = round(max(deterministic_latencies), 2)

    prov_share_pct = round((prov_median / e2e_median) * 100, 1) if e2e_median > 0 else 0

    summary = {
        "records": records,
        "statistics": {
            "sample_size": len(records),
            "e2e_latency_ms": {
                "min": e2e_min,
                "median": e2e_median,
                "p95": e2e_p95,
                "max": e2e_max,
            },
            "provider_latency_ms": {
                "min": prov_min,
                "median": prov_median,
                "p95": prov_p95,
                "max": prov_max,
            },
            "deterministic_latency_ms": {
                "min": det_min,
                "median": det_median,
                "max": det_max,
            },
            "provider_latency_share_percent": prov_share_pct,
            "total_tokens_consumed": sum(token_usage_records),
            "avg_tokens_per_scan": round(sum(token_usage_records) / len(token_usage_records), 1) if token_usage_records else 0,
        }
    }

    with open("scripts/step5_benchmark_results.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 80)
    print("BENCHMARK SUMMARY RESULTS:")
    print(f"End-to-End Latency:  Min: {e2e_min} ms | Median: {e2e_median} ms | P95: {e2e_p95} ms | Max: {e2e_max} ms")
    print(f"Gemini Provider:     Min: {prov_min} ms | Median: {prov_median} ms | P95: {prov_p95} ms | Max: {prov_max} ms")
    print(f"Deterministic Engine:Min: {det_min} ms | Median: {det_median} ms | Max: {det_max} ms")
    print(f"Provider Latency Share of Total: {prov_share_pct}%")
    print(f"Total Tokens Consumed across sequence: {sum(token_usage_records)}")
    print("Results saved to backend/scripts/step5_benchmark_results.json")
    print("=" * 80)

if __name__ == "__main__":
    main()
