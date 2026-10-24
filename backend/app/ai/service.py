import json
import logging
import os
import time
from typing import List, Optional
from pydantic import ValidationError
from app.ai.fallback import generate_deterministic_explanation
from app.ai.sanitizer import build_sanitized_ai_prompt, verify_sanitization
from app.ai.schemas import (
    AIContextAnalysisResult,
    AIUsageTelemetry,
    RemediationActionType,
    RemediationRecommendation,
)
from app.core.config import settings
from app.engine.schemas import Finding
from app.policy.schemas import PolicyEvaluationResult, RiskScoreResult, SharingContext

logger = logging.getLogger(__name__)


class GeminiContextAnalysisService:
    """Dedicated AI service for explainable security decisions & least-privilege remediation.
    Operates strictly as an advisory explanation layer.
    Separation of concerns: AI explanations NEVER alter or override deterministic decisions.
    """

    def __init__(self):
        self._model = settings.GEMINI_MODEL
        self._timeout_seconds = settings.GEMINI_TIMEOUT_SECONDS
        self._max_retries = settings.GEMINI_MAX_RETRIES

    @property
    def is_configured(self) -> bool:
        """Determines if the Gemini API key is available without exposing the key value."""
        return settings.is_llm_configured

    def _get_client(self):
        """Initializes the official Google Gen AI SDK Client securely."""
        key = settings.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY")
        if not key or not key.strip():
            return None
        from google import genai
        # Initialize client with API key
        return genai.Client(api_key=key.strip())

    def analyze_context(
        self,
        sanitized_text: str,
        findings: List[Finding],
        context: SharingContext,
        policy_result: PolicyEvaluationResult,
        risk_result: RiskScoreResult,
    ) -> AIContextAnalysisResult:
        """Analyzes transfer context and generates structured explanations and least-privilege remediations.
        Fails safely to deterministic fallback if Gemini is unconfigured, times out, or errors.
        """
        # 1. Check if model is configured
        if not self.is_configured:
            return generate_deterministic_explanation(
                findings=findings,
                context=context,
                policy_result=policy_result,
                risk_result=risk_result,
                failure_reason="GEMINI_API_KEY is not configured",
                latency_ms=0.0,
                retries_attempted=0,
                api_calls_count=0,
            )

        # 2. Privacy verification: Ensure input is safely masked before sending
        if not verify_sanitization(sanitized_text, findings):
            return generate_deterministic_explanation(
                findings=findings,
                context=context,
                policy_result=policy_result,
                risk_result=risk_result,
                failure_reason="Sanitization verification failed: input could not be verified safe for model egress",
                latency_ms=0.0,
                retries_attempted=0,
                api_calls_count=0,
            )

        triggered_ids = [p.id for p in policy_result.triggered_policies]

        # 3. Build sanitized, prompt-injection-resistant prompt
        prompt = build_sanitized_ai_prompt(
            sanitized_text=sanitized_text,
            findings=findings,
            context=context,
            policy_decision=policy_result.final_decision,
            triggered_policy_ids=triggered_ids,
            risk_score=risk_result.score,
            risk_band=risk_result.band,
        )

        client = None
        try:
            client = self._get_client()
        except Exception as client_err:
            return generate_deterministic_explanation(
                findings=findings,
                context=context,
                policy_result=policy_result,
                risk_result=risk_result,
                failure_reason=f"Failed to initialize GenAI client: {client_err}",
                latency_ms=0.0,
                retries_attempted=0,
                api_calls_count=0,
            )

        if not client:
            return generate_deterministic_explanation(
                findings=findings,
                context=context,
                policy_result=policy_result,
                risk_result=risk_result,
                failure_reason="GenAI client unavailable",
                latency_ms=0.0,
                retries_attempted=0,
                api_calls_count=0,
            )

        # 4. Invoke model with bounded retries for transient failures
        start_time = time.perf_counter()
        retries_attempted = 0
        rate_limit_encountered = False
        timeout_encountered = False
        last_error_type = None
        last_error = ""
        from google.genai import types

        config = types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.1,  # Low temperature for deterministic security consistency
        )

        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                retries_attempted = attempt
            try:
                response = client.models.generate_content(
                    model=self._model,
                    contents=prompt,
                    config=config,
                )

                if not response or not response.text:
                    raise ValueError("Empty response received from Gemini model")

                # Parse JSON text safely
                parsed_json = json.loads(response.text)

                latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

                # Extract provider-confirmed usage metadata if present
                meta = getattr(response, "usage_metadata", None)
                def _safe_int(val):
                    if val is not None and isinstance(val, (int, float)):
                        return int(val)
                    return None

                prompt_tokens = _safe_int(getattr(meta, "prompt_token_count", None)) if meta else None
                candidates_tokens = _safe_int(getattr(meta, "candidates_token_count", None)) if meta else None
                total_tokens = _safe_int(getattr(meta, "total_token_count", None)) if meta else None
                cached_tokens = _safe_int(getattr(meta, "cached_content_token_count", None)) if meta else None

                raw_resp_id = getattr(response, "response_id", None)
                response_id = str(raw_resp_id) if raw_resp_id is not None and isinstance(raw_resp_id, str) else None

                usage = AIUsageTelemetry(
                    prompt_tokens=prompt_tokens,
                    candidates_tokens=candidates_tokens,
                    total_tokens=total_tokens,
                    cached_tokens=cached_tokens,
                    is_estimated=False,
                    operation="context_policy_remediation",
                    api_calls_count=1,
                    latency_ms=latency_ms,
                    retries_attempted=retries_attempted,
                    rate_limit_encountered=rate_limit_encountered,
                    timeout_encountered=timeout_encountered,
                    error_type=last_error_type,
                    fallback_reason=None,
                    provider_status="SUCCESS",
                    provider_response_id=response_id,
                )

                # Validate against strict Pydantic response schema
                result = self._validate_and_normalize_response(
                    parsed_json=parsed_json,
                    triggered_ids=triggered_ids,
                    findings=findings,
                    policy_result=policy_result,
                    risk_result=risk_result,
                    usage=usage,
                )
                return result

            except json.JSONDecodeError as json_err:
                last_error_type = "JSON_DECODE_ERROR"
                last_error = f"Model returned invalid JSON: {json_err}"
                break  # Non-transient format error; do not retry

            except ValidationError as val_err:
                last_error_type = "SCHEMA_VALIDATION_ERROR"
                last_error = f"Model response failed schema validation: {val_err}"
                break  # Non-transient schema error; do not retry

            except Exception as exc:
                err_str = str(exc)
                last_error = f"Provider invocation error: {err_str}"
                err_lower = err_str.lower()
                is_rate_limit = any(kw in err_lower for kw in ["429", "rate limit", "quota", "resource_exhausted"])
                is_timeout = any(kw in err_lower for kw in ["timeout", "timed out", "deadline"])
                if is_rate_limit:
                    rate_limit_encountered = True
                    last_error_type = "RATE_LIMIT"
                elif is_timeout:
                    timeout_encountered = True
                    last_error_type = "TIMEOUT"
                else:
                    last_error_type = "PROVIDER_ERROR"

                is_transient = any(
                    transient_kw in err_lower
                    for transient_kw in ["429", "rate limit", "503", "unavailable", "timeout", "connection reset"]
                )
                if is_transient and attempt < self._max_retries:
                    time.sleep(0.5 * (2 ** attempt))
                    continue
                else:
                    break

        # Fallback if invocation failed or exhausted retries
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return generate_deterministic_explanation(
            findings=findings,
            context=context,
            policy_result=policy_result,
            risk_result=risk_result,
            failure_reason=last_error or "Model invocation failed",
            latency_ms=latency_ms,
            retries_attempted=retries_attempted,
            api_calls_count=1,
        )

    def _validate_and_normalize_response(
        self,
        parsed_json: dict,
        triggered_ids: List[str],
        findings: List[Finding],
        policy_result: PolicyEvaluationResult,
        risk_result: RiskScoreResult,
        usage: Optional[AIUsageTelemetry] = None,
    ) -> AIContextAnalysisResult:
        """Normalizes and validates model response to ensure it respects hard boundaries:
        - Filters out invented policy IDs not present in triggered_ids.
        - Enforces that remediation recommendations are marked advisory.
        - Prevents model from overriding authoritative decisions.
        - Preserves usage and reliability telemetry.
        """
        raw_rationales = parsed_json.get("policy_rationales")
        if not isinstance(raw_rationales, dict):
            raw_rationales = {}
        # Filter policy rationales to only valid triggered policy IDs
        filtered_rationales = {
            pid: str(rationale)
            for pid, rationale in raw_rationales.items()
            if pid in triggered_ids and rationale
        }
        # If model missed explanations for any triggered policies, populate from deterministic rules
        for p in policy_result.triggered_policies:
            if p.id not in filtered_rationales:
                filtered_rationales[p.id] = f"{p.name}: {p.intent_explanation}"

        # Parse remediation recommendations
        recs_data = parsed_json.get("remediation_recommendations")
        if not isinstance(recs_data, list):
            recs_data = []
        validated_recs: List[RemediationRecommendation] = []
        for idx, rec_dict in enumerate(recs_data):
            if not isinstance(rec_dict, dict):
                continue
            try:
                # Ensure action_type is valid
                action_type_str = str(rec_dict.get("action_type", ""))
                if action_type_str not in RemediationActionType.__members__:
                    action_type = RemediationActionType.REQUEST_HUMAN_REVIEW
                else:
                    action_type = RemediationActionType(action_type_str)

                rec = RemediationRecommendation(
                    id=str(rec_dict.get("id", f"REM-{idx+1:02d}")),
                    action_type=action_type,
                    title=str(rec_dict.get("title", "Advisory Remediation")),
                    explanation=str(rec_dict.get("explanation", "")),
                    reason=str(rec_dict.get("reason", "Based on detected findings")),
                    expected_security_benefit=str(rec_dict.get("expected_security_benefit", "Enhances security posture")),
                    requires_human_approval=bool(rec_dict.get("requires_human_approval", False)),
                    is_advisory=True,
                )
                validated_recs.append(rec)
            except Exception:
                continue

        # If model returned no recommendations, fall back to deterministic recommendations
        if not validated_recs:
            det_fallback = generate_deterministic_explanation(
                findings=findings,
                context=policy_result.context_evaluated,
                policy_result=policy_result,
                risk_result=risk_result,
            )
            validated_recs = det_fallback.remediation_recommendations

        risk_factors_raw = parsed_json.get("relevant_risk_factors")
        risk_factors = [str(rf) for rf in risk_factors_raw if rf] if isinstance(risk_factors_raw, list) else []

        ambiguities_raw = parsed_json.get("ambiguities_and_uncertainty")
        ambiguities = [str(a) for a in ambiguities_raw if a] if isinstance(ambiguities_raw, list) else []

        return AIContextAnalysisResult(
            incident_summary=str(parsed_json.get("incident_summary", "Security transfer analysis completed.")),
            relevant_risk_factors=risk_factors,
            policy_rationales=filtered_rationales,
            ambiguities_and_uncertainty=ambiguities,
            remediation_recommendations=validated_recs,
            human_review_recommended=bool(parsed_json.get("human_review_recommended", False)),
            ai_status="SUCCESS",
            model_identifier=self._model,
            is_ai_assisted=True,
            usage=usage,
            disclaimer="AI-assisted explanation. Deterministic policies and risk scores remain authoritative.",
        )


# Global default AI analysis service instance
ai_analysis_service = GeminiContextAnalysisService()
