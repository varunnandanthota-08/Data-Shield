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
            )

        # 2. Privacy verification: Ensure input is safely masked before sending
        if not verify_sanitization(sanitized_text, findings):
            return generate_deterministic_explanation(
                findings=findings,
                context=context,
                policy_result=policy_result,
                risk_result=risk_result,
                failure_reason="Sanitization verification failed: input could not be verified safe for model egress",
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
            )

        if not client:
            return generate_deterministic_explanation(
                findings=findings,
                context=context,
                policy_result=policy_result,
                risk_result=risk_result,
                failure_reason="GenAI client unavailable",
            )

        # 4. Invoke model with bounded retries for transient failures
        last_error = ""
        from google.genai import types

        config = types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.1,  # Low temperature for deterministic security consistency
        )

        for attempt in range(self._max_retries + 1):
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

                # Validate against strict Pydantic response schema
                result = self._validate_and_normalize_response(
                    parsed_json=parsed_json,
                    triggered_ids=triggered_ids,
                    findings=findings,
                    policy_result=policy_result,
                    risk_result=risk_result,
                )
                return result

            except json.JSONDecodeError as json_err:
                last_error = f"Model returned invalid JSON: {json_err}"
                break  # Non-transient format error; do not retry

            except ValidationError as val_err:
                last_error = f"Model response failed schema validation: {val_err}"
                break  # Non-transient schema error; do not retry

            except Exception as exc:
                err_str = str(exc)
                last_error = f"Provider invocation error: {err_str}"
                # Check for rate limit or transient network error
                is_transient = any(
                    transient_kw in err_str.lower()
                    for transient_kw in ["429", "rate limit", "503", "unavailable", "timeout", "connection reset"]
                )
                if is_transient and attempt < self._max_retries:
                    time.sleep(0.5 * (2 ** attempt))
                    continue
                else:
                    break

        # Fallback if invocation failed or exhausted retries
        return generate_deterministic_explanation(
            findings=findings,
            context=context,
            policy_result=policy_result,
            risk_result=risk_result,
            failure_reason=last_error or "Model invocation failed",
        )

    def _validate_and_normalize_response(
        self,
        parsed_json: dict,
        triggered_ids: List[str],
        findings: List[Finding],
        policy_result: PolicyEvaluationResult,
        risk_result: RiskScoreResult,
    ) -> AIContextAnalysisResult:
        """Normalizes and validates model response to ensure it respects hard boundaries:
        - Filters out invented policy IDs not present in triggered_ids.
        - Enforces that remediation recommendations are marked advisory.
        - Prevents model from overriding authoritative decisions.
        """
        raw_rationales = parsed_json.get("policy_rationales", {})
        # Filter policy rationales to only valid triggered policy IDs
        filtered_rationales = {
            pid: rationale
            for pid, rationale in raw_rationales.items()
            if pid in triggered_ids
        }
        # If model missed explanations for any triggered policies, populate from deterministic rules
        for p in policy_result.triggered_policies:
            if p.id not in filtered_rationales:
                filtered_rationales[p.id] = f"{p.name}: {p.intent_explanation}"

        # Parse remediation recommendations
        recs_data = parsed_json.get("remediation_recommendations", [])
        validated_recs: List[RemediationRecommendation] = []
        for idx, rec_dict in enumerate(recs_data):
            try:
                # Ensure action_type is valid
                action_type_str = rec_dict.get("action_type", "")
                if action_type_str not in RemediationActionType.__members__:
                    action_type = RemediationActionType.REQUEST_HUMAN_REVIEW
                else:
                    action_type = RemediationActionType(action_type_str)

                rec = RemediationRecommendation(
                    id=rec_dict.get("id", f"REM-{idx+1:02d}"),
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

        return AIContextAnalysisResult(
            incident_summary=str(parsed_json.get("incident_summary", "Security transfer analysis completed.")),
            relevant_risk_factors=[str(rf) for rf in parsed_json.get("relevant_risk_factors", [])],
            policy_rationales=filtered_rationales,
            ambiguities_and_uncertainty=[str(a) for a in parsed_json.get("ambiguities_and_uncertainty", [])],
            remediation_recommendations=validated_recs,
            human_review_recommended=bool(parsed_json.get("human_review_recommended", False)),
            ai_status="SUCCESS",
            model_identifier=self._model,
            is_ai_assisted=True,
            disclaimer="AI-assisted explanation. Deterministic policies and risk scores remain authoritative.",
        )


# Global default AI analysis service instance
ai_analysis_service = GeminiContextAnalysisService()
