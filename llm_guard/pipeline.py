from __future__ import annotations

from typing import Any, Dict, Optional

from llm_guard.config import Settings
from llm_guard.detectors.prompt_injection import PromptInjectionDetector
from llm_guard.detectors.sensitive_info import SensitiveInfoFilter
from llm_guard.detectors.system_prompt_leak import SystemPromptLeakDetector
from llm_guard.detectors.output_scanner import ImproperOutputScanner
from llm_guard.fact_check import FactChecker, classify_risk_domain
from llm_guard.model_providers.base import get_model_provider
from llm_guard.rate_limit import estimate_token_count


class SafetyPipeline:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

        s = settings.security
        self.prompt_detector = PromptInjectionDetector(
            keywords=s.prompt_injection.keywords,
            patterns=s.prompt_injection.patterns,
            allowed_prompt_list=s.prompt_injection.allowed_prompt_list,
            require_human_approval_on_executable_requests=s.prompt_injection.require_human_approval_on_executable_requests,
        )
        self.sensitive_filter = SensitiveInfoFilter(
            patterns=s.sensitive_output.patterns,
            mask_policy=s.sensitive_output.mask_policy,
            redact_placeholder=s.sensitive_output.redact_placeholder,
        )
        self.system_prompt_leak = SystemPromptLeakDetector(
            system_prompt=settings.app.system_prompt,
            similarity_threshold=s.system_prompt_disclosure.similarity_threshold,
        )
        self.output_scanner = ImproperOutputScanner(
            high_risk_functions=s.improper_output.high_risk_functions,
            html_escape=s.improper_output.html_escape,
        )
        self.fact_checker = FactChecker(
            url=s.inaccurate_info.fact_check.url if s.inaccurate_info.fact_check.enabled else None,
            api_key=(None),
        )
        self.model = get_model_provider(
            settings.model.provider,
            model_name=settings.model.model_name,
            api_key=settings.get_api_key(),
            endpoint=settings.model.endpoint,
        )

    def check_access(self, role: str) -> bool:
        roles = self.settings.access_control.roles
        if role not in roles:
            return False
        return True

    def role_can_view_sensitive(self, role: str) -> bool:
        role_cfg = self.settings.access_control.roles.get(role)
        return bool(role_cfg and role_cfg.can_view_sensitive)

    def violates_prohibited_autogen(self, prompt: str) -> Optional[str]:
        items = self.settings.security.inaccurate_info.prohibited_auto_generation
        lower = prompt.lower()
        for item in items:
            if item.lower() in lower:
                return item
        return None

    async def generate(self, user_id: str, role: str, prompt: str) -> Dict[str, Any]:
        if not self.check_access(role):
            return {"error": "unauthorized role"}

        # Resource exhaustion: token length check
        max_tokens = self.settings.security.resource_exhaustion.max_prompt_tokens
        if estimate_token_count(prompt) > max_tokens:
            return {"error": "prompt too long"}

        # Prohibited auto-generation enforcement (LLM09)
        violated = self.violates_prohibited_autogen(prompt)
        if violated:
            return {"error": "prohibited auto-generation", "category": violated}

        # Prompt injection detection
        inj = self.prompt_detector.analyze(prompt) if self.settings.security.prompt_injection.enabled else None
        if inj and inj.is_malicious and inj.requires_human_approval:
            return {"error": "requires human approval", "reasons": inj.reasons}

        # Generate using model
        system_prompt = self.settings.app.system_prompt
        temperature = self.settings.model.temperature
        model_output = await self.model.generate(system_prompt=system_prompt, user_prompt=prompt, temperature=temperature)

        # System prompt disclosure detection
        leak = self.system_prompt_leak.analyze(model_output) if self.settings.security.system_prompt_disclosure.enabled else None
        if leak and leak.is_leak:
            model_output = "[BLOCKED: potential system prompt disclosure detected]"

        # Sensitive info filtering (LLM02) unless role allowed
        masked_output = model_output
        sensitive_matches = []
        if self.settings.security.sensitive_output.enabled and not self.role_can_view_sensitive(role):
            masked_output, sensitive_matches = self.sensitive_filter.filter_text(model_output)
            if self.settings.security.sensitive_output.mask_policy == "block" and sensitive_matches:
                masked_output = "[BLOCKED: sensitive information detected]"

        # Improper output handling (LLM05)
        scan = self.output_scanner.scan(masked_output) if self.settings.security.improper_output.enabled else None
        if scan and scan.is_high_risk:
            masked_output = "[REVIEW REQUIRED: high-risk content detected]"

        # Inaccurate information checks (LLM09)
        risk_level = classify_risk_domain(prompt, self.settings.security.inaccurate_info.high_risk_domains)
        fact_result = None
        if self.settings.security.inaccurate_info.enabled and risk_level == "high":
            fact_result = await self.fact_checker.check(masked_output)

        return {
            "user_id": user_id,
            "role": role,
            "prompt_injection": inj.__dict__ if inj else None,
            "system_prompt_leak": leak.__dict__ if leak else None,
            "sensitive_matches": [m.__dict__ for m in sensitive_matches],
            "improper_output": scan.__dict__ if scan else None,
            "fact_check": fact_result.__dict__ if fact_result else None,
            "output": masked_output,
        }