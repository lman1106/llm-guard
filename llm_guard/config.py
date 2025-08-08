from __future__ import annotations

import os
from typing import Any, Dict

import yaml
from pydantic import BaseModel, Field


class AppConfig(BaseModel):
    name: str = "llm-guard"
    environment: str = "dev"
    system_prompt: str = (
        "You are a helpful, honest, and safe AI assistant."
    )
    allow_user_system_injection: bool = False


class ModelConfig(BaseModel):
    provider: str = "dummy"
    model_name: str = "gpt-4o-mini"
    api_key_env: str | None = None
    endpoint: str | None = None
    temperature: float = 0.2


class PromptInjectionConfig(BaseModel):
    enabled: bool = True
    keywords: list[str] = Field(default_factory=list)
    patterns: list[str] = Field(default_factory=list)
    allowed_prompt_list: list[str] = Field(default_factory=list)
    require_human_approval_on_executable_requests: bool = True


class SensitiveOutputConfig(BaseModel):
    enabled: bool = True
    mask_policy: str = "redact"
    redact_placeholder: str = "[REDACTED]"
    patterns: list[Dict[str, str]] = Field(default_factory=list)


class SystemPromptDisclosureConfig(BaseModel):
    enabled: bool = True
    similarity_threshold: float = 0.72


class ImproperOutputConfig(BaseModel):
    enabled: bool = True
    html_escape: bool = True
    sql_parameterize_required: bool = True
    high_risk_functions: list[str] = Field(default_factory=list)


class VectorEmbeddingConfig(BaseModel):
    enabled: bool = True
    min_similarity: float = 0.4
    encrypt_at_rest: bool = True
    fernet_key_env: str = "FERNET_KEY"


class FactCheckSubConfig(BaseModel):
    enabled: bool = False
    url: str | None = None
    api_key_env: str | None = None


class InaccurateInfoConfig(BaseModel):
    enabled: bool = True
    high_risk_domains: list[str] = Field(default_factory=list)
    prohibited_auto_generation: list[str] = Field(default_factory=list)
    fact_check: FactCheckSubConfig = Field(default_factory=FactCheckSubConfig)


class ResourceExhaustionConfig(BaseModel):
    enabled: bool = True
    qps_per_user: int = 2
    qpm_per_user: int = 60
    max_prompt_tokens: int = 2000
    priority_users: list[str] = Field(default_factory=list)


class RolesConfig(BaseModel):
    can_view_sensitive: bool = False


class AccessControlConfig(BaseModel):
    roles: Dict[str, RolesConfig] = Field(default_factory=dict)


class ObservabilityConfig(BaseModel):
    log_level: str = "INFO"
    siem_webhook: str | None = None


class SecurityConfig(BaseModel):
    prompt_injection: PromptInjectionConfig = Field(default_factory=PromptInjectionConfig)
    sensitive_output: SensitiveOutputConfig = Field(default_factory=SensitiveOutputConfig)
    system_prompt_disclosure: SystemPromptDisclosureConfig = Field(default_factory=SystemPromptDisclosureConfig)
    improper_output: ImproperOutputConfig = Field(default_factory=ImproperOutputConfig)
    vector_embedding: VectorEmbeddingConfig = Field(default_factory=VectorEmbeddingConfig)
    inaccurate_info: InaccurateInfoConfig = Field(default_factory=InaccurateInfoConfig)
    resource_exhaustion: ResourceExhaustionConfig = Field(default_factory=ResourceExhaustionConfig)


class Settings(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    model: ModelConfig = Field(default_factory=ModelConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    access_control: AccessControlConfig = Field(default_factory=AccessControlConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)

    def get_api_key(self) -> str | None:
        if self.model.api_key_env:
            return os.getenv(self.model.api_key_env)
        return None


def load_yaml_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_settings(config_path: str = "/workspace/config/config.yaml") -> Settings:
    data = load_yaml_config(config_path)
    return Settings.model_validate(data)