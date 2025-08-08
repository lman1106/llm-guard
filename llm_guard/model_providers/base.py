from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class ModelProvider(ABC):
    @abstractmethod
    async def generate(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        raise NotImplementedError


class DummyModelProvider(ModelProvider):
    async def generate(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        return f"[DUMMY MODEL]\nSYSTEM: {system_prompt[:80]}...\nUSER: {user_prompt}"


def get_model_provider(provider: str, **kwargs: Dict[str, Any]) -> ModelProvider:
    # Placeholder for real providers based on `provider`
    # e.g., if provider == "openai": return OpenAIProvider(...)
    return DummyModelProvider()