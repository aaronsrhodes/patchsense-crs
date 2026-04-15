"""Anthropic Claude backend (cloud API)."""

from __future__ import annotations
import anthropic
from patchsense.backends.base import LLMBackend


class AnthropicBackend(LLMBackend):
    """Uses the Anthropic API. Requires ANTHROPIC_API_KEY."""

    def __init__(self, model: str = "claude-opus-4-6", api_key: str | None = None):
        self._model = model
        self._client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()

    @property
    def name(self) -> str:
        return f"anthropic:{self._model}"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text.strip()
