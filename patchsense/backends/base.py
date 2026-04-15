"""Abstract LLM backend interface for PatchSense.

All backends implement the same single method: complete(system, user) -> str.
This keeps the analyzers backend-agnostic — they never import anthropic or
ollama directly, only call backend.complete().
"""

from __future__ import annotations
from abc import ABC, abstractmethod


class LLMBackend(ABC):
    """Minimal interface every backend must satisfy."""

    @abstractmethod
    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        """Send a system+user prompt and return the response text."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable model identifier for logging."""
        ...
