"""Ollama local model backend.

Talks to a locally running Ollama server (default: http://localhost:11434).
No API key required. All data stays on-device — suitable for confidential code.

Usage:
    backend = OllamaBackend(model="qwen2.5-coder:32b")
    result = backend.complete(system="...", user="...")
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from patchsense.backends.base import LLMBackend


class OllamaBackend(LLMBackend):
    """Local Ollama backend. Requires `ollama serve` to be running."""

    def __init__(
        self,
        model: str = "qwen2.5-coder:32b",
        host: str = "http://localhost:11434",
    ):
        self._model = model
        self._host = host.rstrip("/")
        self._verify_running()

    @property
    def name(self) -> str:
        return f"ollama:{self._model}"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        """Call /api/chat with system+user messages and return response text."""
        payload = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"num_predict": max_tokens},
        }).encode()

        req = urllib.request.Request(
            f"{self._host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = json.loads(resp.read())
                return data["message"]["content"].strip()
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"Ollama request failed — is `ollama serve` running? Error: {e}"
            ) from e

    def _verify_running(self) -> None:
        """Confirm Ollama is reachable and the requested model is available."""
        try:
            with urllib.request.urlopen(f"{self._host}/api/tags", timeout=5) as resp:
                data = json.loads(resp.read())
                available = [m["name"] for m in data.get("models", [])]

            # Normalize: "qwen2.5-coder:32b" matches "qwen2.5-coder:32b" exactly
            # but also accept prefix match (e.g. "qwen2.5-coder" matches "qwen2.5-coder:latest")
            model_base = self._model.split(":")[0]
            matched = any(
                a == self._model or a.startswith(model_base)
                for a in available
            )
            if not matched:
                raise RuntimeError(
                    f"Model '{self._model}' not found in Ollama.\n"
                    f"Available: {available}\n"
                    f"Run: ollama pull {self._model}"
                )
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"Cannot reach Ollama at {self._host}. "
                f"Run: brew services start ollama\nError: {e}"
            ) from e
