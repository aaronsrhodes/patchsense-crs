"""MLX local model backend via mlx_lm.server (OpenAI-compatible API).

Talks to a locally running mlx_lm.server (default: http://localhost:8080).
No API key required. All data stays on-device.

Start the server:
    python3 -m mlx_lm server \
        --model mlx-community/Qwen2.5-Coder-32B-Instruct-4bit \
        --adapter-path models/patchsense-lora \
        --port 8080

Usage:
    backend = MLXBackend()
    result = backend.complete(system="...", user="...")
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from patchsense.backends.base import LLMBackend


class MLXBackend(LLMBackend):
    """Local MLX backend via mlx_lm.server's OpenAI-compatible API."""

    def __init__(
        self,
        model: str = "patchsense-qwen",
        host: str = "http://localhost:8080",
    ):
        self._display_name = model
        self._host = host.rstrip("/")
        self._model = self._resolve_model_id()

    def _resolve_model_id(self) -> str:
        """Get the actual model ID from the server (may differ from display name)."""
        try:
            with urllib.request.urlopen(f"{self._host}/v1/models", timeout=5) as resp:
                data = json.loads(resp.read())
                models = data.get("data", [])
                if models:
                    return models[0]["id"]
        except Exception:
            pass
        return self._display_name

    @property
    def name(self) -> str:
        return f"mlx:{self._display_name}"

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        """Call /v1/chat/completions with system+user messages and return response text."""
        payload = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.1,
            "top_p": 0.9,
        }).encode()

        req = urllib.request.Request(
            f"{self._host}/v1/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = json.loads(resp.read())
                return data["choices"][0]["message"]["content"].strip()
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"MLX server request failed — is `mlx_lm.server` running? Error: {e}"
            ) from e

    def _verify_running(self) -> None:
        """Confirm mlx_lm.server is reachable."""
        try:
            with urllib.request.urlopen(f"{self._host}/v1/models", timeout=5) as resp:
                json.loads(resp.read())
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"Cannot reach MLX server at {self._host}. "
                f"Start with: python3 -m mlx_lm server "
                f"--model mlx-community/Qwen2.5-Coder-32B-Instruct-4bit "
                f"--adapter-path models/patchsense-lora --port 8080\n"
                f"Error: {e}"
            ) from e
