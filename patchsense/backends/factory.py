"""Backend factory — resolves a model string to the correct backend instance.

Model string format:  "provider:model-name"

Examples:
    "anthropic:claude-opus-4-6"      → AnthropicBackend
    "anthropic:claude-haiku-4-5"     → AnthropicBackend (cheaper)
    "ollama:qwen2.5-coder:32b"       → OllamaBackend
    "ollama:patchsense-qwen"         → OllamaBackend (fine-tuned)
    "mlx:patchsense-qwen"            → MLXBackend (direct MLX inference)
"""

from __future__ import annotations
from patchsense.backends.base import LLMBackend


def get_backend(model_str: str, api_key: str | None = None) -> LLMBackend:
    """Parse a provider:model string and return the appropriate backend."""
    if ":" not in model_str:
        raise ValueError(
            f"Invalid model string '{model_str}'. "
            "Format: 'provider:model'  e.g. 'ollama:qwen2.5-coder:32b'"
        )

    provider, _, model_name = model_str.partition(":")

    if provider == "anthropic":
        from patchsense.backends.anthropic_backend import AnthropicBackend
        return AnthropicBackend(model=model_name, api_key=api_key)

    if provider == "ollama":
        from patchsense.backends.ollama_backend import OllamaBackend
        return OllamaBackend(model=model_name)

    if provider == "mlx":
        from patchsense.backends.mlx_backend import MLXBackend
        return MLXBackend(model=model_name)

    raise ValueError(
        f"Unknown provider '{provider}'. Supported: anthropic, ollama, mlx"
    )


def default_backend(api_key: str | None = None) -> LLMBackend:
    """Return best available backend: Ollama if running, else Anthropic."""
    # Try Ollama first (local, private, free)
    try:
        from patchsense.backends.ollama_backend import OllamaBackend
        import urllib.request, json
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=2) as r:
            data = json.loads(r.read())
            models = [m["name"] for m in data.get("models", [])]
            if models:
                # Prefer code models
                preferred = ["qwen2.5-coder", "deepseek-coder", "codellama", "llama3"]
                for pref in preferred:
                    match = next((m for m in models if m.startswith(pref)), None)
                    if match:
                        return OllamaBackend(model=match)
                return OllamaBackend(model=models[0])
    except Exception:
        pass

    # Fall back to Anthropic
    from patchsense.backends.anthropic_backend import AnthropicBackend
    return AnthropicBackend(api_key=api_key)
