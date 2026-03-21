from __future__ import annotations

from typing import Any, Dict

from .base import ProviderConnector


class AnthropicConnector(ProviderConnector):
    provider_id = "anthropic"

    def _headers(self) -> Dict[str, str]:
        return {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

    async def chat_completions(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        messages = payload.get("messages", [])
        system = payload.get("system")
        body: Dict[str, Any] = {
            "model": payload["model"],
            "messages": [m for m in messages if m.get("role") != "system"],
            "max_tokens": payload.get("max_tokens", 1024),
        }
        if system:
            body["system"] = system
        data = await self._post("/messages", body, self._headers())
        text = ""
        content = data.get("content", [])
        if content and isinstance(content[0], dict):
            text = content[0].get("text", "")
        return {
            "id": data.get("id"),
            "model": data.get("model", payload["model"]),
            "choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": data.get("stop_reason", "stop")}],
            "usage": {
                "prompt_tokens": data.get("usage", {}).get("input_tokens", 0),
                "completion_tokens": data.get("usage", {}).get("output_tokens", 0),
            },
            "raw": data,
        }

    async def completions(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.chat_completions(payload)

    async def embeddings(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        model = payload.get("model", "unknown")
        return {
            "id": "unsupported_feature",
            "model": model,
            "provider": self.provider_id,
            "provider_message": "Anthropic does not expose a public embeddings endpoint in this connector",
            "error": {
                "code": "unsupported_provider_capability",
                "message": "Use a provider that exposes embeddings (for example: openai, google, microsoft, xai, meta, perplexity, or amazon)",
            },
            "data": [],
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
            },
            "raw": {
                "input": payload.get("input"),
                "request_model": model,
            },
        }

    async def images_generate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        model = payload.get("model", "unknown")
        return {
            "id": "unsupported_feature",
            "model": model,
            "provider": self.provider_id,
            "provider_message": "Anthropic image generation is not exposed by this connector",
            "error": {
                "code": "unsupported_provider_capability",
                "message": "Use a provider that exposes image generation (for example: openai-compatible providers)",
            },
            "data": {
                "prompt": payload.get("prompt"),
                "size": payload.get("size"),
                "n": payload.get("n", 1),
            },
            "raw": {
                "request_model": model,
            },
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
            },
        }
