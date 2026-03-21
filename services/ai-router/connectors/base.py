from __future__ import annotations

from typing import Any, Dict, List

import httpx


class ProviderConnector:
    provider_id: str = "unknown"

    def __init__(self, base_url: str, api_key: str, config: Dict[str, Any] | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.config = config or {}

    async def chat_completions(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    async def completions(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    async def embeddings(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    async def images_generate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    async def _post(self, path: str, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(f"{self.base_url}{path}", json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def normalize_text_choices(data: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "choices" in data and isinstance(data["choices"], list):
            return data["choices"]
        output_text = data.get("output_text") or data.get("text") or ""
        return [{"message": {"role": "assistant", "content": output_text}, "finish_reason": "stop"}]
