from __future__ import annotations

from typing import Any, Dict

from .base import ProviderConnector


class OpenAICompatibleConnector(ProviderConnector):
    provider_id = "openai-compatible"

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def chat_completions(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self._post("/chat/completions", payload, self._headers())

    async def completions(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self._post("/completions", payload, self._headers())

    async def embeddings(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self._post("/embeddings", payload, self._headers())

    async def images_generate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self._post("/images/generations", payload, self._headers())
