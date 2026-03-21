from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Tuple

from schemas import IntegrationConnection, IntegrationEvent, IntegrationFinding, IntegrationPermission


class IntegrationConnector(ABC):
    provider_id: str

    @abstractmethod
    async def discover(self, tenant_id: str, include_events: bool = False) -> Tuple[
        List[IntegrationConnection],
        List[IntegrationPermission],
        List[IntegrationEvent],
        List[IntegrationFinding],
    ]:
        raise NotImplementedError

    @abstractmethod
    async def revoke_consent(self, tenant_id: str, permission_external_id: str, dry_run: bool = True) -> dict:
        raise NotImplementedError

    @abstractmethod
    async def disable_connection(self, tenant_id: str, connection_external_id: str, dry_run: bool = True) -> dict:
        raise NotImplementedError

