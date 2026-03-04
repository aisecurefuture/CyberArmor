"""
CyberArmor.ai Protect - SIEM Output Base Class

Abstract base class that all SIEM output adapters must implement.
"""

from __future__ import annotations

import abc
import logging
from typing import Any

logger = logging.getLogger("siem-connector.outputs")


class SIEMOutput(abc.ABC):
    """Base class for all SIEM output destinations."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate that required configuration keys are present.

        Subclasses should override this to enforce required fields.
        """

    @abc.abstractmethod
    async def send_event(self, event: dict[str, Any]) -> None:
        """Send a single normalized event to the SIEM destination.

        Args:
            event: A normalized event dictionary conforming to the common schema.

        Raises:
            ConnectionError: If the destination is unreachable.
            ValueError: If the event cannot be serialized for the destination.
        """

    async def send_batch(self, events: list[dict[str, Any]]) -> None:
        """Send a batch of normalized events.

        The default implementation sends events one at a time. Subclasses
        should override this for destinations that support native batching.

        Args:
            events: List of normalized event dictionaries.
        """
        for event in events:
            await self.send_event(event)

    @abc.abstractmethod
    async def test_connection(self) -> bool:
        """Test connectivity to the SIEM destination.

        Returns:
            True if the destination is reachable and credentials are valid.
        """

    @classmethod
    @abc.abstractmethod
    def get_config_schema(cls) -> dict[str, Any]:
        """Return a JSON-Schema-like description of the required configuration.

        Returns:
            Dictionary describing required and optional configuration fields.
        """

    @property
    def name(self) -> str:
        return self.__class__.__name__

    def _require_config(self, *keys: str) -> None:
        """Raise ValueError if any of the given keys are missing from config."""
        missing = [k for k in keys if not self._config.get(k)]
        if missing:
            raise ValueError(
                f"{self.name} requires configuration keys: {', '.join(missing)}"
            )
