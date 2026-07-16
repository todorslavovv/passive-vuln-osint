from __future__ import annotations

from abc import ABC, abstractmethod

from ..http import HttpClient
from ..models import DiscoveryResult, TargetConfig
from ..registry import GlobalRegistry


class DiscoveryPlugin(ABC):
    name = "base"

    def __init__(self, http: HttpClient | None = None, offline: bool = False) -> None:
        self.http = http or HttpClient()
        self.offline = offline

    @abstractmethod
    def discover(self, target: TargetConfig, registry: GlobalRegistry) -> DiscoveryResult:
        raise NotImplementedError
