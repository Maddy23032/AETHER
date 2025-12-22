"""Base detector interface for all OWASP detection plugins."""

from abc import ABC, abstractmethod
from typing import List
from app.models.scan import DiscoveredEndpoint, Vulnerability
from app.services.http_client import HttpClient


class BaseDetector(ABC):
    """Abstract base class for vulnerability detectors."""

    name: str = "BaseDetector"
    description: str = "Base detection plugin"

    @abstractmethod
    async def detect(
        self,
        endpoint: DiscoveredEndpoint,
        http_client: HttpClient,
    ) -> List[Vulnerability]:
        """
        Run detection against an endpoint.
        
        Args:
            endpoint: The discovered endpoint to test
            http_client: HTTP client for making requests
            
        Returns:
            List of discovered vulnerabilities
        """
        pass
