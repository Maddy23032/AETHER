"""Web crawler for endpoint discovery."""

import asyncio
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse, parse_qs

from bs4 import BeautifulSoup
import structlog

from app.models.scan import DiscoveredEndpoint, ScanConfig
from app.services.http_client import HttpClient

logger = structlog.get_logger()


class Crawler:
    """Async web crawler for discovering endpoints and forms."""

    def __init__(
        self,
        base_url: str,
        config: ScanConfig,
        http_client: HttpClient,
        on_endpoint_found: callable = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc
        self.config = config
        self.http_client = http_client
        self.on_endpoint_found = on_endpoint_found
        
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: List[DiscoveredEndpoint] = []
        self.max_urls = 100  # Configurable limit

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the same domain."""
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ""

    def _normalize_url(self, url: str) -> str:
        """Normalize URL by removing fragments and normalizing path."""
        parsed = urlparse(url)
        # Remove fragment, keep query params
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized

    def _extract_links(self, html: str, current_url: str) -> List[str]:
        """Extract all links from HTML content."""
        soup = BeautifulSoup(html, "lxml")
        links = []
        
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"]
            
            # Skip javascript, mailto, tel links
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            
            # Resolve relative URLs
            full_url = urljoin(current_url, href)
            
            # Only include same-domain links
            if self._is_same_domain(full_url):
                links.append(self._normalize_url(full_url))
        
        return links

    def _extract_forms(self, html: str, current_url: str) -> List[Dict[str, Any]]:
        """Extract form information from HTML."""
        soup = BeautifulSoup(html, "lxml")
        forms = []
        
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            
            # Resolve form action URL
            form_url = urljoin(current_url, action) if action else current_url
            
            # Extract form inputs
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                input_name = inp.get("name")
                if input_name:
                    inputs.append({
                        "name": input_name,
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
            
            forms.append({
                "action": form_url,
                "method": method,
                "inputs": inputs,
            })
        
        return forms

    def _extract_parameters(self, url: str) -> List[str]:
        """Extract query parameters from URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())

    def _extract_api_endpoints(self, html: str) -> List[str]:
        """Extract potential API endpoints from JavaScript code."""
        soup = BeautifulSoup(html, "lxml")
        endpoints = []
        
        # Common API patterns to look for
        api_patterns = [
            r'/api/',
            r'/v1/',
            r'/v2/',
            r'/graphql',
            r'/rest/',
        ]
        
        # Search in script tags
        for script in soup.find_all("script"):
            if script.string:
                # Look for fetch/axios calls, URL patterns
                content = script.string
                for pattern in api_patterns:
                    if pattern in content:
                        # Extract URLs containing the pattern
                        # This is a simplified extraction
                        start = content.find(pattern)
                        if start != -1:
                            # Find the surrounding quotes
                            for quote in ['"', "'"]:
                                quote_start = content.rfind(quote, 0, start)
                                quote_end = content.find(quote, start)
                                if quote_start != -1 and quote_end != -1:
                                    endpoint = content[quote_start + 1:quote_end]
                                    if endpoint.startswith("/"):
                                        endpoints.append(endpoint)
                                    break
        
        return list(set(endpoints))

    async def crawl(self) -> List[DiscoveredEndpoint]:
        """
        Crawl the target starting from base_url.
        
        Returns list of discovered endpoints.
        """
        queue = [self.base_url]
        depth_map = {self.base_url: 0}
        
        logger.info("Starting crawl", base_url=self.base_url, max_depth=self.config.max_depth)
        
        while queue and len(self.visited_urls) < self.max_urls:
            current_url = queue.pop(0)
            current_depth = depth_map.get(current_url, 0)
            
            if current_url in self.visited_urls:
                continue
            
            if current_depth > self.config.max_depth:
                continue
            
            self.visited_urls.add(current_url)
            
            try:
                response = await self.http_client.get(current_url)
                
                # Skip non-HTML responses
                content_type = response.headers.get("content-type", "")
                if "text/html" not in content_type:
                    continue
                
                html = response.text
                
                # Create endpoint record
                endpoint = DiscoveredEndpoint(
                    url=current_url,
                    method="GET",
                    parameters=self._extract_parameters(current_url),
                    forms=self._extract_forms(html, current_url),
                )
                self.discovered_endpoints.append(endpoint)
                
                # Notify callback if provided
                if self.on_endpoint_found:
                    await self.on_endpoint_found(endpoint)
                
                # Extract and queue new links
                if self.config.deep_crawl:
                    links = self._extract_links(html, current_url)
                    for link in links:
                        if link not in self.visited_urls and link not in queue:
                            queue.append(link)
                            depth_map[link] = current_depth + 1
                
                # Extract API endpoints if enabled
                if self.config.api_discovery:
                    api_endpoints = self._extract_api_endpoints(html)
                    for api_ep in api_endpoints:
                        full_api_url = urljoin(self.base_url, api_ep)
                        if full_api_url not in self.visited_urls:
                            queue.append(full_api_url)
                            depth_map[full_api_url] = current_depth + 1
                
                logger.debug(
                    "Page crawled",
                    url=current_url,
                    depth=current_depth,
                    links_found=len(self._extract_links(html, current_url)),
                )
                
            except Exception as e:
                logger.warning("Failed to crawl URL", url=current_url, error=str(e))
                continue
        
        logger.info(
            "Crawl completed",
            total_urls=len(self.visited_urls),
            endpoints=len(self.discovered_endpoints),
        )
        
        return self.discovered_endpoints
