"""
Security module for input validation and target sanitization
"""

import re
import ipaddress
from typing import Optional
from urllib.parse import urlparse
from app.core.config import settings


class SecurityValidator:
    """Validates and sanitizes user inputs for security"""
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Validate if string is a valid domain name"""
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        return bool(domain_pattern.match(domain))
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Validate if string is a valid URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc]) and result.scheme in settings.ALLOWED_SCHEMES
        except Exception:
            return False
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP address is private or reserved"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        except ValueError:
            return False
    
    @staticmethod
    def extract_host_from_url(url: str) -> Optional[str]:
        """Extract hostname from URL"""
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                return parsed.netloc.split(':')[0]  # Remove port if present
            return None
        except Exception:
            return None
    
    @staticmethod
    def is_blocked_target(target: str) -> bool:
        """Check if target is blocked (localhost, private IPs, etc.)"""
        target_lower = target.lower()
        
        # Check blocked keywords
        if any(blocked in target_lower for blocked in settings.BLOCKED_IPS):
            return True
        
        # Extract hostname if URL
        if target.startswith(('http://', 'https://')):
            host = SecurityValidator.extract_host_from_url(target)
            if not host:
                return True
            target = host
        
        # Try to resolve as IP
        try:
            if SecurityValidator.is_private_ip(target):
                return True
        except Exception:
            pass
        
        return False
    
    @staticmethod
    def sanitize_target(target: str) -> str:
        """Sanitize and validate target input"""
        # Remove whitespace
        target = target.strip()
        
        # Check if blocked
        if SecurityValidator.is_blocked_target(target):
            raise ValueError("Target is blocked: localhost, private IPs, or reserved ranges are not allowed")
        
        # Validate format
        is_url = target.startswith(('http://', 'https://'))
        if is_url:
            if not SecurityValidator.is_valid_url(target):
                raise ValueError("Invalid URL format")
        else:
            if not SecurityValidator.is_valid_domain(target):
                raise ValueError("Invalid domain format")
        
        return target
    
    @staticmethod
    def sanitize_argument(arg: str) -> str:
        """Sanitize command-line argument to prevent injection"""
        # Remove dangerous characters
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
        for char in dangerous_chars:
            if char in arg:
                raise ValueError(f"Argument contains dangerous character: {char}")
        
        return arg.strip()
    
    @staticmethod
    def validate_port_range(ports: str) -> bool:
        """Validate port range specification"""
        # Allow common patterns: 80, 80-443, 1-1000, top-100, top-1000
        if ports in ['top-100', 'top-1000', 'all']:
            return True
        
        # Single port
        if ports.isdigit():
            port = int(ports)
            return 1 <= port <= 65535
        
        # Port range
        if '-' in ports:
            try:
                start, end = ports.split('-')
                start_port = int(start)
                end_port = int(end)
                return (1 <= start_port <= 65535 and 
                       1 <= end_port <= 65535 and 
                       start_port <= end_port)
            except ValueError:
                return False
        
        # Comma-separated ports
        if ',' in ports:
            port_list = ports.split(',')
            for port in port_list:
                if not port.isdigit():
                    return False
                if not (1 <= int(port) <= 65535):
                    return False
            return True
        
        return False
