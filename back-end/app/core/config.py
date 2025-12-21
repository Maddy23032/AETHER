"""
Configuration settings for AETHER Reconnaissance API
"""

import os
from typing import List
from dotenv import load_dotenv

load_dotenv()

class Settings:
    """Application settings"""
    
    # Execution settings
    DEFAULT_TIMEOUT: int = int(os.getenv("DEFAULT_TIMEOUT", "180"))
    MAX_TIMEOUT: int = int(os.getenv("MAX_TIMEOUT", "300"))
    
    # Security settings
    ALLOWED_SCHEMES: List[str] = ["http", "https"]
    BLOCKED_IPS: List[str] = [
        "127.0.0.1",
        "localhost",
        "0.0.0.0"
    ]
    
    # Private IP ranges (RFC1918)
    PRIVATE_IP_RANGES: List[str] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16"  # Link-local
    ]
    
    # Tool paths (override if tools are in custom locations)
    NMAP_PATH: str = os.getenv("NMAP_PATH", "nmap")
    WHATWEB_PATH: str = os.getenv("WHATWEB_PATH", "whatweb")
    NIKTO_PATH: str = os.getenv("NIKTO_PATH", "nikto")
    DIRSEARCH_PATH: str = os.getenv("DIRSEARCH_PATH", "dirsearch")
    GOBUSTER_PATH: str = os.getenv("GOBUSTER_PATH", "gobuster")
    AMASS_PATH: str = os.getenv("AMASS_PATH", "amass")
    THEHARVESTER_PATH: str = os.getenv("THEHARVESTER_PATH", "theHarvester")
    DNSENUM_PATH: str = os.getenv("DNSENUM_PATH", "dnsenum")
    SUBFINDER_PATH: str = os.getenv("SUBFINDER_PATH", "subfinder")
    HTTPX_PATH: str = os.getenv("HTTPX_PATH", "httpx")
    
    # Wordlist paths
    WORDLIST_SMALL: str = os.getenv("WORDLIST_SMALL", "/usr/share/wordlists/dirb/common.txt")
    WORDLIST_MEDIUM: str = os.getenv("WORDLIST_MEDIUM", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
    
    # API settings
    API_PREFIX: str = "/api/recon"
    
    # CORS origins
    CORS_ORIGINS: List[str] = os.getenv("CORS_ORIGINS", "*").split(",")

settings = Settings()
