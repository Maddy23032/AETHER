"""
Output parsers for various reconnaissance tools
"""

import re
import json
from typing import Dict, Any, List


class OutputParser:
    """Parse tool outputs into structured data"""
    
    @staticmethod
    def parse_nmap(output: str) -> Dict[str, Any]:
        """Parse nmap output"""
        parsed = {
            "hosts": [],
            "open_ports": [],
            "services": []
        }
        
        try:
            # Extract open ports
            port_pattern = r'(\d+)/tcp\s+open\s+(\S+)'
            matches = re.findall(port_pattern, output)
            for port, service in matches:
                parsed["open_ports"].append(int(port))
                parsed["services"].append({
                    "port": int(port),
                    "service": service
                })
            
            # Extract host info
            host_pattern = r'Nmap scan report for (.+)'
            hosts = re.findall(host_pattern, output)
            parsed["hosts"] = hosts
            
        except Exception:
            pass
        
        return parsed
    
    @staticmethod
    def parse_whatweb(output: str) -> Dict[str, Any]:
        """Parse whatweb output"""
        parsed = {
            "technologies": [],
            "status_code": None,
            "title": None
        }
        
        try:
            # Extract technologies
            tech_pattern = r'\[([^\]]+)\]'
            technologies = re.findall(tech_pattern, output)
            parsed["technologies"] = technologies
            
            # Extract status code
            status_pattern = r'\[(\d{3})\s'
            status_match = re.search(status_pattern, output)
            if status_match:
                parsed["status_code"] = int(status_match.group(1))
            
            # Extract title
            title_pattern = r'Title:\[([^\]]+)\]'
            title_match = re.search(title_pattern, output)
            if title_match:
                parsed["title"] = title_match.group(1)
                
        except Exception:
            pass
        
        return parsed
    
    @staticmethod
    def parse_nikto(output: str) -> Dict[str, Any]:
        """Parse nikto output"""
        parsed = {
            "findings": [],
            "server": None,
            "vulnerabilities": 0
        }
        
        try:
            # Extract findings (lines starting with +)
            finding_pattern = r'^\+\s+(.+)$'
            findings = re.findall(finding_pattern, output, re.MULTILINE)
            parsed["findings"] = findings
            parsed["vulnerabilities"] = len(findings)
            
            # Extract server info
            server_pattern = r'Server:\s+(.+)'
            server_match = re.search(server_pattern, output)
            if server_match:
                parsed["server"] = server_match.group(1).strip()
                
        except Exception:
            pass
        
        return parsed
    
    @staticmethod
    def parse_directory_scan(output: str) -> Dict[str, Any]:
        """Parse dirsearch/gobuster output"""
        parsed = {
            "found_paths": [],
            "status_codes": {}
        }
        
        try:
            # Extract paths with status codes
            # Format: [STATUS] URL
            path_pattern = r'\[?(\d{3})\]?\s+(.+)'
            matches = re.findall(path_pattern, output)
            
            for status, path in matches:
                parsed["found_paths"].append(path.strip())
                status_code = int(status)
                if status_code not in parsed["status_codes"]:
                    parsed["status_codes"][status_code] = 0
                parsed["status_codes"][status_code] += 1
                
        except Exception:
            pass
        
        return parsed
    
    @staticmethod
    def parse_subdomain_enum(output: str) -> Dict[str, Any]:
        """Parse amass/subfinder output"""
        parsed = {
            "subdomains": [],
            "count": 0
        }
        
        try:
            # Each line typically contains one subdomain
            lines = output.strip().split('\n')
            subdomains = []
            
            for line in lines:
                line = line.strip()
                # Filter out empty lines and non-domain lines
                if line and '.' in line and not line.startswith('['):
                    subdomains.append(line)
            
            parsed["subdomains"] = list(set(subdomains))  # Remove duplicates
            parsed["count"] = len(parsed["subdomains"])
            
        except Exception:
            pass
        
        return parsed
    
    @staticmethod
    def parse_theharvester(output: str) -> Dict[str, Any]:
        """Parse theHarvester output"""
        parsed = {
            "emails": [],
            "hosts": [],
            "ips": []
        }
        
        try:
            # Extract emails
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, output)
            parsed["emails"] = list(set(emails))
            
            # Extract hosts/domains
            host_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
            hosts = re.findall(host_pattern, output.lower())
            parsed["hosts"] = list(set(hosts))
            
            # Extract IPs
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips = re.findall(ip_pattern, output)
            parsed["ips"] = list(set(ips))
            
        except Exception:
            pass
        
        return parsed
    
    @staticmethod
    def parse_dnsenum(output: str) -> Dict[str, Any]:
        """Parse dnsenum output"""
        parsed = {
            "nameservers": [],
            "mx_records": [],
            "hosts": []
        }
        
        try:
            # Extract nameservers
            ns_pattern = r'(?:NS|nameserver).*?(\S+\.\S+)'
            nameservers = re.findall(ns_pattern, output, re.IGNORECASE)
            parsed["nameservers"] = list(set(nameservers))
            
            # Extract MX records
            mx_pattern = r'(?:MX|mail).*?(\S+\.\S+)'
            mx_records = re.findall(mx_pattern, output, re.IGNORECASE)
            parsed["mx_records"] = list(set(mx_records))
            
        except Exception:
            pass
        
        return parsed
    
    @staticmethod
    def parse_httpx(output: str) -> Dict[str, Any]:
        """Parse httpx output"""
        parsed = {
            "live_hosts": [],
            "status_codes": {},
            "technologies": []
        }
        
        try:
            # Parse JSON output if available
            lines = output.strip().split('\n')
            for line in lines:
                if line.strip():
                    try:
                        # Try parsing as JSON
                        data = json.loads(line)
                        if 'url' in data:
                            parsed["live_hosts"].append(data['url'])
                        if 'status-code' in data:
                            status = data['status-code']
                            parsed["status_codes"][status] = parsed["status_codes"].get(status, 0) + 1
                    except json.JSONDecodeError:
                        # Plain text format
                        if 'http' in line.lower():
                            parsed["live_hosts"].append(line.strip())
                            
        except Exception:
            pass
        
        return parsed
