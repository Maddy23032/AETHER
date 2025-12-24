"""
Python-based reconnaissance tools for Windows compatibility.
These implementations use Python libraries instead of CLI tools.
"""

import socket
import ssl
import dns.resolver
import requests
import concurrent.futures
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import time
import re


class PythonPortScanner:
    """Python-based port scanner (replacement for nmap)"""
    
    COMMON_PORTS = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
        993: 'imaps', 995: 'pop3s', 3306: 'mysql', 3389: 'rdp',
        5432: 'postgresql', 8080: 'http-alt', 8443: 'https-alt'
    }
    
    TOP_100_PORTS = [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
        113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
        465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990,
        993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723,
        1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389,
        3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
        5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080,
        8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154,
        49155, 49156, 49157
    ]
    
    @classmethod
    def scan_port(cls, host: str, port: int, timeout: float = 1.0) -> Optional[Dict]:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                service = cls.COMMON_PORTS.get(port, 'unknown')
                return {'port': port, 'state': 'open', 'service': service}
            return None
        except:
            return None
    
    @classmethod
    def scan(cls, target: str, ports: str = "top-100", timeout: int = 60) -> Dict[str, Any]:
        """Scan target for open ports"""
        start_time = time.time()
        
        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return {
                'error': f'Could not resolve hostname: {target}',
                'open_ports': [],
                'services': []
            }
        
        # Determine ports to scan
        if ports == "top-100":
            port_list = cls.TOP_100_PORTS
        elif ports == "top-1000":
            port_list = list(range(1, 1001))
        elif '-' in ports:
            start, end = map(int, ports.split('-'))
            port_list = list(range(start, end + 1))
        elif ',' in ports:
            port_list = [int(p.strip()) for p in ports.split(',')]
        else:
            try:
                port_list = [int(ports)]
            except:
                port_list = cls.TOP_100_PORTS
        
        # Parallel port scanning
        open_ports = []
        services = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(cls.scan_port, ip, port, 1.0): port 
                for port in port_list
            }
            
            for future in concurrent.futures.as_completed(futures, timeout=timeout):
                result = future.result()
                if result:
                    open_ports.append(result['port'])
                    services.append(result)
        
        exec_time = time.time() - start_time
        
        return {
            'host': target,
            'ip': ip,
            'open_ports': sorted(open_ports),
            'services': sorted(services, key=lambda x: x['port']),
            'scan_time': f"{exec_time:.2f}s",
            'ports_scanned': len(port_list)
        }
    
    @classmethod
    def format_output(cls, results: Dict) -> str:
        """Format results as nmap-like output"""
        if 'error' in results:
            return f"Error: {results['error']}"
        
        lines = [
            f"Python Port Scanner - Scan Report for {results['host']} ({results['ip']})",
            f"Scanned {results['ports_scanned']} ports in {results['scan_time']}",
            "",
            "PORT      STATE   SERVICE",
            "-" * 35
        ]
        
        for svc in results['services']:
            lines.append(f"{svc['port']:<9} {svc['state']:<7} {svc['service']}")
        
        if not results['services']:
            lines.append("No open ports found")
        
        return "\n".join(lines)


class PythonWebAnalyzer:
    """Python-based web technology detection (replacement for whatweb)"""
    
    TECH_PATTERNS = {
        'Apache': [r'Apache/?[\d.]*', r'Server:.*Apache'],
        'Nginx': [r'nginx/?[\d.]*', r'Server:.*nginx'],
        'IIS': [r'Microsoft-IIS/?[\d.]*', r'Server:.*IIS'],
        'PHP': [r'X-Powered-By:.*PHP/?[\d.]*', r'\.php'],
        'ASP.NET': [r'X-Powered-By:.*ASP\.NET', r'X-AspNet-Version'],
        'WordPress': [r'wp-content', r'wp-includes', r'/wp-json/'],
        'jQuery': [r'jquery[.-]?[\d.]*\.js', r'jquery\.min\.js'],
        'Bootstrap': [r'bootstrap[.-]?[\d.]*\.css', r'bootstrap\.min\.css'],
        'React': [r'react[.-]?[\d.]*\.js', r'__REACT'],
        'Angular': [r'angular[.-]?[\d.]*\.js', r'ng-app', r'ng-controller'],
        'Vue.js': [r'vue[.-]?[\d.]*\.js', r'v-bind', r'v-model'],
        'CloudFlare': [r'cloudflare', r'cf-ray'],
        'Google Analytics': [r'google-analytics\.com', r'ga\.js', r'gtag'],
        'reCAPTCHA': [r'recaptcha', r'grecaptcha'],
    }
    
    @classmethod
    def analyze(cls, target: str, timeout: int = 30) -> Dict[str, Any]:
        """Analyze web technologies"""
        start_time = time.time()
        
        # Ensure URL has scheme
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        try:
            response = requests.get(
                target, 
                timeout=timeout, 
                allow_redirects=True,
                headers={'User-Agent': 'AETHER-WebAnalyzer/1.0'}
            )
            
            technologies = []
            headers_str = str(response.headers)
            content = response.text[:50000]  # Limit content size
            combined = headers_str + content
            
            # Detect technologies
            for tech, patterns in cls.TECH_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, combined, re.IGNORECASE):
                        technologies.append(tech)
                        break
            
            # Extract additional info
            server = response.headers.get('Server', 'Unknown')
            powered_by = response.headers.get('X-Powered-By', '')
            
            # Get title
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else None
            
            exec_time = time.time() - start_time
            
            return {
                'url': response.url,
                'status_code': response.status_code,
                'title': title,
                'server': server,
                'powered_by': powered_by,
                'technologies': list(set(technologies)),
                'headers': dict(response.headers),
                'scan_time': f"{exec_time:.2f}s"
            }
            
        except requests.exceptions.RequestException as e:
            return {
                'url': target,
                'error': str(e),
                'technologies': [],
                'status_code': None
            }
    
    @classmethod
    def format_output(cls, results: Dict) -> str:
        """Format results as whatweb-like output"""
        if 'error' in results:
            return f"{results['url']} [ERROR] {results['error']}"
        
        techs = ", ".join(results['technologies']) if results['technologies'] else "None detected"
        
        lines = [
            f"URL: {results['url']}",
            f"Status: {results['status_code']}",
            f"Title: {results.get('title', 'N/A')}",
            f"Server: {results.get('server', 'N/A')}",
            f"Technologies: {techs}",
            f"Scan Time: {results['scan_time']}"
        ]
        
        return "\n".join(lines)


class PythonDNSEnumerator:
    """Python-based DNS enumeration (replacement for dnsenum)"""
    
    RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    @classmethod
    def enumerate(cls, target: str, timeout: int = 30) -> Dict[str, Any]:
        """Enumerate DNS records"""
        start_time = time.time()
        
        # Remove any URL components
        if '://' in target:
            target = urlparse(target).netloc
        target = target.split('/')[0]
        
        results = {
            'domain': target,
            'records': {},
            'nameservers': [],
            'mx_records': [],
            'ip_addresses': []
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        for record_type in cls.RECORD_TYPES:
            try:
                answers = resolver.resolve(target, record_type)
                records = [str(rdata) for rdata in answers]
                results['records'][record_type] = records
                
                if record_type == 'NS':
                    results['nameservers'] = records
                elif record_type == 'MX':
                    results['mx_records'] = records
                elif record_type in ['A', 'AAAA']:
                    results['ip_addresses'].extend(records)
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                results['records'][record_type] = []
            except Exception:
                results['records'][record_type] = []
        
        exec_time = time.time() - start_time
        results['scan_time'] = f"{exec_time:.2f}s"
        
        return results
    
    @classmethod
    def format_output(cls, results: Dict) -> str:
        """Format results as dnsenum-like output"""
        lines = [
            f"DNS Enumeration for {results['domain']}",
            "=" * 50,
            ""
        ]
        
        for record_type, records in results['records'].items():
            if records:
                lines.append(f"{record_type} Records:")
                for record in records:
                    lines.append(f"  {record}")
                lines.append("")
        
        lines.append(f"Scan completed in {results['scan_time']}")
        
        return "\n".join(lines)


class PythonSubdomainFinder:
    """Python-based subdomain enumeration (replacement for subfinder/amass)"""
    
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'dns', 'dns1', 'dns2', 'ns', 'admin', 'administrator', 'blog', 'shop',
        'dev', 'development', 'staging', 'test', 'api', 'app', 'mobile', 'm',
        'support', 'help', 'docs', 'portal', 'vpn', 'remote', 'secure', 'ssl',
        'cloud', 'cdn', 'media', 'static', 'assets', 'img', 'images', 'video',
        'email', 'mx', 'mx1', 'mx2', 'exchange', 'autodiscover', 'cpanel',
        'whm', 'plesk', 'panel', 'login', 'signin', 'sso', 'auth', 'oauth',
        'beta', 'alpha', 'demo', 'sandbox', 'preview', 'old', 'new', 'v1', 'v2'
    ]
    
    @classmethod
    def find_subdomains(cls, target: str, timeout: int = 60) -> Dict[str, Any]:
        """Find subdomains via DNS bruteforce"""
        start_time = time.time()
        
        # Clean target
        if '://' in target:
            target = urlparse(target).netloc
        target = target.split('/')[0]
        
        found_subdomains = []
        
        def check_subdomain(subdomain: str) -> Optional[str]:
            full_domain = f"{subdomain}.{target}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None
        
        # Parallel subdomain checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(check_subdomain, sub): sub 
                for sub in cls.COMMON_SUBDOMAINS
            }
            
            for future in concurrent.futures.as_completed(futures, timeout=timeout):
                result = future.result()
                if result:
                    found_subdomains.append(result)
        
        exec_time = time.time() - start_time
        
        return {
            'domain': target,
            'subdomains': sorted(found_subdomains),
            'count': len(found_subdomains),
            'scan_time': f"{exec_time:.2f}s"
        }
    
    @classmethod
    def format_output(cls, results: Dict) -> str:
        """Format results"""
        lines = [f"Subdomain Enumeration for {results['domain']}", ""]
        
        for sub in results['subdomains']:
            lines.append(sub)
        
        lines.append("")
        lines.append(f"Found {results['count']} subdomains in {results['scan_time']}")
        
        return "\n".join(lines)


class PythonHTTPProbe:
    """Python-based HTTP probing (replacement for httpx)"""
    
    @classmethod
    def probe(cls, target: str, timeout: int = 30) -> Dict[str, Any]:
        """Probe HTTP/HTTPS endpoints"""
        start_time = time.time()
        
        results = {
            'target': target,
            'probes': [],
            'live_hosts': []
        }
        
        # If target is a domain, try both HTTP and HTTPS
        if not target.startswith(('http://', 'https://')):
            urls = [f"https://{target}", f"http://{target}"]
        else:
            urls = [target]
        
        for url in urls:
            try:
                response = requests.get(
                    url, 
                    timeout=timeout,
                    allow_redirects=True,
                    headers={'User-Agent': 'AETHER-HTTPProbe/1.0'},
                    verify=False  # Allow self-signed certs
                )
                
                # Get title
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text[:10000], re.IGNORECASE)
                title = title_match.group(1).strip() if title_match else ""
                
                probe_result = {
                    'url': response.url,
                    'status_code': response.status_code,
                    'title': title[:50],
                    'server': response.headers.get('Server', ''),
                    'content_length': len(response.content),
                    'final_url': response.url
                }
                
                results['probes'].append(probe_result)
                results['live_hosts'].append(
                    f"{response.url} [{response.status_code}] [{title[:30]}]"
                )
                
            except requests.exceptions.SSLError:
                results['probes'].append({
                    'url': url,
                    'error': 'SSL Error',
                    'status_code': None
                })
            except requests.exceptions.RequestException as e:
                results['probes'].append({
                    'url': url,
                    'error': str(e)[:100],
                    'status_code': None
                })
        
        exec_time = time.time() - start_time
        results['scan_time'] = f"{exec_time:.2f}s"
        
        return results
    
    @classmethod
    def format_output(cls, results: Dict) -> str:
        """Format results"""
        lines = []
        for host in results['live_hosts']:
            lines.append(host)
        
        if not lines:
            lines.append(f"No live hosts found for {results['target']}")
        
        return "\n".join(lines)


class PythonDirectoryBuster:
    """Python-based directory brute forcing (replacement for dirsearch/gobuster)"""
    
    COMMON_PATHS = [
        '', 'admin', 'administrator', 'login', 'wp-admin', 'wp-login.php',
        'admin.php', 'administrator.php', 'phpmyadmin', 'cpanel', 'webmail',
        'dashboard', 'panel', 'controlpanel', 'manage', 'manager',
        'api', 'api/v1', 'api/v2', 'graphql', 'rest', 'swagger', 'docs',
        'robots.txt', 'sitemap.xml', '.htaccess', 'web.config', '.git',
        '.env', 'config', 'configuration', 'settings', 'setup', 'install',
        'backup', 'backups', 'db', 'database', 'sql', 'dump', 'data',
        'test', 'testing', 'dev', 'development', 'staging', 'stage',
        'uploads', 'upload', 'files', 'images', 'img', 'media', 'assets',
        'static', 'css', 'js', 'scripts', 'includes', 'inc', 'lib',
        'temp', 'tmp', 'cache', 'logs', 'log', 'debug', 'error',
        'user', 'users', 'member', 'members', 'account', 'accounts',
        'profile', 'profiles', 'register', 'signup', 'signin', 'logout'
    ]
    
    @classmethod
    def bust(cls, target: str, timeout: int = 120) -> Dict[str, Any]:
        """Brute force directories"""
        start_time = time.time()
        
        # Ensure URL has scheme
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        target = target.rstrip('/')
        
        results = {
            'target': target,
            'found_paths': [],
            'status_codes': {}
        }
        
        def check_path(path: str) -> Optional[Dict]:
            url = f"{target}/{path}"
            try:
                response = requests.get(
                    url,
                    timeout=5,
                    allow_redirects=False,
                    headers={'User-Agent': 'AETHER-DirBuster/1.0'}
                )
                
                if response.status_code not in [404]:
                    return {
                        'path': f"/{path}",
                        'status': response.status_code,
                        'size': len(response.content),
                        'redirect': response.headers.get('Location', '')
                    }
                return None
            except:
                return None
        
        # Parallel path checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(check_path, path): path 
                for path in cls.COMMON_PATHS
            }
            
            for future in concurrent.futures.as_completed(futures, timeout=timeout):
                result = future.result()
                if result:
                    results['found_paths'].append(result)
                    status = str(result['status'])
                    results['status_codes'][status] = results['status_codes'].get(status, 0) + 1
        
        exec_time = time.time() - start_time
        results['scan_time'] = f"{exec_time:.2f}s"
        results['paths_checked'] = len(cls.COMMON_PATHS)
        
        return results
    
    @classmethod
    def format_output(cls, results: Dict) -> str:
        """Format results"""
        lines = [
            f"Directory Brute Force: {results['target']}",
            f"Paths checked: {results['paths_checked']}",
            "",
            "Found paths:",
            "-" * 50
        ]
        
        for path in sorted(results['found_paths'], key=lambda x: x['path']):
            redirect = f" -> {path['redirect']}" if path.get('redirect') else ""
            lines.append(f"[{path['status']}] {path['path']} ({path['size']} bytes){redirect}")
        
        if not results['found_paths']:
            lines.append("No paths found")
        
        lines.append("")
        lines.append(f"Completed in {results['scan_time']}")
        
        return "\n".join(lines)


class PythonEmailHarvester:
    """Python-based email/info harvester (replacement for theHarvester)"""
    
    @classmethod
    def harvest(cls, target: str, timeout: int = 60) -> Dict[str, Any]:
        """Harvest emails and info from target"""
        start_time = time.time()
        
        # Clean target
        if '://' in target:
            target = urlparse(target).netloc
        target = target.split('/')[0]
        
        results = {
            'domain': target,
            'emails': [],
            'hosts': [],
            'ips': []
        }
        
        # Try to find emails on the main website
        try:
            for scheme in ['https', 'http']:
                try:
                    response = requests.get(
                        f"{scheme}://{target}",
                        timeout=timeout,
                        headers={'User-Agent': 'AETHER-Harvester/1.0'}
                    )
                    
                    # Find emails
                    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                    emails = re.findall(email_pattern, response.text)
                    results['emails'].extend([e for e in emails if target in e])
                    break
                except:
                    continue
        except:
            pass
        
        # Get DNS records for hosts/IPs
        try:
            resolver = dns.resolver.Resolver()
            
            # A records
            try:
                answers = resolver.resolve(target, 'A')
                results['ips'].extend([str(r) for r in answers])
            except:
                pass
            
            # MX records (for mail hosts)
            try:
                answers = resolver.resolve(target, 'MX')
                results['hosts'].extend([str(r.exchange).rstrip('.') for r in answers])
            except:
                pass
            
        except:
            pass
        
        # Find common subdomains as hosts
        common_subs = ['www', 'mail', 'ftp', 'webmail', 'smtp', 'pop']
        for sub in common_subs:
            try:
                socket.gethostbyname(f"{sub}.{target}")
                results['hosts'].append(f"{sub}.{target}")
            except:
                pass
        
        exec_time = time.time() - start_time
        results['scan_time'] = f"{exec_time:.2f}s"
        results['emails'] = list(set(results['emails']))
        results['hosts'] = list(set(results['hosts']))
        results['ips'] = list(set(results['ips']))
        
        return results
    
    @classmethod
    def format_output(cls, results: Dict) -> str:
        """Format results"""
        lines = [
            f"Email/Host Harvester for {results['domain']}",
            "=" * 50,
            "",
            f"Emails found ({len(results['emails'])}):"
        ]
        
        for email in results['emails']:
            lines.append(f"  {email}")
        
        lines.append(f"\nHosts found ({len(results['hosts'])}):")
        for host in results['hosts']:
            lines.append(f"  {host}")
        
        lines.append(f"\nIPs found ({len(results['ips'])}):")
        for ip in results['ips']:
            lines.append(f"  {ip}")
        
        lines.append(f"\nCompleted in {results['scan_time']}")
        
        return "\n".join(lines)


class PythonVulnScanner:
    """Python-based web vulnerability scanner (replacement for nikto)"""
    
    # Common security checks
    SECURITY_HEADERS = {
        'X-Frame-Options': 'Clickjacking protection',
        'X-Content-Type-Options': 'MIME type sniffing protection',
        'X-XSS-Protection': 'XSS filter',
        'Content-Security-Policy': 'CSP protection',
        'Strict-Transport-Security': 'HSTS enabled',
        'X-Permitted-Cross-Domain-Policies': 'Cross-domain policy',
        'Referrer-Policy': 'Referrer policy set',
        'Permissions-Policy': 'Permissions policy set',
        'Cross-Origin-Opener-Policy': 'COOP protection',
        'Cross-Origin-Resource-Policy': 'CORP protection'
    }
    
    # Sensitive paths to check
    SENSITIVE_PATHS = [
        '.git/config', '.git/HEAD', '.env', '.htaccess', '.htpasswd',
        'web.config', 'wp-config.php.bak', 'config.php.bak', 'phpinfo.php',
        'info.php', 'test.php', 'server-status', 'server-info',
        'adminer.php', 'phpmyadmin/', 'pma/', 'mysql/', 'myadmin/',
        'backup.sql', 'database.sql', 'dump.sql', 'db.sql',
        'backup.zip', 'backup.tar.gz', 'backup.tar', 'site.zip',
        '.DS_Store', 'Thumbs.db', '.svn/entries', 'CVS/Root',
        'crossdomain.xml', 'clientaccesspolicy.xml',
        'elmah.axd', 'trace.axd', 'debug/default.aspx',
        'WEB-INF/web.xml', 'META-INF/MANIFEST.MF',
        'actuator', 'actuator/health', 'actuator/env',
        'console', 'admin/console', 'jmx-console/', '_profiler/'
    ]
    
    # Common vulnerable software patterns
    VULN_PATTERNS = {
        'outdated_apache': (r'Apache/(1\.|2\.[0-3]\.)', 'Potentially outdated Apache version'),
        'outdated_nginx': (r'nginx/(0\.|1\.[0-9]\.|1\.1[0-7]\.)', 'Potentially outdated Nginx version'),
        'outdated_php': (r'PHP/(5\.|7\.[0-3]\.)', 'Potentially outdated PHP version'),
        'outdated_iis': (r'IIS/(6\.|7\.0|7\.5|8\.0)', 'Potentially outdated IIS version'),
        'server_info_leak': (r'Server:\s*[\w/]+-[\d.]+', 'Server version information disclosed'),
        'powered_by_leak': (r'X-Powered-By:', 'Technology stack disclosed via X-Powered-By'),
        'asp_net_version': (r'X-AspNet-Version:', 'ASP.NET version disclosed'),
    }
    
    @classmethod
    def scan(cls, target: str, ssl: bool = False, timeout: int = 60) -> Dict[str, Any]:
        """Perform vulnerability scan on target"""
        start_time = time.time()
        
        # Ensure URL has scheme
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}" if ssl else f"http://{target}"
        
        target = target.rstrip('/')
        
        results = {
            'target': target,
            'vulnerabilities': [],
            'missing_headers': [],
            'sensitive_files': [],
            'server_info': {},
            'ssl_info': {}
        }
        
        try:
            # Main request to get headers and content
            response = requests.get(
                target,
                timeout=timeout,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; AETHER-VulnScanner/1.0)'},
                verify=False
            )
            
            headers = response.headers
            content = response.text[:100000]
            
            # Extract server information
            results['server_info'] = {
                'server': headers.get('Server', 'Not disclosed'),
                'powered_by': headers.get('X-Powered-By', 'Not disclosed'),
                'status_code': response.status_code,
                'final_url': response.url
            }
            
            # Check for missing security headers
            for header, description in cls.SECURITY_HEADERS.items():
                if header not in headers:
                    results['missing_headers'].append({
                        'header': header,
                        'risk': 'Medium',
                        'description': f'Missing {header} - {description}'
                    })
                    results['vulnerabilities'].append({
                        'type': 'Missing Security Header',
                        'severity': 'Medium',
                        'description': f'{header} header not set',
                        'recommendation': f'Add {header} header to responses'
                    })
            
            # Check for version information disclosure
            headers_str = str(dict(headers))
            for vuln_name, (pattern, description) in cls.VULN_PATTERNS.items():
                if re.search(pattern, headers_str, re.IGNORECASE):
                    results['vulnerabilities'].append({
                        'type': 'Information Disclosure',
                        'severity': 'Low',
                        'description': description,
                        'recommendation': 'Consider hiding version information'
                    })
            
            # Check for sensitive files
            def check_sensitive_path(path: str) -> Optional[Dict]:
                try:
                    url = f"{target}/{path}"
                    resp = requests.get(
                        url,
                        timeout=5,
                        allow_redirects=False,
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    if resp.status_code in [200, 301, 302, 403]:
                        # Additional check for real content vs custom 404
                        if resp.status_code == 200 and len(resp.content) > 0:
                            return {
                                'path': path,
                                'status': resp.status_code,
                                'size': len(resp.content),
                                'risk': 'High' if any(x in path for x in ['.git', '.env', 'config', 'backup', 'sql']) else 'Medium'
                            }
                        elif resp.status_code == 403:
                            return {
                                'path': path,
                                'status': resp.status_code,
                                'size': 0,
                                'risk': 'Low'
                            }
                except:
                    pass
                return None
            
            # Parallel check for sensitive files
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(check_sensitive_path, path): path
                    for path in cls.SENSITIVE_PATHS
                }
                
                for future in concurrent.futures.as_completed(futures, timeout=timeout):
                    result = future.result()
                    if result:
                        results['sensitive_files'].append(result)
                        results['vulnerabilities'].append({
                            'type': 'Sensitive File Exposure',
                            'severity': result['risk'],
                            'description': f"Sensitive file accessible: {result['path']}",
                            'recommendation': 'Restrict access to sensitive files'
                        })
            
            # Check for common issues in content
            if '<form' in content.lower() and 'autocomplete="off"' not in content.lower():
                if 'password' in content.lower():
                    results['vulnerabilities'].append({
                        'type': 'Form Security',
                        'severity': 'Low',
                        'description': 'Password form without autocomplete="off"',
                        'recommendation': 'Add autocomplete="off" to password fields'
                    })
            
            # Check for HTTP on HTTPS page (mixed content)
            if target.startswith('https://'):
                if re.search(r'src=["\']http://', content, re.IGNORECASE):
                    results['vulnerabilities'].append({
                        'type': 'Mixed Content',
                        'severity': 'Medium',
                        'description': 'HTTP resources loaded on HTTPS page',
                        'recommendation': 'Use HTTPS for all resources'
                    })
            
            # Check SSL certificate info if HTTPS
            if target.startswith('https://'):
                try:
                    from urllib.parse import urlparse
                    hostname = urlparse(target).netloc.split(':')[0]
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, 443), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            results['ssl_info'] = {
                                'subject': dict(x[0] for x in cert.get('subject', [])),
                                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                                'expires': cert.get('notAfter', 'Unknown'),
                                'version': ssock.version()
                            }
                except Exception as e:
                    results['ssl_info'] = {'error': str(e)[:100]}
        
        except requests.exceptions.SSLError as e:
            results['vulnerabilities'].append({
                'type': 'SSL/TLS Issue',
                'severity': 'High',
                'description': f'SSL Error: {str(e)[:100]}',
                'recommendation': 'Check SSL certificate configuration'
            })
        except requests.exceptions.RequestException as e:
            results['error'] = str(e)[:200]
        
        exec_time = time.time() - start_time
        results['scan_time'] = f"{exec_time:.2f}s"
        results['checks_performed'] = len(cls.SECURITY_HEADERS) + len(cls.SENSITIVE_PATHS) + len(cls.VULN_PATTERNS)
        
        return results
    
    @classmethod
    def format_output(cls, results: Dict) -> str:
        """Format results as nikto-like output"""
        lines = [
            f"- AETHER Vulnerability Scanner v1.0",
            f"+ Target: {results['target']}",
            f"+ Start Time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "-" * 60
        ]
        
        if 'error' in results:
            lines.append(f"+ ERROR: {results['error']}")
            return "\n".join(lines)
        
        # Server info
        if results.get('server_info'):
            info = results['server_info']
            lines.append(f"+ Server: {info.get('server', 'Unknown')}")
            if info.get('powered_by') != 'Not disclosed':
                lines.append(f"+ X-Powered-By: {info.get('powered_by')}")
        
        lines.append("")
        
        # Vulnerabilities
        if results.get('vulnerabilities'):
            lines.append(f"+ VULNERABILITIES FOUND: {len(results['vulnerabilities'])}")
            for vuln in results['vulnerabilities']:
                severity = vuln.get('severity', 'Unknown')
                lines.append(f"  [{severity}] {vuln.get('description', 'Unknown issue')}")
        else:
            lines.append("+ No significant vulnerabilities found")
        
        # Sensitive files
        if results.get('sensitive_files'):
            lines.append("")
            lines.append(f"+ SENSITIVE FILES FOUND: {len(results['sensitive_files'])}")
            for f in results['sensitive_files']:
                lines.append(f"  [{f['status']}] /{f['path']} ({f['size']} bytes)")
        
        # Missing headers summary
        if results.get('missing_headers'):
            lines.append("")
            lines.append(f"+ MISSING SECURITY HEADERS: {len(results['missing_headers'])}")
            for h in results['missing_headers'][:5]:  # Show first 5
                lines.append(f"  - {h['header']}")
        
        # SSL info
        if results.get('ssl_info') and 'error' not in results.get('ssl_info', {}):
            lines.append("")
            lines.append("+ SSL Certificate Info:")
            ssl_info = results['ssl_info']
            if ssl_info.get('subject'):
                lines.append(f"  Subject: {ssl_info['subject'].get('commonName', 'Unknown')}")
            if ssl_info.get('expires'):
                lines.append(f"  Expires: {ssl_info['expires']}")
        
        lines.append("")
        lines.append("-" * 60)
        lines.append(f"+ Checks performed: {results.get('checks_performed', 0)}")
        lines.append(f"+ Scan completed in {results.get('scan_time', 'N/A')}")
        
        return "\n".join(lines)
