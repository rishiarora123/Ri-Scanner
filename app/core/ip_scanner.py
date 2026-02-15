"""
IP-Specific Deep Reconnaissance
Comprehensive scanning of a single IP address with full intelligence gathering
"""

import asyncio
import socket
import subprocess
import shlex
import dns.resolver
import ssl
import httpx
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import json

class IPScanner:
    """Deep reconnaissance on a single IP address"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
    
    async def scan_ip(self, ip: str, ports: str = None) -> Dict[str, Any]:
        """
        Comprehensive scan of a single IP address
        
        Args:
            ip: IP address to scan
            ports: Comma-separated ports to scan (e.g., "80,443,8443")
        
        Returns:
        {
            "ip": "1.2.3.4",
            "basic_info": {...},
            "reverse_dns": {...},
            "asn_info": {...},
            "open_ports": [...],
            "ssl_certificates": [...],
            "http_services": [...],
            "dns_records": {...},
            "geolocation": {...},
            "associated_domains": [...],
            "technology_stack": {...},
            "cdn_waf": {...},
            "threat_intelligence": {...},
            "scan_timestamp": "ISO8601"
        }
        """
        
        tasks = [
            self._get_reverse_dns(ip),
            self._get_asn_info(ip),
            self._scan_ports(ip, ports),
            self._get_ssl_certificates(ip, ports),
            self._get_http_headers(ip, ports),
            self._get_geolocation(ip),
            self._find_associated_domains(ip),
            self._detect_cdn_waf(ip),
            self._get_threat_intelligence(ip),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            "ip": ip,
            "ports_scanned": ports or "default",
            "basic_info": {
                "ip_address": ip,
                "is_private": self._is_private_ip(ip),
                "is_reserved": self._is_reserved_ip(ip),
                "scan_timestamp": datetime.now().isoformat()
            },
            "reverse_dns": results[0] or {},
            "asn_info": results[1] or {},
            "open_ports": results[2] or [],
            "ssl_certificates": results[3] or [],
            "http_services": results[4] or [],
            "geolocation": results[5] or {},
            "associated_domains": results[6] or [],
            "cdn_waf_detection": results[7] or {},
            "threat_intelligence": results[8] or {},
            "scan_summary": {
                "open_ports_count": len(results[2] or []),
                "ssl_certs_count": len(results[3] or []),
                "http_services_count": len(results[4] or []),
                "associated_domains_count": len(results[6] or []),
                "potential_threats": self._calculate_threat_score(results[8] or {})
            }
        }
    
    async def _get_reverse_dns(self, ip: str) -> Dict[str, Any]:
        """Get reverse DNS (PTR) records and associated domains"""
        try:
            loop = asyncio.get_event_loop()
            hostname = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            return {
                "status": "success",
                "hostname": hostname[0],
                "aliases": hostname[1],
                "addresses": hostname[2]
            }
        except socket.herror:
            return {
                "status": "not_found",
                "hostname": None,
                "aliases": []
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def _get_asn_info(self, ip: str) -> Dict[str, Any]:
        """Get ASN, ISP, organization information"""
        try:
            # Query using whois command
            result = await asyncio.create_subprocess_exec(
                "whois", ip,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            output = stdout.decode('utf-8', errors='ignore')
            
            # Parse WHOIS output
            asn_info = {
                "status": "success",
                "asn": None,
                "isp": None,
                "organization": None,
                "country": None,
                "network_prefix": None,
                "whois_server": None
            }
            
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith('ASN:') or line.startswith('OriginAS:'):
                    asn_info["asn"] = line.split()[-1]
                elif line.startswith('ISP:') or line.startswith('OrgName:'):
                    asn_info["isp"] = line.split(':', 1)[-1].strip()
                elif line.startswith('Organization:') or line.startswith('Org:'):
                    asn_info["organization"] = line.split(':', 1)[-1].strip()
                elif line.startswith('Country:'):
                    asn_info["country"] = line.split()[-1]
                elif line.startswith('CIDR:') or line.startswith('route:'):
                    asn_info["network_prefix"] = line.split()[-1]
                elif line.startswith('WhoisServer:'):
                    asn_info["whois_server"] = line.split()[-1]
            
            return asn_info
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def _scan_ports(self, ip: str, ports: str = None) -> List[Dict[str, Any]]:
        """Scan common ports or custom ports using netcat (nc)"""
        open_ports = []
        
        # Use custom ports if provided, otherwise use common ports
        if ports and ports.strip():
            try:
                port_list_str = ports.split(',')
                port_list = [int(p.strip()) for p in port_list_str if p.strip().isdigit()]
            except:
                port_list = [80, 443]
        else:
            port_list = [20, 21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5984, 6379, 7001, 8000, 8008, 8080, 8443, 8888, 9000, 9200, 9300, 11211, 27017, 27018, 50070]
        
        # Common port to service map for 'nc' since it doesn't give service info
        common_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 
            110: "pop3", 143: "imap", 443: "https", 445: "microsoft-ds", 3306: "mysql", 
            3389: "ms-wbt-server", 5432: "postgresql", 6379: "redis", 8080: "http-proxy", 
            27017: "mongod"
        }
        
        async def check_port(port):
            try:
                # nc -z -n -w 1 -> zero-I/O, no-dns, wait 1 sec
                cmd = ["nc", "-z", "-n", "-w", "1", ip, str(port)]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                import sys
                if process.returncode == 0:
                    print(f"[DEBUG] Port {port} is OPEN on {ip}", file=sys.stderr)
                    return {
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": common_services.get(port, "unknown")
                    }
                else:
                    err_msg = stderr.decode().strip()
                    print(f"[DEBUG] Port {port} CLOSED. Code: {process.returncode}. Stderr: {err_msg}", file=sys.stderr)
                    pass
            except Exception as e:
                import sys
                print(f"[ERROR] Port scan failed for {port}: {e}", file=sys.stderr)
                pass
            return None

        # Run checks concurrently with a semaphore
        # Reduced to 20 to avoid system limit issues
        sem = asyncio.Semaphore(20)
        
        async def bound_check(port):
            async with sem:
                return await check_port(port)
        
        import sys
        print(f"[DEBUG] Scanning {len(port_list)} ports for {ip} with nc...", file=sys.stderr)
        tasks = [bound_check(p) for p in port_list]
        results = await asyncio.gather(*tasks)
        
        open_ports = [r for r in results if r is not None]
        print(f"[DEBUG] Found {len(open_ports)} open ports: {[p['port'] for p in open_ports]}", file=sys.stderr)
        return open_ports
    
    async def _get_ssl_certificates(self, ip: str, ports: str = None) -> List[Dict[str, Any]]:
        """Extract SSL/TLS certificates from HTTPS ports"""
        certificates = []
        
        # Determine ports to check
        if ports and ports.strip():
            try:
                ports_to_check = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
            except:
                ports_to_check = [443, 8443, 9443]
        else:
            ports_to_check = [443, 8443, 9443]
        
        import sys
        
        for port in ports_to_check:
            try:
                # Use openssl s_client to fetch certificate (more reliable for CN extraction)
                # timeout 5s
                print(f"[DEBUG] SSL Scanning {ip}:{port}...", file=sys.stderr)
                cmd = f"openssl s_client -connect {ip}:{port} -servername {ip} -showcerts < /dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates"
                
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
                except asyncio.TimeoutError:
                    print(f"[ERROR] SSL scan timeout for {ip}:{port}", file=sys.stderr)
                    try:
                        process.kill()
                    except:
                        pass
                    continue
                
                if process.returncode != 0:
                    print(f"[DEBUG] SSL scan failed for {ip}:{port} (code {process.returncode})", file=sys.stderr)
                    continue

                output = stdout.decode('utf-8', errors='ignore')
                print(f"[DEBUG] SSL Output for {ip}:{port}: {output[:50]}...", file=sys.stderr)
                
                if not output.strip():
                     continue

                cert_info = {"port": port}
                
                # Parse openssl output
                # subject=CN = dns.google
                # issuer=C = US, O = Google Trust Services LLC, CN = GTS 8ec1
                # notBefore=Feb 10 08:18:10 2025 GMT
                # notAfter=Apr 21 08:33:09 2025 GMT
                
                for line in output.split('\n'):
                    line = line.strip()
                    if line.startswith("subject="):
                        # Extract CN from subject
                        # subject=CN = dns.google OR subject=C = US, ST = California, L = Mountain View, O = Google LLC, CN = dns.google
                        cert_info["subject"] = line[8:]
                        # Regex to find CN
                        import re
                        cn_match = re.search(r"CN\s*=\s*([^/,]+)", line)
                        if cn_match:
                            cert_info["common_name"] = cn_match.group(1).strip()
                    
                    elif line.startswith("issuer="):
                        cert_info["issuer"] = line[7:]
                    elif line.startswith("notBefore="):
                        cert_info["notBefore"] = line[10:]
                    elif line.startswith("notAfter="):
                        cert_info["notAfter"] = line[9:]
                
                if cert_info.get("common_name") or cert_info.get("subject"):
                    certificates.append(cert_info)
                    
            except Exception as e:
                print(f"[ERROR] SSL scan error for {ip}:{port}: {e}", file=sys.stderr)
                pass
        
        return certificates
    
    async def _get_http_headers(self, ip: str, ports: str = None) -> List[Dict[str, Any]]:
        """Get HTTP headers from running services"""
        services = []
        
        # Determine ports to check
        if ports and ports.strip():
            custom_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
            ports_to_check = []
            for p in custom_list:
                # Basic heuristic: 443, 8443, 9443 etc. are usually https
                scheme = "https" if str(p).endswith("443") else "http"
                ports_to_check.append((p, scheme))
        else:
            ports_to_check = [
                (80, "http"),
                (443, "https"),
                (8000, "http"),
                (8080, "http"),
                (8443, "https"),
                (8888, "http"),
                (9000, "http")
            ]
        
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for port, scheme in ports_to_check:
                try:
                    url = f"{scheme}://{ip}:{port}"
                    resp = await client.get(url, follow_redirects=False)
                    
                    headers = dict(resp.headers)
                    
                    services.append({
                        "port": port,
                        "scheme": scheme,
                        "status_code": resp.status_code,
                        "server": headers.get('server', 'Unknown'),
                        "content_type": headers.get('content-type', 'Unknown'),
                        "powered_by": headers.get('x-powered-by', None),
                        "aspnet_version": headers.get('x-aspnet-version', None),
                        "headers": headers,
                        "title": self._extract_title(resp.text)
                    })
                except Exception as e:
                    pass
        
        return services
    
    def _extract_title(self, html: str) -> Optional[str]:
        """Extract title from HTML content"""
        import re
        match = re.search(r'<title>(.+?)</title>', html, re.IGNORECASE)
        return match.group(1) if match else None
    
    async def _get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation data for IP"""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"https://ipapi.co/{ip}/json/", verify=False)
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "country": data.get('country_name'),
                        "country_code": data.get('country_code'),
                        "region": data.get('region'),
                        "city": data.get('city'),
                        "latitude": data.get('latitude'),
                        "longitude": data.get('longitude'),
                        "timezone": data.get('timezone'),
                        "org": data.get('org'),
                        "isp": data.get('isp')
                    }
        except Exception as e:
            pass
        
        return {}
    
    async def _find_associated_domains(self, ip: str) -> List[Dict[str, Any]]:
        """Find domains associated with this IP"""
        domains = []
        
        try:
            # Try reverse DNS lookup
            loop = asyncio.get_event_loop()
            
            try:
                result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
                hostname = result[0]
                domains.append({
                    "domain": hostname,
                    "source": "reverse_dns",
                    "confidence": "high"
                })
            except:
                pass
            
            # Query DNS PTR record
            try:
                reversed_ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
                answers = self.resolver.resolve(reversed_ip, 'PTR')
                for rr in answers:
                    domains.append({
                        "domain": str(rr).rstrip('.'),
                        "source": "ptr_record",
                        "confidence": "high"
                    })
            except:
                pass
        
        except Exception as e:
            pass
        
        return domains
    
    async def _detect_cdn_waf(self, ip: str) -> Dict[str, Any]:
        """Detect CDN and WAF providers"""
        cdn_waf = {
            "cdn": None,
            "waf": None,
            "indicators": []
        }
        
        # Common CDN/WAF IP ranges and signatures
        cdn_signatures = {
            "cloudflare": ["104.16.0.0/12", "173.245.48.0/20", "103.21.244.0/22"],
            "akamai": ["1.2.3.0/24"],  # Simplified
            "cloudfront": ["54.230.0.0/16"],
            "fastly": ["23.235.32.0/20"],
            "aws_shield": ["52.0.0.0/8"],
        }
        
        # Check HTTP headers from services
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                resp = await client.get(f"https://{ip}", follow_redirects=False)
                headers = dict(resp.headers)
                
                if 'cf-ray' in headers or 'cf-cache-status' in headers:
                    cdn_waf["cdn"] = "Cloudflare"
                    cdn_waf["indicators"].append("cf-ray header")
                
                if 'x-amzn-waf' in headers:
                    cdn_waf["waf"] = "AWS WAF"
                    cdn_waf["indicators"].append("x-amzn-waf header")
                
                if 'x-mod-security' in headers or 'modsecurity' in str(headers):
                    cdn_waf["waf"] = "ModSecurity"
                    cdn_waf["indicators"].append("modsecurity header")
        except:
            pass
        
        return cdn_waf
    
    async def _get_threat_intelligence(self, ip: str) -> Dict[str, Any]:
        """Gather threat intelligence on IP"""
        threat_info = {
            "reputation": "unknown",
            "threat_level": "low",
            "known_malware": False,
            "botnet_activity": False,
            "spam_reports": 0,
            "abuse_reports": 0,
            "sources": []
        }
        
        # This would integrate with threat feeds like:
        # - AbuseIPDB
        # - AlienVault OTX
        # - VirusTotal
        # - Shodan
        # For now, return placeholder
        
        return threat_info
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            import ipaddress
            return ipaddress.ip_address(ip).is_private
        except:
            return False
    
    def _is_reserved_ip(self, ip: str) -> bool:
        """Check if IP is reserved"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_reserved or ip_obj.is_loopback or ip_obj.is_multicast
        except:
            return False
    
    def _calculate_threat_score(self, threat_info: Dict[str, Any]) -> int:
        """Calculate threat score 0-100"""
        score = 0
        
        if threat_info.get("known_malware"):
            score += 50
        if threat_info.get("botnet_activity"):
            score += 30
        
        spam_reports = threat_info.get("spam_reports", 0)
        abuse_reports = threat_info.get("abuse_reports", 0)
        
        score += min(spam_reports * 2, 20)
        score += min(abuse_reports * 3, 20)
        
        return min(score, 100)
