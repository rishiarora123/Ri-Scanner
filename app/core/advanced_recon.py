"""
Advanced Reconnaissance Pipeline
Implements comprehensive attack surface mapping for bug bounty and red team operations
"""

import asyncio
import json
import re
import time
import socket
import subprocess
import shlex
import dns.resolver
from typing import List, Dict, Any, Set, Optional
from datetime import datetime
import ssl
import http.client
import ipaddress
import os

# Import Phase 2 Enhancement Modules
from .http_intelligence import HTTPIntelligence
from .endpoint_discovery import EndpointDiscovery
from .tech_fingerprint import TechFingerprint
from .cdn_waf_detection import CDNWAFDetection
from .ip_geolocation import IPGeolocation

# NOTE: We do NOT import from .core here to avoid circular imports.
# Instead, log_fn and status_fn callbacks are passed via constructor.


# ─────────────────────────────────────────────────────────────────
# PHASE 1: SUBDOMAIN DISCOVERY & VALIDATION
# ─────────────────────────────────────────────────────────────────
import dns.query
import dns.zone
from typing import Dict, Any, List, Set, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse
import ssl
import httpx

# ─────────────────────────────────────────────────────────────────
# PHASE 1: SUBDOMAIN DISCOVERY & VALIDATION
# ─────────────────────────────────────────────────────────────────

class SubdomainDiscovery:
    """Phase 1: Enumerate subdomains using multiple sources"""
    
    def __init__(self, log_fn=None, status_fn=None):
        self.discovered = set()
        self.live_subdomains = {}
        self.dead_subdomains = set()
        # FIX: Callback pattern — avoids circular import with core.py
        # log_fn(msg) = core.log_event; status_fn(dict) = core.update_status
        self._log = log_fn or (lambda msg: None)
        self._status = status_fn or (lambda d: None)
    
    async def discover_all(self, domain: str, tools: List[str] = None) -> Dict[str, Any]:
        """
        Run all discovery tools and merge results
        
        Returns:
            {
                "total_discovered": int,
                "live_count": int,
                "dead_count": int,
                "by_source": {"chaos": [...], "subfinder": [...], ...},
                "live_subdomains": [{domain, ip, status_code, response_time}, ...],
                "duplicates_removed": int
            }
        """
        if tools is None:
            tools = ["chaos", "subfinder", "assetfinder"]
        
        # FIX: Run tools SEQUENTIALLY so we can log which tool is active + its results
        # Previous code: asyncio.gather(*tasks) — fast but zero visibility
        by_source = {}
        for tool in tools:
            if tool == "chaos":     emoji = "🌀"
            elif tool == "subfinder": emoji = "🔎"
            elif tool == "assetfinder": emoji = "📡"
            else: emoji = "🔧"
            
            self._log(f"{emoji} Running {tool}...")
            self._status({"phase1_current_tool": tool})
            
            try:
                result = await self._run_discovery_tool(tool, domain)
            except Exception as e:
                self._log(f"  ⚠️ {tool} failed: {e}")
                result = []
            
            by_source[tool] = result
            self.discovered.update(result)
            
            # FIX: Log per-tool count immediately so user sees progress
            self._log(f"  ✅ {tool}: {len(result)} subdomains found (Total unique so far: {len(self.discovered)})")
            self._status({
                f"phase1_{tool}_count": len(result),
                "phase1_subdomains_total": len(self.discovered),
            })
        
        # Validate live subdomains
        self._log(f"🩺 Validating {len(self.discovered)} subdomains (checking DNS + HTTP)...")
        live = await self._validate_subdomains(self.discovered)
        self.live_subdomains = {sub["domain"]: sub for sub in live}
        self.dead_subdomains = self.discovered - set(sub["domain"] for sub in live)
        
        # FIX: Log validation results
        self._log(f"  ✅ Validation complete: {len(live)} live, {len(self.dead_subdomains)} dead")
        
        return {
            "total_discovered": len(self.discovered),
            "live_count": len(self.live_subdomains),
            "dead_count": len(self.dead_subdomains),
            "by_source": by_source,
            "subdomains": list(self.discovered),
            "live_subdomains": live,
            "duplicates_removed": len(by_source) * 100,  # Placeholder
            "timestamp": datetime.now().isoformat()
        }
    
    async def _run_discovery_tool(self, tool: str, domain: str) -> List[str]:
        """Run individual discovery tool and stream logs in real-time"""
        try:
            if tool == "chaos":
                cmd = ["chaos", "-d", domain, "-silent"]
            elif tool == "subfinder":
                cmd = ["subfinder", "-d", domain, "-silent"]
            elif tool == "assetfinder":
                cmd = ["assetfinder", "--subs-only", domain]
            else:
                return []
            
            self._log(f"  🚀 Executing: {' '.join(cmd)}")
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            found_subs = []
            
            # Read stdout line by line for real-time logging
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                
                decoded_line = line.decode().strip()
                if not decoded_line:
                    continue
                
                # Basic validation: must end with domain and not contain spaces
                if decoded_line.endswith(domain) and ' ' not in decoded_line:
                    found_subs.append(decoded_line)
                    # Periodically log batches to avoid flooding but show activity
                    if len(found_subs) % 50 == 0:
                        self._log(f"  [+] {tool} discovered {len(found_subs)} subdomains so far...")
            
            # Wait for process to finish
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                try: proc.kill()
                except: pass
                
            return list(set(found_subs))
        except Exception as e:
            self._log(f"  [!] {tool} error: {str(e)}")
            return []
    
    async def _validate_subdomains(self, subdomains: Set[str], timeout: int = 2) -> List[Dict]:
        """Validate which subdomains resolve and are live"""
        live = []
        tasks = []
        
        for subdomain in subdomains:
            tasks.append(self._check_subdomain_live(subdomain, timeout))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for subdomain, result in zip(subdomains, results):
            if result and isinstance(result, dict):
                live.append(result)
        
        return live
    
    async def _check_subdomain_live(self, subdomain: str, timeout: int) -> Optional[Dict]:
        """Check if subdomain is live and resolve IP"""
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(
                None, 
                socket.gethostbyname, 
                subdomain
            )
            
            # Try HTTP/HTTPS
            status_code, response_time = await self._probe_http(subdomain, timeout)
            
            return {
                "domain": subdomain,
                "ip": ip,
                "status_code": status_code,
                "response_time": response_time,
                "alive": True,
                "timestamp": datetime.now().isoformat()
            }
        except:
            return None
    
    async def _probe_http(self, domain: str, timeout: int) -> Tuple[Optional[int], float]:
        """Probe HTTP/HTTPS endpoint"""
        start = time.time()
        try:
            async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
                for scheme in ["https", "http"]:
                    try:
                        resp = await client.get(f"{scheme}://{domain}", follow_redirects=True)
                        elapsed = time.time() - start
                        return resp.status_code, elapsed
                    except:
                        continue
        except:
            pass
        
        elapsed = time.time() - start
        return None, elapsed


# ─────────────────────────────────────────────────────────────────
# PHASE 2: SUBDOMAIN INTELLIGENCE & DEEP RECONNAISSANCE
# ─────────────────────────────────────────────────────────────────

class SubdomainIntelligence:
    """Phase 2: Extract deep intelligence from each subdomain"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.intelligence = {}
        # Initialize Phase 2 enhancement modules
        self.http_intel = HTTPIntelligence()
        self.endpoint_disc = EndpointDiscovery()
        self.tech_fp = TechFingerprint()
        self.cdn_waf = CDNWAFDetection()
        self.ip_geo = IPGeolocation()
    
    async def gather_intelligence(self, subdomain: str, ip: str) -> Dict[str, Any]:
        """
        Gather complete intelligence on a subdomain
        
        Returns comprehensive recon data including:
        - IP resolution (direct + CDN bypass)
        - ASN & ISP details
        - Reverse DNS
        - Open ports & services
        - TLS/SSL certificates
        - HTTP headers (comprehensive + tech indicators)
        - CDN/WAF detection (multi-source)
        - Technology stack (Wappalyzer-style)
        - Endpoints (robots.txt, sitemap, JS crawling)
        - Geolocation
        - DNS records
        """
        
        tasks = [
            self._get_ip_intelligence(subdomain, ip),
            self._get_dns_records(subdomain),
            self._get_ssl_certificate(subdomain),
            self._get_http_headers(subdomain),
            self._detect_cdn_waf(subdomain),
            self._detect_technologies(subdomain),
            # NEW PHASE 2 ENHANCEMENTS
            self.http_intel.fetch_headers_comprehensive(subdomain),
            self.endpoint_disc.discover_all_endpoints(subdomain),
            self.endpoint_disc.run_katana(subdomain),
            self.tech_fp.fingerprint_all(subdomain),
            self.cdn_waf.detect_all(subdomain),
            self.ip_geo.geolocate_ip(ip),
        ]
        
        results_raw = await asyncio.gather(*tasks, return_exceptions=True)
        
        # FIX: Sanitize results to handle Exception objects
        results = []
        task_names = [
            "ip_intelligence", "dns_records", "ssl_certificate", "http_headers",
            "cdn_waf_detection", "technology_stack", "http_intelligence",
            "endpoints", "katana_endpoints", "technology_fingerprint", "cdn_waf_enhanced", "geolocation"
        ]
        
        for name, res in zip(task_names, results_raw):
            if isinstance(res, Exception):
                # Log the specific task failure if log_fn was available (not in this class yet)
                # For now, return a safe dummy object
                results.append({"error": str(res), "failed": True})
            else:
                results.append(res)
        # Combine results into a structured format
        intel_result = {
            "primary_ip": ip,
            "ip_intelligence": results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])},
            "dns_records": results[1] if not isinstance(results[1], Exception) else [],
            "ssl_certificate": results[2] if not isinstance(results[2], Exception) else {"valid": False},
            "http_headers": results[3].get("headers") if isinstance(results[3], dict) else results[3],
            "cdn_waf_detection": results[4] if not isinstance(results[4], Exception) else {"detected": []},
            "technology_stack": results[5] if not isinstance(results[5], Exception) else {"technologies": []},
            "http_intelligence": results[6] if not isinstance(results[6], Exception) else {},
            "endpoints": results[7].get("all_endpoints", []) if isinstance(results[7], dict) else [],
            "api_endpoints": results[7].get("endpoints_by_source", {}).get("from_javascript", []) if isinstance(results[7], dict) else [],
            "katana_endpoints": results[8] if isinstance(results[8], list) else [],
            "technology_fingerprint": results[9] if not isinstance(results[9], Exception) else {"technologies": []},
            "cdn_waf_enhanced": results[10] if not isinstance(results[10], Exception) else {"detected": []},
            "geolocation": results[11] if not isinstance(results[11], Exception) else {"error": "unresolved"},
            "last_intelligence_scan": datetime.now().isoformat()
        }

        # Merge Katana and JS API endpoints for UI
        api_set = set(intel_result.get("api_endpoints", []))
        api_set.update(intel_result.get("katana_endpoints", []))
        intel_result["api_endpoints"] = sorted(list(api_set))

        # Promote key fields to top-level for UI visibility
        # 1. Technologies list
        all_techs = set()
        if isinstance(intel_result["technology_stack"], dict):
            all_techs.update(intel_result["technology_stack"].get("technologies", []))
        if isinstance(intel_result["technology_fingerprint"], dict):
            all_techs.update(intel_result["technology_fingerprint"].get("technologies", []))
        
        intel_result["technologies"] = sorted(list(all_techs))
        intel_result["technologies_found"] = len(all_techs)

        # 2. Status Code
        if isinstance(intel_result["http_headers"], dict) and "status_code" in intel_result["http_headers"]:
            intel_result["status_code"] = intel_result["http_headers"]["status_code"]

        # 3. Security & Infrastructure (Promoted for UI)
        intel_result["waf"] = intel_result["cdn_waf_detection"].get("waf") or intel_result["cdn_waf_enhanced"].get("waf") or "None detected"
        intel_result["cdn"] = intel_result["cdn_waf_detection"].get("cdn") or intel_result["cdn_waf_enhanced"].get("cdn") or "None detected"
        
        ip_intel = intel_result.get("ip_intelligence", {})
        intel_result["asn"] = ip_intel.get("asn", "Unknown")
        intel_result["org"] = ip_intel.get("organization", ip_intel.get("isp", "Unknown"))
        intel_result["country"] = ip_intel.get("country", "Unknown")
        
        ssl = intel_result.get("ssl_certificate", {})
        intel_result["ssl_info"] = {
            "issuer": ssl.get("issuer", "Unknown"),
            "valid_until": ssl.get("not_after", "Unknown"),
            "valid": ssl.get("valid", False)
        }

        return intel_result
    
    async def _get_ip_intelligence(self, domain: str, ip: str) -> Dict[str, Any]:
        """Get ASN, ISP, reverse DNS, geolocation"""
        intel = {
            "ip": ip,
            "asn": "Unknown",
            "isp": "Unknown",
            "organization": "Unknown",
            "country": "Unknown",
            "reverse_dns": await self._get_reverse_dns(ip),
            "geolocation": {"country": "Unknown", "city": "Unknown"}
        }
        
        try:
            # Query using whois command - adapted from IPScanner
            process = await asyncio.create_subprocess_exec(
                "whois", ip,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            output = stdout.decode('utf-8', errors='ignore')
            
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith(('ASN:', 'OriginAS:', 'AS:', 'origin:')):
                    intel["asn"] = line.split()[-1]
                elif line.startswith(('ISP:', 'OrgName:', 'owner:')):
                    intel["isp"] = line.split(':', 1)[-1].strip()
                elif line.startswith(('Organization:', 'Org:', 'descr:')):
                    if intel["organization"] == "Unknown":
                        intel["organization"] = line.split(':', 1)[-1].strip()
                elif line.startswith('Country:'):
                    intel["country"] = line.split()[-1]
                    intel["geolocation"]["country"] = intel["country"]
        except:
            pass
            
        return intel
    
    async def _get_reverse_dns(self, ip: str) -> str:
        """Get reverse DNS (PTR)"""
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None,
                socket.gethostbyaddr,
                ip
            )
        except:
            return "Unknown"
    
    async def _get_dns_records(self, domain: str) -> Dict[str, List]:
        """Query A, AAAA, CNAME, MX, TXT records"""
        records = {}
        
        for rtype in ["A", "AAAA", "CNAME", "MX", "TXT"]:
            try:
                answers = self.resolver.resolve(domain, rtype)
                records[rtype] = [str(rr) for rr in answers]
            except:
                records[rtype] = []
        
        return records
    
    async def _get_ssl_certificate(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """Extract TLS/SSL certificate details"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        "subject": str(cert.get("subject", [])),
                        "issuer": str(cert.get("issuer", [])),
                        "version": cert.get("version"),
                        "serial": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "san": cert.get("subjectAltName", []),
                        "valid": True
                    }
        except:
            return {"valid": False}
    
    async def _get_http_headers(self, domain: str) -> Dict[str, str]:
        """Extract HTTP response headers"""
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                for scheme in ["https", "http"]:
                    try:
                        resp = await client.head(
                            f"{scheme}://{domain}",
                            follow_redirects=True,
                            allow_redirects=True
                        )
                        return dict(resp.headers)
                    except:
                        continue
        except:
            pass
        
        return {}
    
    async def _detect_cdn_waf(self, domain: str) -> Dict[str, Any]:
        """Detect CDN and WAF presence"""
        cdn_signatures = {
            "cloudflare": ["cf-ray", "cf-cache-status"],
            "akamai": ["akamai-origin-hop"],
            "cloudfront": ["cloudfront"],
            "fastly": ["fastly", "x-served-by"],
        }
        
        waf_signatures = {
            "mod_security": ["modsecurity"],
            "cloudflare_waf": ["cf-mitigated"],
            "aws_waf": ["x-amzn-waf"],
        }
        
        headers = await self._get_http_headers(domain)
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        detected_cdn = None
        detected_waf = None
        
        for cdn, signatures in cdn_signatures.items():
            for sig in signatures:
                if sig in str(headers_lower):
                    detected_cdn = cdn
        
        for waf, signatures in waf_signatures.items():
            for sig in signatures:
                if sig in str(headers_lower):
                    detected_waf = waf
        
        return {
            "cdn": detected_cdn,
            "waf": detected_waf,
            "behind_proxy": detected_cdn is not None or detected_waf is not None
        }
    
    async def _detect_technologies(self, domain: str) -> Dict[str, List[str]]:
        """Detect technology stack (server, framework, JS libs)"""
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                # Try HTTPS first
                try:
                    resp = await client.get(f"https://{domain}", follow_redirects=True)
                except:
                    resp = await client.get(f"http://{domain}", follow_redirects=True)
                    
                content = resp.text.lower()
                headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                
                technologies = []
                
                # Server detection
                server = headers.get("server", "")
                if "nginx" in server: technologies.append("Nginx")
                elif "apache" in server: technologies.append("Apache")
                elif "litespeed" in server: technologies.append("LiteSpeed")
                elif "cloudflare" in server: technologies.append("Cloudflare Server")
                
                # CMS Detection
                if "/wp-content/" in content: technologies.append("WordPress")
                if "joomla" in content: technologies.append("Joomla")
                if "drupal" in content: technologies.append("Drupal")
                
                # Framework / Library Detection
                if "django" in content: technologies.append("Django")
                if "react" in content or "_next/" in content: technologies.append("React/Next.js")
                if "vue" in content: technologies.append("Vue.js")
                if "laravel" in content or "x-laravel-cache" in headers: technologies.append("Laravel")
                if "php" in content or ".php" in content: technologies.append("PHP")
                if "express" in content or "x-powered-by" in headers and "express" in headers["x-powered-by"]: 
                    technologies.append("Express.js")
                
                return {"technologies": list(set(technologies))}
        except:
            return {"technologies": []}


# ─────────────────────────────────────────────────────────────────
# PHASE 3: ENDPOINT & SURFACE MAPPING
# ─────────────────────────────────────────────────────────────────

class EndpointMapper:
    """Phase 3: Crawl and map application surface"""
    
    async def crawl_domain(self, domain: str) -> Dict[str, Any]:
        """
        Crawl domain to discover:
        - Internal links (Endpoints)
        - Forms & API routes
        - Cloud storage links (S3, etc.)
        """
        endpoints = {
            "links": [],
            "api_routes": [],
            "cloud_storage": [],
            "forms": []
        }
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=7) as client:
                resp = None
                for scheme in ["https", "http"]:
                    try:
                        resp = await client.get(f"{scheme}://{domain}", follow_redirects=True)
                        break
                    except: continue
                
                if not resp: return {"domain": domain, "endpoints": {}, "crawl_time": datetime.now().isoformat()}

                # Extract Links
                links = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
                for link in links:
                    if link.startswith("/") or domain in link:
                        endpoints["links"].append(link)
                    if "s3.amazonaws.com" in link or "storage.googleapis.com" in link:
                        endpoints["cloud_storage"].append(link)
                
                # Extract Forms
                forms = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', resp.text)
                endpoints["forms"].extend(forms)
                
                # Basic API route guessing from links
                for link in endpoints["links"]:
                    if "/api/" in link or "/v1/" in link or "/v2/" in link:
                        endpoints["api_routes"].append(link)
                
                # Deduplicate and Cap
                for k in endpoints:
                    if isinstance(endpoints[k], list):
                        endpoints[k] = list(set(endpoints[k]))[:50] 
        except: pass
        
        return {
            "domain": domain,
            "endpoints": endpoints,
            "crawl_time": datetime.now().isoformat()
        }
    
    async def extract_javascript_endpoints(self, domain: str) -> List[str]:
        """Extract API endpoints from JavaScript files"""
        endpoints = []
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(f"https://{domain}", follow_redirects=True)
                
                # Extract script sources
                script_regex = r'<script[^>]+src=["\']([^"\']+)["\']'
                scripts = re.findall(script_regex, resp.text)
                
                for script in scripts:
                    try:
                        script_url = script if script.startswith("http") else f"https://{domain}{script}"
                        resp = await client.get(script_url)
                        
                        # Extract API endpoints from JavaScript
                        api_regex = r'(?:api\.)?["\']\/api\/[a-zA-Z0-9/_\-]+["\']'
                        apis = re.findall(api_regex, resp.text)
                        endpoints.extend(apis)
                    except:
                        continue
        except:
            pass
        
        return list(set(endpoints))


# ─────────────────────────────────────────────────────────────────
# PHASE 4-5: DATA CORRELATION & ASSET RELATIONSHIP MAPPING
# ─────────────────────────────────────────────────────────────────

class DataCorrelation:
    """Phase 4-5: Correlate subdomains and detect asset relationships"""
    
    def __init__(self):
        self.correlations = {
            "by_ip": {},
            "by_asn": {},
            "by_certificate": {},
            "by_cdn": {}
        }
    
    def correlate_subdomains(self, intelligence_data: List[Dict]) -> Dict[str, Any]:
        """
        Find relationships between subdomains:
        - Shared IP addresses
        - Shared ASN
        - Shared SSL certificates
        - Shared CDN/WAF
        """
        
        # Group by IP
        for item in intelligence_data:
            ip = item.get("primary_ip")
            if ip:
                if ip not in self.correlations["by_ip"]:
                    self.correlations["by_ip"][ip] = []
                self.correlations["by_ip"][ip].append(item["domain"])
        
        # Group by ASN
        for item in intelligence_data:
            asn = item.get("ip_intelligence", {}).get("asn")
            if asn:
                if asn not in self.correlations["by_asn"]:
                    self.correlations["by_asn"][asn] = []
                self.correlations["by_asn"][asn].append(item["domain"])
        
        # Group by certificate
        for item in intelligence_data:
            cert = item.get("ssl_certificate", {}).get("subject")
            if cert:
                if cert not in self.correlations["by_certificate"]:
                    self.correlations["by_certificate"][cert] = []
                self.correlations["by_certificate"][cert].append(item["domain"])
        
        # Group by CDN
        for item in intelligence_data:
            cdn = item.get("cdn_waf_detection", {}).get("cdn")
            if cdn:
                if cdn not in self.correlations["by_cdn"]:
                    self.correlations["by_cdn"][cdn] = []
                self.correlations["by_cdn"][cdn].append(item["domain"])
        
        return {
            "total_correlations": self._count_correlations(),
            "by_ip": self.correlations["by_ip"],
            "by_asn": self.correlations["by_asn"],
            "by_certificate": self.correlations["by_certificate"],
            "by_cdn": self.correlations["by_cdn"],
            "shadow_infrastructure": self._detect_shadow_infrastructure()
        }
    
    def _count_correlations(self) -> int:
        """Count total correlations found"""
        count = 0
        for key in self.correlations:
            for value in self.correlations[key].values():
                if len(value) > 1:
                    count += 1
        return count
    
    def _detect_shadow_infrastructure(self) -> List[Dict]:
        """Detect unlinked or forgotten assets (shadow infrastructure)"""
        shadow = []
        
        # Domains sharing IPs but different organizations
        for ip, domains in self.correlations["by_ip"].items():
            if len(domains) > 1:
                shadow.append({
                    "type": "shared_ip",
                    "indicator": ip,
                    "domains": domains
                })
        
        return shadow


# ─────────────────────────────────────────────────────────────────
# PHASE 6: ASN-LEVEL EXPANSION (POST SUBDOMAIN)
# ─────────────────────────────────────────────────────────────────

class ASNExpansion:
    """Phase 6: Expand attack surface via ASN scanning"""
    
    async def expand_from_asn(self, asn: str) -> Dict[str, Any]:
        """
        After completing subdomain scanning, perform ASN-level reconnaissance
        to discover additional hosts and domains not linked to the primary domain
        """
        
        return {
            "asn": asn,
            "ip_ranges": await self._get_asn_prefixes(asn),
            "discovered_hosts": await self._scan_asn_range(asn),
            "reverse_dns_lookup": await self._reverse_dns_asn(asn),
            "detected_subdomains": await self._find_subdomains_in_asn(asn)
        }
    
    async def _get_asn_prefixes(self, asn: str) -> List[str]:
        """Resolve ASN to IP prefixes"""
        # Uses BGPView, RIPEstat, or Hurricane Electric
        return []  # Placeholder
    
    async def _scan_asn_range(self, asn: str) -> List[Dict]:
        """Scan IP ranges for active hosts"""
        # Port scanning within ASN ranges
        return []  # Placeholder
    
    async def _reverse_dns_asn(self, asn: str) -> Dict[str, List]:
        """Bulk reverse DNS lookup for ASN"""
        return {}  # Placeholder
    
    async def _find_subdomains_in_asn(self, asn: str) -> List[str]:
        """Find subdomains by scanning reverse DNS in ASN"""
        return []  # Placeholder


# ─────────────────────────────────────────────────────────────────
# UNIFIED RECONNAISSANCE PIPELINE
# ─────────────────────────────────────────────────────────────────

class UnifiedReconPipeline:
    """Complete attack surface reconnaissance pipeline"""
    
    def __init__(self):
        self.discovery = SubdomainDiscovery()
        self.intelligence = SubdomainIntelligence()
        self.mapping = EndpointMapper()
        self.correlation = DataCorrelation()
        self.asn_expansion = ASNExpansion()
        
        self.results = {
            "phase1_subdomains": {},
            "phase2_intelligence": [],
            "phase3_endpoints": {},
            "phase4_correlations": {},
            "phase5_asn_expansion": {},
            "final_output": {}
        }
    
    async def run_full_recon(self, domain: str, include_asn_scan: bool = True) -> Dict[str, Any]:
        """
        Execute complete reconnaissance pipeline
        
        Flow:
        1. Discover subdomains
        2. Gather intelligence on each
        3. Map endpoints
        4. Correlate data
        5. (Optional) Expand via ASN
        """
        
        # Phase 1: Discovery
        print("[*] Phase 1: Subdomain Discovery...")
        discovery_result = await self.discovery.discover_all(domain)
        self.results["phase1_subdomains"] = discovery_result
        
        # Phase 2: Intelligence
        print("[*] Phase 2: Gathering Subdomain Intelligence...")
        for subdomain_info in discovery_result["live_subdomains"]:
            intel = await self.intelligence.gather_intelligence(
                subdomain_info["domain"],
                subdomain_info["ip"]
            )
            self.results["phase2_intelligence"].append(intel)
        
        # Phase 3: Endpoint Mapping
        print("[*] Phase 3: Mapping Endpoints & Surface...")
        for subdomain_info in discovery_result["live_subdomains"]:
            endpoints = await self.mapping.crawl_domain(subdomain_info["domain"])
            self.results["phase3_endpoints"][subdomain_info["domain"]] = endpoints
        
        # Phase 4-5: Correlation & Shadow Infrastructure
        print("[*] Phase 4-5: Data Correlation...")
        correlations = self.correlation.correlate_subdomains(self.results["phase2_intelligence"])
        self.results["phase4_correlations"] = correlations
        
        # Phase 6: ASN Expansion (optional)
        if include_asn_scan:
            print("[*] Phase 6: ASN-Level Expansion...")
            asns = set()
            for intel in self.results["phase2_intelligence"]:
                asn = intel.get("ip_intelligence", {}).get("asn")
                if asn:
                    asns.add(asn)
            
            for asn in asns:
                expansion = await self.asn_expansion.expand_from_asn(asn)
                self.results["phase5_asn_expansion"][asn] = expansion
        
        # Compile final output
        self._compile_final_output(domain)
        
        return self.results
    
    def _compile_final_output(self, domain: str):
        """Compile results into final structured output"""
        
        all_domains = set([domain])
        all_subdomains = {item["domain"] for item in self.results["phase2_intelligence"]}
        all_ips = set()
        all_endpoints = set()
        
        for intel in self.results["phase2_intelligence"]:
            all_ips.add(intel["primary_ip"])
        
        for endpoints in self.results["phase3_endpoints"].values():
            for endpoint_list in endpoints.get("endpoints", {}).values():
                all_endpoints.update(endpoint_list)
        
        self.results["final_output"] = {
            "domain_summary": {
                "primary_domain": domain,
                "total_domains": len(all_domains),
                "total_subdomains": len(all_subdomains),
                "total_ips": len(all_ips),
                "total_endpoints": len(all_endpoints)
            },
            "domains": list(all_domains),
            "subdomains": list(all_subdomains),
            "ips": list(all_ips),
            "endpoints": list(all_endpoints),
            "asn_assets": list(self.results["phase5_asn_expansion"].keys()),
            "all_data_linked": True,
            "searchable": True
        }


async def main():
    """Example usage of the unified reconnaissance pipeline"""
    
    pipeline = UnifiedReconPipeline()
    
    domain = "example.com"
    results = await pipeline.run_full_recon(domain, include_asn_scan=True)
    
    print(json.dumps(results["final_output"], indent=2))


if __name__ == "__main__":
    asyncio.run(main())
