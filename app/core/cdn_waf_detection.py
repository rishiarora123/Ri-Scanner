"""
CDN/WAF Detection - Phase 2 Enhancement
Multi-source detection of CDN and WAF providers
"""

import httpx
import re
import dns.resolver
from typing import Dict, List

# Common User-Agent to avoid blocking
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

class CDNWAFDetection:
    """Multi-stage CDN/WAF detection with confidence scoring"""
    
    # Known CDN CNAME patterns
    CDN_CNAMES = {
        "Cloudflare": [r"\.cloudflare\.com$", r"cf-ns\.com$"],
        "Akamai": [r"\.akamaiedge\.net$", r"\.akamai\.net$"],
        "Fastly": [r"\.fastly\.net$"],
        "CloudFront": [r"\.cloudfront\.net$"],
        "Limelight": [r"\.limelight\.com$"],
        "Stackpath": [r"\.stackpath\.net$"],
        "Imperva": [r"\.imperva\.net$"],
        "AWS Shield": [r"\.awssecurity\."]
    }
    
    # Known WAF header signatures
    WAF_HEADERS = {
        "Cloudflare": [r"cf-ray", r"cf-request-id"],
        "AWS WAF": [r"x-amzn-"], 
        "Imperva": [r"x-iinfo", r"x-cdn"],
        "Sucuri": [r"x-sucuri-id"],
        "Wordfence": [r"x-wordfence"],
        "ModSecurity": [r"modsecurity"],
        "F5 BIG-IP": [r"bigipserver"],
        "Barracuda": [r"barracuda"],
        "Fortinet FortiWeb": [r"x-fortiweb"],
        "Citrix NetScaler": [r"ns-server", r"netscaler"],
    }
    
    # Known WAF response patterns
    WAF_RESPONSES = {
        "Cloudflare": [r"1005", r"error code: 1005"],
        "Imperva": [r"403 Forbidden", r"detected anomalous traffic"],
        "AWS WAF": [r"403 Forbidden"],
        "Sucuri": [r"Blocked by Sucuri"],
    }
    
    async def detect_all(self, domain: str) -> Dict:
        """Master detection function combining all methods"""
        
        results = {
            "cdn_detection": await self._detect_cdn(domain),
            "waf_detection": await self._detect_waf(domain),
            "combined_analysis": {}
        }
        
        # Combine results
        results["combined_analysis"] = {
            "total_cdn_detected": len(results["cdn_detection"].get("detected", [])),
            "total_waf_detected": len(results["waf_detection"].get("detected", [])),
            "is_behind_cdn": len(results["cdn_detection"].get("detected", [])) > 0,
            "is_protected_by_waf": len(results["waf_detection"].get("detected", [])) > 0,
        }
        
        return results
    
    async def _detect_cdn(self, domain: str) -> Dict:
        """Multi-source CDN detection"""
        detected = []
        methods_used = []
        
        # Method 1: CNAME lookup
        cname_result = await self._check_cname(domain)
        if cname_result:
            detected.extend(cname_result["detected"])
            methods_used.append("CNAME lookup")
        
        # Method 2: Header analysis
        headers_result = await self._check_headers_for_cdn(domain)
        if headers_result:
            detected.extend(headers_result["detected"])
            methods_used.append("HTTP headers")
        
        # Method 3: IP reputation check
        ip_result = await self._check_cdn_by_ip(domain)
        if ip_result:
            detected.extend(ip_result["detected"])
            methods_used.append("IP reputation")
        
        # Deduplicate
        detected = list(set(detected))
        
        return {
            "detected": detected,
            "methods_used": methods_used,
            "confidence": "high" if len(detected) >= 2 else "medium" if len(detected) == 1 else "low"
        }
    
    async def _detect_waf(self, domain: str) -> Dict:
        """Multi-source WAF detection"""
        detected = []
        methods_used = []
        
        # Method 1: Header analysis
        headers_result = await self._check_headers_for_waf(domain)
        if headers_result:
            detected.extend(headers_result["detected"])
            methods_used.append("HTTP headers")
        
        # Method 2: Response pattern analysis
        response_result = await self._check_waf_responses(domain)
        if response_result:
            detected.extend(response_result["detected"])
            methods_used.append("Response patterns")
        
        # Method 3: Behavioral detection
        behavior_result = await self._check_waf_behavior(domain)
        if behavior_result:
            detected.extend(behavior_result["detected"])
            methods_used.append("Behavioral patterns")
        
        detected = list(set(detected))
        
        return {
            "detected": detected,
            "methods_used": methods_used,
            "confidence": "high" if len(detected) >= 2 else "medium" if len(detected) == 1 else "low"
        }
    
    async def _check_cname(self, domain: str) -> Dict:
        """Check CNAME records for CDN signatures"""
        detected = []
        
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target)
                
                for cdn_name, patterns in self.CDN_CNAMES.items():
                    for pattern in patterns:
                        if re.search(pattern, cname, re.IGNORECASE):
                            detected.append(cdn_name)
                            break
        
        except Exception:
            pass
        
        return {"detected": list(set(detected))} if detected else None
    
    async def _check_headers_for_cdn(self, domain: str) -> Dict:
        """Check HTTP headers for CDN indicators"""
        detected = []
        
        try:
            async with httpx.AsyncClient(timeout=5, verify=False, headers=DEFAULT_HEADERS) as client:
                response = await client.get(f"https://{domain}", follow_redirects=False)
                headers = dict(response.headers)
                
                # Check specific headers
                cdn_header_patterns = {
                    "Cloudflare": [r"cf-", r"server: cloudflare"],
                    "Akamai": [r"akamai"],
                    "Fastly": [r"fastly"],
                    "CloudFront": [r"cloudfront"],
                    "AWS": [r"x-amzn"],
                }
                
                for header_name, header_value in headers.items():
                    for cdn_name, patterns in cdn_header_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, f"{header_name}: {header_value}", re.IGNORECASE):
                                detected.append(cdn_name)
                                break
        
        except Exception:
            pass
        
        return {"detected": list(set(detected))} if detected else None
    
    async def _check_headers_for_waf(self, domain: str) -> Dict:
        """Check HTTP headers for WAF signatures"""
        detected = []
        
        try:
            async with httpx.AsyncClient(timeout=5, verify=False, headers=DEFAULT_HEADERS) as client:
                response = await client.get(f"https://{domain}", follow_redirects=False)
                headers = dict(response.headers)
                headers_str = "\n".join([f"{k}: {v}" for k, v in headers.items()])
                
                for waf_name, patterns in self.WAF_HEADERS.items():
                    for pattern in patterns:
                        if re.search(pattern, headers_str, re.IGNORECASE):
                            detected.append(waf_name)
                            break
        
        except Exception:
            pass
        
        return {"detected": list(set(detected))} if detected else None
    
    async def _check_waf_responses(self, domain: str) -> Dict:
        """Detect WAF by response patterns (send suspicious payloads)"""
        detected = []
        
        # Safe payloads that won't cause harm but trigger WAF
        test_payloads = [
            "/?id=1' OR '1'='1",
            "/?page=../../etc/passwd",
            "/?file=<script>alert(1)</script>",
        ]
        
        try:
            async with httpx.AsyncClient(timeout=5, verify=False, headers=DEFAULT_HEADERS) as client:
                for payload in test_payloads:
                    try:
                        response = await client.get(f"https://{domain}{payload}", timeout=3)
                        
                        # Check for WAF response patterns
                        response_text = response.text
                        for waf_name, patterns in self.WAF_RESPONSES.items():
                            for pattern in patterns:
                                if re.search(pattern, response_text, re.IGNORECASE):
                                    detected.append(waf_name)
                                    break
                    except:
                        continue
        
        except Exception:
            pass
        
        return {"detected": list(set(detected))} if detected else None
    
    async def _check_waf_behavior(self, domain: str) -> Dict:
        """Detect WAF by behavioral patterns"""
        detected = []
        
        try:
            async with httpx.AsyncClient(timeout=5, verify=False, headers=DEFAULT_HEADERS) as client:
                # Check rate limiting behavior
                responses = []
                for i in range(5):
                    try:
                        response = await client.get(f"https://{domain}/?test={i}", timeout=2)
                        responses.append(response.status_code)
                    except:
                        responses.append(None)
                
                # If we get 429 (rate limited), likely WAF
                if 429 in responses:
                    detected.append("WAF (Rate Limited)")
                
                # If some requests blocked but others succeed, likely WAF
                if 403 in responses and 200 in responses:
                    detected.append("WAF (Selective Blocking)")
        
        except Exception:
            pass
        
        return {"detected": list(set(detected))} if detected else None
    
    async def _check_cdn_by_ip(self, domain: str) -> Dict:
        """Detect CDN by IP reputation/ranges"""
        detected = []
        
        try:
            import socket
            ip = socket.gethostbyname(domain)
            
            # Known CDN IP ranges (simplified)
            cdn_ranges = {
                "Cloudflare": [
                    "173.245.48.0/20",
                    "103.21.244.0/22",
                    "103.22.200.0/22",
                ],
                "Akamai": [
                    "95.101.0.0/16",
                    "204.15.0.0/16",
                ],
                "AWS CloudFront": [
                    "54.0.0.0/8",
                    "52.0.0.0/8",
                ],
            }
            
            # Simplified check (real implementation would use ipaddress module)
            if "173.245." in ip or "103.21." in ip or "103.22." in ip:
                detected.append("Cloudflare")
        
        except Exception:
            pass
        
        return {"detected": detected} if detected else None
