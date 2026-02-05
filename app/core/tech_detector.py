"""
Tech Stack Detector - Detect technologies used by websites
Uses multiple methods: headers, HTML analysis, and webanalyze CLI tool
"""
import subprocess
import asyncio
import aiohttp
import re
import json
from typing import Dict, List, Optional, Set
from bs4 import BeautifulSoup


class TechDetector:
    """Detect technologies from websites using multiple methods."""
    
    def __init__(self):
        self.timeout = 10
    
    async def detect(self, url: str) -> Dict[str, any]:
        """
        Detect technologies from a URL.
        
        Returns:
            Dict with keys: technologies, server, status_code, ip, headers
        """
        result = {
            "url": url,
            "technologies": [],
            "server": None,
            "status_code": None,
            "ip": None,
            "headers": {},
            "cms": None,
            "frameworks": [],
            "languages": []
        }
        
        try:
            # Ensure URL has scheme
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            # Get headers and HTML
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout), allow_redirects=True) as resp:
                    result["status_code"] = resp.status
                    result["headers"] = dict(resp.headers)
                    result["ip"] = str(resp.connection.transport.get_extra_info('peername')[0]) if resp.connection else None
                    
                    html = await resp.text()
                    
                    # Detect from headers
                    header_tech = self._detect_from_headers(resp.headers)
                    result["technologies"].extend(header_tech)
                    result["server"] = resp.headers.get("Server")
                    
                    # Detect from HTML
                    html_tech = self._detect_from_html(html)
                    result["technologies"].extend(html_tech)
                    
                    # Categorize
                    result["cms"] = self._extract_cms(result["technologies"])
                    result["frameworks"] = self._extract_frameworks(result["technologies"])
                    result["languages"] = self._extract_languages(result["technologies"])
            
            # Try webanalyze (if installed)
            webanalyze_tech = await self._detect_with_webanalyze(url)
            result["technologies"].extend(webanalyze_tech)
            
            # Deduplicate
            result["technologies"] = list(set(result["technologies"]))
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _detect_from_headers(self, headers) -> List[str]:
        """Detect technologies from HTTP headers."""
        tech = []
        
        # Server header
        server = headers.get("Server", "")
        if "nginx" in server.lower():
            tech.append("Nginx")
        if "apache" in server.lower():
            tech.append("Apache")
        if "cloudflare" in server.lower():
            tech.append("Cloudflare")
        
        # X-Powered-By
        powered_by = headers.get("X-Powered-By", "")
        if "php" in powered_by.lower():
            tech.append("PHP")
        if "asp.net" in powered_by.lower():
            tech.append("ASP.NET")
        if "express" in powered_by.lower():
            tech.append("Express.js")
        
        # Other headers
        if "X-Drupal-Cache" in headers:
            tech.append("Drupal")
        if "X-Generator" in headers:
            tech.append(headers["X-Generator"])
        
        return tech
    
    def _detect_from_html(self, html: str) -> List[str]:
        """Detect technologies from HTML content."""
        tech = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Meta generator
            generator = soup.find("meta", attrs={"name": "generator"})
            if generator and generator.get("content"):
                tech.append(generator["content"])
            
            # WordPress
            if 'wp-content' in html or 'wp-includes' in html:
                tech.append("WordPress")
            
            # Joomla
            if '/components/com_' in html or 'Joomla' in html:
                tech.append("Joomla")
            
            # Drupal
            if 'Drupal' in html or '/sites/all/' in html:
                tech.append("Drupal")
            
            # React
            if 'react' in html.lower() or '__REACT' in html:
                tech.append("React")
            
            # Vue.js
            if 'vue' in html.lower() or 'v-app' in html:
                tech.append("Vue.js")
            
            # Angular
            if 'ng-app' in html or 'angular' in html.lower():
                tech.append("Angular")
            
            # jQuery
            if 'jquery' in html.lower():
                tech.append("jQuery")
            
            # Bootstrap
            if 'bootstrap' in html.lower():
                tech.append("Bootstrap")
            
            # Tailwind
            if 'tailwind' in html.lower():
                tech.append("Tailwind CSS")
            
        except Exception:
            pass
        
        return tech
    
    async def _detect_with_webanalyze(self, url: str) -> List[str]:
        """Use webanalyze CLI tool if available."""
        tech = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "webanalyze", "-host", url, "-output", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            
            if stdout:
                data = json.loads(stdout.decode())
                if isinstance(data, list) and len(data) > 0:
                    for app in data[0].get("matches", []):
                        tech.append(app.get("app_name", ""))
        except:
            pass
        
        return tech
    
    def _extract_cms(self, technologies: List[str]) -> Optional[str]:
        """Extract CMS from technologies list."""
        cms_list = ["WordPress", "Joomla", "Drupal", "Magento", "Shopify", "Wix"]
        for tech in technologies:
            for cms in cms_list:
                if cms.lower() in tech.lower():
                    return cms
        return None
    
    def _extract_frameworks(self, technologies: List[str]) -> List[str]:
        """Extract frameworks from technologies list."""
        frameworks = []
        framework_keywords = ["React", "Vue", "Angular", "Django", "Flask", "Express", "Laravel", "Spring", "Rails"]
        for tech in technologies:
            for fw in framework_keywords:
                if fw.lower() in tech.lower() and fw not in frameworks:
                    frameworks.append(fw)
        return frameworks
    
    def _extract_languages(self, technologies: List[str]) -> List[str]:
        """Extract programming languages."""
        languages = []
        lang_keywords = ["PHP", "Python", "Ruby", "Java", "Node.js", "ASP.NET", "Go"]
        for tech in technologies:
            for lang in lang_keywords:
                if lang.lower() in tech.lower() and lang not in languages:
                    languages.append(lang)
        return languages


# Singleton
_detector_instance: Optional[TechDetector] = None


def get_tech_detector() -> TechDetector:
    """Get or create the global TechDetector instance."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = TechDetector()
    return _detector_instance
