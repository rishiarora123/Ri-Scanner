"""
IP Geolocation - Phase 2 Enhancement
Multi-source IP geolocation with fallback APIs
"""

import httpx
import re
from typing import Dict
import socket

# Common User-Agent to avoid blocking
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

class IPGeolocation:
    """IP geolocation with multiple API fallbacks"""
    
    async def geolocate_ip(self, ip: str) -> Dict:
        """Master geolocation function with fallback sources"""
        
        results = {
            "ip": ip,
            "geolocation": None,
            "sources_tried": [],
            "confidence": "low"
        }
        
        # Try multiple geolocation APIs in order of reliability
        sources = [
            self._geolocate_ipapi,
            self._geolocate_maxmind,
            self._geolocate_ipstack,
            self._geolocate_whois,
        ]
        
        for source_func in sources:
            try:
                result = await source_func(ip)
                if result:
                    results["geolocation"] = result
                    results["sources_tried"].append(source_func.__name__)
                    results["confidence"] = "high"
                    break
            except:
                results["sources_tried"].append(f"{source_func.__name__} (failed)")
                continue
        
        # If we have geolocation, add ASN lookup
        if results["geolocation"]:
            asn_info = await self._get_asn_info(ip)
            if asn_info:
                results["geolocation"]["asn_info"] = asn_info
        
        return results
    
    async def _geolocate_ipapi(self, ip: str) -> Dict:
        """IP-API.com geolocation (free tier, limited)"""
        try:
            async with httpx.AsyncClient(timeout=5, headers=DEFAULT_HEADERS) as client:
                response = await client.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": "status,country,countryCode,region,city,lat,lon,isp,org,as"}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        return {
                            "country": data.get("country"),
                            "country_code": data.get("countryCode"),
                            "region": data.get("region"),
                            "city": data.get("city"),
                            "latitude": data.get("lat"),
                            "longitude": data.get("lon"),
                            "isp": data.get("isp"),
                            "organization": data.get("org"),
                            "asn": data.get("as"),
                            "source": "ip-api.com"
                        }
        except Exception:
            pass
        
        return None
    
    async def _geolocate_maxmind(self, ip: str) -> Dict:
        """MaxMind GeoIP2 geolocation (enterprise grade)"""
        try:
            # MaxMind offers free GeoLite2 database
            # This is a placeholder for when the database is available locally
            
            import geoip2.database
            
            # Look for local MaxMind database
            try:
                with geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-City.mmdb') as reader:
                    response = reader.city(ip)
                    return {
                        "country": response.country.name,
                        "country_code": response.country.iso_code,
                        "region": response.subdivisions[0].name if response.subdivisions else None,
                        "city": response.city.name,
                        "latitude": response.location.latitude,
                        "longitude": response.location.longitude,
                        "accuracy_radius": response.location.accuracy_radius,
                        "source": "maxmind-geolite2"
                    }
            except:
                pass
        except:
            pass
        
        return None
    
    async def _geolocate_ipstack(self, ip: str) -> Dict:
        """IPStack geolocation API (free tier available)"""
        try:
            # Note: This requires API key, using placeholder
            api_key = "free"  # or set from config
            
            async with httpx.AsyncClient(timeout=5, headers=DEFAULT_HEADERS) as client:
                response = await client.get(
                    f"http://api.ipstack.com/{ip}",
                    params={"access_key": api_key}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get("type") != "error":
                        return {
                            "country": data.get("country_name"),
                            "country_code": data.get("country_code"),
                            "region": data.get("region_name"),
                            "city": data.get("city"),
                            "latitude": data.get("latitude"),
                            "longitude": data.get("longitude"),
                            "timezone": data.get("time_zone", {}).get("id"),
                            "isp": data.get("connection", {}).get("isp_name"),
                            "organization": data.get("connection", {}).get("organization_name"),
                            "source": "ipstack"
                        }
        except Exception:
            pass
        
        return None
    
    async def _geolocate_whois(self, ip: str) -> Dict:
        """WHOIS data parsing for geolocation (fallback)"""
        try:
            async with httpx.AsyncClient(timeout=5, headers=DEFAULT_HEADERS) as client:
                response = await client.get(f"https://whois.arin.net/rest/ip/{ip}/json")
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extract from ARIN WHOIS
                    network = data.get("net", {})
                    org = data.get("org", {})
                    
                    return {
                        "organization": org.get("name"),
                        "country_code": org.get("iso3166-1", {}).get("$"),
                        "network": network.get("name"),
                        "network_range": f"{network.get('startAddress')} - {network.get('endAddress')}",
                        "source": "arin-whois"
                    }
        except Exception:
            pass
        
        return None
    
    async def _get_asn_info(self, ip: str) -> Dict:
        """Get ASN information for IP"""
        try:
            # Try ASN lookup via whois
            async with httpx.AsyncClient(timeout=5, headers=DEFAULT_HEADERS) as client:
                response = await client.get(
                    f"https://asn.cymru.com/cgi-bin/whois.cgi",
                    params={"ip": ip}
                )
                
                if response.status_code == 200:
                    lines = response.text.strip().split('\n')
                    if len(lines) > 1:
                        parts = lines[-1].split('|')
                        if len(parts) >= 3:
                            return {
                                "asn": parts[0].strip(),
                                "cidr": parts[1].strip(),
                                "country_code": parts[2].strip(),
                                "organization": parts[3].strip() if len(parts) > 3 else None
                            }
        except Exception:
            pass
        
        return None
    
    async def bulk_geolocate(self, ips: list) -> Dict:
        """Geolocate multiple IPs"""
        results = {
            "total_ips": len(ips),
            "geolocation_results": [],
            "countries": {},
            "organizations": set()
        }
        
        for ip in ips[:100]:  # Limit to 100 IPs to avoid rate limiting
            try:
                geo_result = await self.geolocate_ip(ip)
                results["geolocation_results"].append(geo_result)
                
                # Aggregate countries
                if geo_result.get("geolocation", {}).get("country"):
                    country = geo_result["geolocation"]["country"]
                    results["countries"][country] = results["countries"].get(country, 0) + 1
                
                # Collect organizations
                if geo_result.get("geolocation", {}).get("organization"):
                    results["organizations"].add(geo_result["geolocation"]["organization"])
            
            except:
                continue
        
        results["organizations"] = list(results["organizations"])
        return results
