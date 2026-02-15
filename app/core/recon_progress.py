"""
Advanced Reconnaissance UI Integration
Provides real-time progress tracking and structured result output
"""

import asyncio
import time
from typing import Dict, Any, List, Callable, Optional
from datetime import datetime
from enum import Enum

class ScanPhase(Enum):
    """Scan phase enumeration"""
    DISCOVERY = "Discovery"
    INTELLIGENCE = "Intelligence"
    MAPPING = "Mapping"
    CORRELATION = "Correlation"
    ASN_EXPANSION = "ASN Expansion"
    COMPLETE = "Complete"


class RealtimeScanTracker:
    """Track and report real-time scan progress to UI"""
    
    def __init__(self, on_update: Optional[Callable] = None):
        self.current_phase = ScanPhase.DISCOVERY
        self.progress = {
            "phase": self.current_phase.value,
            "phase_progress": 0,  # 0-100
            "overall_progress": 0,  # 0-100
            "timestamp": datetime.now().isoformat(),
            
            # Phase 1: Discovery
            "discovery_total": 0,
            "discovery_live": 0,
            "discovery_dead": 0,
            "discovery_current_tool": None,
            
            # Phase 2: Intelligence
            "intelligence_total": 0,
            "intelligence_completed": 0,
            "intelligence_current_target": None,
            
            # Phase 3: Mapping
            "mapping_total": 0,
            "mapping_completed": 0,
            "endpoints_found": 0,
            
            # Phase 4: Correlation
            "correlation_shared_ips": 0,
            "correlation_shared_asn": 0,
            "correlation_shared_certs": 0,
            "shadow_infrastructure_found": 0,
            
            # Phase 5: ASN Expansion
            "asn_total": 0,
            "asn_completed": 0,
            "asn_hosts_found": 0,
        }
        self.on_update = on_update
    
    def update_discovery(self, 
                         total: int, 
                         live: int, 
                         dead: int, 
                         current_tool: str = None):
        """Update discovery phase progress.
        FIX: Removed async — this method only does dict updates, no I/O.
        Was being called without await in core.py, causing silent failures."""
        self.progress["discovery_total"] = total
        self.progress["discovery_live"] = live
        self.progress["discovery_dead"] = dead
        if current_tool:
            self.progress["discovery_current_tool"] = current_tool
        
        self.progress["phase_progress"] = int((live / max(total, 1)) * 100)
        self._notify_update()
    
    def update_intelligence(self, 
                            total: int, 
                            completed: int, 
                            current_target: str = None):
        """Update intelligence gathering progress.
        FIX: Removed async — no I/O, was silently failing."""
        self.progress["intelligence_total"] = total
        self.progress["intelligence_completed"] = completed
        if current_target:
            self.progress["intelligence_current_target"] = current_target
        
        self.progress["phase_progress"] = int((completed / max(total, 1)) * 100)
        self._notify_update()
    
    def update_mapping(self, 
                       total: int, 
                       completed: int, 
                       endpoints_found: int = 0):
        """Update endpoint mapping progress.
        FIX: Removed async — no I/O."""
        self.progress["mapping_total"] = total
        self.progress["mapping_completed"] = completed
        self.progress["endpoints_found"] = endpoints_found
        
        self.progress["phase_progress"] = int((completed / max(total, 1)) * 100)
        self._notify_update()
    
    def update_correlation(self,
                           shared_ips: int,
                           shared_asn: int,
                           shared_certs: int,
                           shadow_infra: int):
        """Update correlation progress.
        FIX: Removed async — no I/O."""
        self.progress["correlation_shared_ips"] = shared_ips
        self.progress["correlation_shared_asn"] = shared_asn
        self.progress["correlation_shared_certs"] = shared_certs
        self.progress["shadow_infrastructure_found"] = shadow_infra
        
        self.progress["phase_progress"] = 100  # Correlation is fast
        self._notify_update()
    
    def update_asn_expansion(self,
                             total: int,
                             completed: int,
                             hosts_found: int):
        """Update ASN expansion progress.
        FIX: Removed async — no I/O."""
        self.progress["asn_total"] = total
        self.progress["asn_completed"] = completed
        self.progress["asn_hosts_found"] = hosts_found
        
        self.progress["phase_progress"] = int((completed / max(total, 1)) * 100)
        self._notify_update()
    
    def set_phase(self, phase: ScanPhase, overall_progress: int = None):
        """Transition to new phase.
        FIX: Removed async — no I/O."""
        self.current_phase = phase
        self.progress["phase"] = phase.value
        self.progress["phase_progress"] = 0
        
        if overall_progress:
            self.progress["overall_progress"] = overall_progress
        
        self.progress["timestamp"] = datetime.now().isoformat()
        self._notify_update()
    
    def _notify_update(self):
        """Notify listeners of progress update"""
        self.progress["timestamp"] = datetime.now().isoformat()
        if self.on_update:
            self.on_update(self.progress)
    
    def get_progress(self) -> Dict[str, Any]:
        """Get current progress state"""
        return self.progress.copy()


class StructuredResultsCompiler:
    """Compile raw reconnaissance data into structured output"""
    
    @staticmethod
    def compile_domains_tab(discovery_result: Dict, 
                           correlation_result: Dict) -> List[Dict]:
        """
        Domains Tab - Primary domains and their relationships
        
        Fields:
        - domain
        - type (primary, subdomain)
        - status (resolved, dead)
        - ip_addresses
        - shared_asn
        - shared_cdn
        - correlation_count
        """
        domains = []
        
        # Primary domain
        primary = {
            "domain": discovery_result.get("root_domain"),
            "type": "primary",
            "status": "active",
            "ip_addresses": [],
            "shared_asn": correlation_result.get("by_asn", {}),
            "shared_cdn": correlation_result.get("by_cdn", {}),
            "correlation_count": len(correlation_result.get("by_asn", {}))
        }
        domains.append(primary)
        
        return domains
    
    @staticmethod
    def compile_subdomains_tab(intelligence_data: List[Dict],
                               discovery_result: Dict) -> List[Dict]:
        """
        Subdomains Tab - Discovered subdomains with full metadata
        
        Fields per subdomain:
        - domain_name
        - primary_ip
        - cdn_detected
        - waf_detected
        - status_code
        - response_time
        - technologies
        - certificate_issuer
        - asn
        - last_seen
        - alerts (if applicable)
        """
        subdomains = []
        
        for intel in intelligence_data:
            subdomain_entry = {
                "domain_name": intel.get("domain"),
                "primary_ip": intel.get("primary_ip"),
                "cdn_detected": intel.get("cdn_waf_detection", {}).get("cdn"),
                "waf_detected": intel.get("cdn_waf_detection", {}).get("waf"),
                "status_code": None,  # From HTTP probe
                "response_time": None,  # From HTTP probe
                "technologies": intel.get("technology_stack", {}).get("technologies", []),
                "certificate_issuer": intel.get("ssl_certificate", {}).get("issuer"),
                "asn": intel.get("ip_intelligence", {}).get("asn"),
                "last_seen": intel.get("collected_at"),
                "alerts": []
            }
            
            # Detect alert conditions
            if intel.get("cdn_waf_detection", {}).get("waf"):
                subdomain_entry["alerts"].append("WAF Detected")
            
            subdomains.append(subdomain_entry)
        
        return subdomains
    
    @staticmethod
    def compile_endpoints_tab(endpoints_data: Dict) -> List[Dict]:
        """
        Endpoints Tab - Discovered API endpoints and application routes
        
        Fields per endpoint:
        - endpoint
        - method
        - parameters
        - source_subdomain
        - sensitive (if JWT, auth tokens, etc.)
        - last_seen
        """
        endpoints = []
        
        for subdomain, data in endpoints_data.items():
            for endpoint_type, endpoint_list in data.get("endpoints", {}).items():
                for endpoint in endpoint_list:
                    endpoints.append({
                        "endpoint": endpoint,
                        "type": endpoint_type,
                        "source_subdomain": subdomain,
                        "method": "GET",  # Would be detected
                        "parameters": [],  # Would be extracted
                        "sensitive": False,
                        "last_seen": datetime.now().isoformat()
                    })
        
        return endpoints
    
    @staticmethod
    def compile_ips_tab(intelligence_data: List[Dict],
                       correlation_result: Dict) -> List[Dict]:
        """
        IPs Tab - Discovered IP addresses with metadata
        
        Fields per IP:
        - ip_address
        - asn
        - organization
        - country
        - associated_domains
        - open_ports
        - services
        - certificate_cn
        - shared_cert_domains
        - last_seen
        """
        ips = []
        ip_seen = set()
        
        for intel in intelligence_data:
            ip = intel.get("primary_ip")
            if ip and ip not in ip_seen:
                ip_seen.add(ip)
                
                ip_entry = {
                    "ip_address": ip,
                    "asn": intel.get("ip_intelligence", {}).get("asn"),
                    "organization": intel.get("ip_intelligence", {}).get("organization"),
                    "country": intel.get("ip_intelligence", {}).get("geolocation", {}).get("country"),
                    "associated_domains": correlation_result.get("by_ip", {}).get(ip, []),
                    "open_ports": [],  # From port scan
                    "services": [],
                    "certificate_cn": intel.get("ssl_certificate", {}).get("subject"),
                    "shared_cert_domains": correlation_result.get("by_certificate", {}).get(
                        intel.get("ssl_certificate", {}).get("subject"), []
                    ),
                    "last_seen": intel.get("collected_at")
                }
                
                ips.append(ip_entry)
        
        return ips
    
    @staticmethod
    def compile_asn_assets_tab(asn_expansion_data: Dict) -> List[Dict]:
        """
        ASN Assets Tab - Additional assets discovered via ASN expansion
        
        Fields per ASN:
        - asn_number
        - ip_ranges
        - active_hosts
        - discovered_domains
        - new_attack_surface (compared to subdomains)
        """
        asn_assets = []
        
        for asn, data in asn_expansion_data.items():
            asn_entry = {
                "asn_number": asn,
                "ip_ranges": data.get("ip_ranges", []),
                "active_hosts": len(data.get("discovered_hosts", [])),
                "discovered_domains": data.get("detected_subdomains", []),
                "new_attack_surface": len(data.get("discovered_hosts", [])) + len(data.get("detected_subdomains", []))
            }
            asn_assets.append(asn_entry)
        
        return asn_assets
    
    @staticmethod
    def compile_full_output(all_data: Dict) -> Dict[str, Any]:
        """
        Compile complete structured output across all tabs
        
        Returns searchable, linked dataset organized by discovery phase
        """
        
        discovery_result = all_data.get("phase1_subdomains", {})
        intelligence_data = all_data.get("phase2_intelligence", [])
        endpoints_data = all_data.get("phase3_endpoints", {})
        correlation_result = all_data.get("phase4_correlations", {})
        asn_expansion_data = all_data.get("phase5_asn_expansion", {})
        
        return {
            "metadata": {
                "scan_timestamp": datetime.now().isoformat(),
                "total_phases_completed": 5 if asn_expansion_data else 4,
                "root_domain": discovery_result.get("root_domain"),
                "total_assets": {
                    "domains": len(discovery_result.get("by_source", {})),
                    "subdomains": discovery_result.get("live_count", 0),
                    "endpoints": sum(
                        len(endpoints_data.get(d, {}).get("endpoints", {}).get("rest_api", []))
                        for d in endpoints_data
                    ),
                    "ips": len(set(
                        i.get("primary_ip") for i in intelligence_data
                    )),
                    "asn_expanded": len(asn_expansion_data)
                }
            },
            
            "tabs": {
                "domains": StructuredResultsCompiler.compile_domains_tab(
                    discovery_result, 
                    correlation_result
                ),
                "subdomains": StructuredResultsCompiler.compile_subdomains_tab(
                    intelligence_data,
                    discovery_result
                ),
                "endpoints": StructuredResultsCompiler.compile_endpoints_tab(
                    endpoints_data
                ),
                "ips": StructuredResultsCompiler.compile_ips_tab(
                    intelligence_data,
                    correlation_result
                ),
                "asn_assets": StructuredResultsCompiler.compile_asn_assets_tab(
                    asn_expansion_data
                )
            },
            
            "correlations": {
                "shared_ips": correlation_result.get("by_ip", {}),
                "shared_asn": correlation_result.get("by_asn", {}),
                "shared_certificates": correlation_result.get("by_certificate", {}),
                "shared_cdn": correlation_result.get("by_cdn", {}),
                "shadow_infrastructure": correlation_result.get("shadow_infrastructure", [])
            },
            
            "search_index": {
                "by_domain": {item.get("domain_name"): item 
                             for item in StructuredResultsCompiler.compile_subdomains_tab(intelligence_data, discovery_result)},
                "by_ip": {item.get("ip_address"): item 
                         for item in StructuredResultsCompiler.compile_ips_tab(intelligence_data, correlation_result)},
                "by_asn": {item.get("asn"): item 
                          for item in StructuredResultsCompiler.compile_asn_assets_tab(asn_expansion_data)}
            }
        }


# ─────────────────────────────────────────────────────────────────
# DASHBOARD UPDATE MECHANISM
# ─────────────────────────────────────────────────────────────────

class DashboardUpdateManager:
    """Manages real-time dashboard updates via WebSocket/SSE"""
    
    def __init__(self):
        self.active_scans = {}
        self.listeners = {}
    
    def register_listener(self, scan_id: str, callback: Callable):
        """Register a callback for progress updates"""
        if scan_id not in self.listeners:
            self.listeners[scan_id] = []
        self.listeners[scan_id].append(callback)
    
    async def broadcast_update(self, scan_id: str, progress: Dict):
        """Broadcast progress update to all listeners"""
        if scan_id in self.listeners:
            for callback in self.listeners[scan_id]:
                try:
                    await callback(progress)
                except:
                    pass
    
    async def broadcast_results(self, scan_id: str, results: Dict):
        """Broadcast final results to all listeners"""
        if scan_id in self.listeners:
            for callback in self.listeners[scan_id]:
                try:
                    await callback({
                        "type": "final_results",
                        "data": results,
                        "timestamp": datetime.now().isoformat()
                    })
                except:
                    pass


# Global instance
dashboard_manager = DashboardUpdateManager()
