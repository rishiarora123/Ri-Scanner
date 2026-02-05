"""
Subdomain Manager - File-based storage for subdomains and domain details
"""
import os
import json
from typing import List, Dict, Optional, Any
from datetime import datetime


class SubdomainManager:
    """Manages subdomain storage and retrieval."""
    
    def __init__(self, base_dir: str = "Data/subdomains"):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
    
    def _get_scan_dir(self, scan_id: str) -> str:
        """Get or create scan directory."""
        scan_dir = os.path.join(self.base_dir, scan_id)
        os.makedirs(scan_dir, exist_ok=True)
        return scan_dir
    
    def save_subdomains(self, scan_id: str, subdomains: List[Any], source: str = "recon") -> bool:
        """
        Save subdomains to file and MongoDB.
        
        Args:
            scan_id: Unique scan identifier
            subdomains: List of subdomain strings OR dicts
            source: Source of subdomains ('recon' or 'asn')
        """
        try:
            scan_dir = self._get_scan_dir(scan_id)
            file_path = os.path.join(scan_dir, "subdomains.json")
            
            # Load existing data
            data = self._load_json(file_path, default={"subdomains": [], "metadata": {}})
            
            # Index existing domains for O(1) lookup and update
            existing_map = {s["domain"]: i for i, s in enumerate(data["subdomains"])}
            timestamp = datetime.now().isoformat()
            
            new_subdomains = []
            
            for item in subdomains:
                domain_val = item if isinstance(item, str) else item.get("domain")
                if not domain_val: continue
                
                if domain_val in existing_map:
                    # UPDATE existing
                    idx = existing_map[domain_val]
                    if isinstance(item, dict):
                        # Merge fields
                        data["subdomains"][idx].update(item)
                        # Ensure we don't overwrite source if it was already there, unless it's new
                        if "source" not in item:
                             data["subdomains"][idx]["source"] = source
                else:
                    # INSERT new
                    if isinstance(item, dict):
                        sub_data = item.copy()
                        if "domain" not in sub_data: sub_data["domain"] = domain_val
                        if "source" not in sub_data: sub_data["source"] = source
                        if "added_at" not in sub_data: sub_data["added_at"] = timestamp
                        if "is_new_from_asn" not in sub_data: sub_data["is_new_from_asn"] = (source == "asn")
                    else:
                        sub_data = {
                            "domain": domain_val,
                            "source": source,
                            "added_at": timestamp,
                            "is_new_from_asn": source == "asn"
                        }
                    
                    data["subdomains"].append(sub_data)
                    new_subdomains.append(sub_data)
                    existing_map[domain_val] = len(data["subdomains"]) - 1
            
            # Update metadata
            data["metadata"]["last_updated"] = timestamp
            data["metadata"]["total_count"] = len(data["subdomains"])
            
            # Save to file
            self._save_json(file_path, data)
            
            # Save to MongoDB
            try:
                from flask import current_app
                if hasattr(current_app, 'db') and current_app.db is not None:
                    # We need to update the whole array or handle upserts carefully.
                    # For simplicity, we'll replace the subdomains list in MongoDB to match file
                    # This ensures updates/merges are reflected.
                    # Optimization: For very large lists, this might be heavy.
                    # But ensures consistency.
                    current_app.db.scans.update_one(
                        {"scan_id": scan_id},
                        {
                            "$set": {
                                "scan_id": scan_id,
                                "last_updated": timestamp,
                                "total_subdomains": len(data["subdomains"]),
                                "subdomains": data["subdomains"] 
                            }
                        },
                        upsert=True
                    )
            except Exception as e:
                # print(f"MongoDB save warning: {e}")
                pass
            
            return True
        except Exception as e:
            print(f"Error saving subdomains: {e}")
            return False
    
    def get_subdomains(self, scan_id: str, filters: Optional[Dict] = None) -> List[Dict]:
        """
        Get subdomains with optional filters.
        
        Args:
            scan_id: Scan identifier
            filters: Dict with keys: source, is_new_from_asn, search_term
        """
        try:
            scan_dir = self._get_scan_dir(scan_id)
            file_path = os.path.join(scan_dir, "subdomains.json")
            data = self._load_json(file_path, default={"subdomains": []})
            
            subdomains = data.get("subdomains", [])
            
            if not filters:
                return subdomains
            
            # Apply filters
            if filters.get("source"):
                subdomains = [s for s in subdomains if s.get("source") == filters["source"]]
            
            if filters.get("is_new_from_asn") is not None:
                subdomains = [s for s in subdomains if s.get("is_new_from_asn") == filters["is_new_from_asn"]]
            
            if filters.get("search_term"):
                term = filters["search_term"].lower()
                subdomains = [s for s in subdomains if term in s.get("domain", "").lower()]
            
            return subdomains
        except Exception as e:
            print(f"Error getting subdomains: {e}")
            return []

    def search_all_subdomains(self, query: str = "", limit: int = 100) -> List[Dict]:
        """
        Search subdomains across ALL scans (Global Search).
        Prefer MongoDB, fall back to filesystem.
        """
        results = []
        mongo_success = False
        
        try:
            # Try MongoDB first
            from flask import current_app
            if hasattr(current_app, 'db') and current_app.db is not None:
                pipeline = [
                    {"$unwind": "$subdomains"},
                    {"$match": {"subdomains.domain": {"$regex": query, "$options": "i"}}},
                    {"$limit": limit},
                    {"$project": {
                        "domain": "$subdomains.domain",
                        "source": "$subdomains.source",
                        "scan_id": "$scan_id",
                        "added_at": "$subdomains.added_at",
                        "ip": "$subdomains.ip",
                        "status_code": "$subdomains.status_code",
                        "technologies": "$subdomains.technologies"
                    }}
                ]
                cursor = current_app.db.scans.aggregate(pipeline)
                results = list(cursor)
                if len(results) > 0:
                    mongo_success = True
                
        except Exception as e:
            print(f"Global search MongoDB error: {e}")
        
        # Fallback to filesystem if MongoDB failed or returned nothing
        if not mongo_success:
            try:
                count = 0
                if os.path.exists(self.base_dir):
                    for scan_id in os.listdir(self.base_dir):
                        if count >= limit: break
                        if scan_id.startswith("."): continue
                        
                        subs = self.get_subdomains(scan_id, filters={"search_term": query})
                        for s in subs:
                            if count >= limit: break
                            s["scan_id"] = scan_id
                            results.append(s)
                            count += 1
            except Exception as e:
                print(f"Global search file error: {e}")
            
        return results
    
    def mark_as_new_from_asn(self, scan_id: str, subdomain_list: List[str]) -> bool:
        """Mark specific subdomains as newly added from ASN."""
        try:
            scan_dir = self._get_scan_dir(scan_id)
            file_path = os.path.join(scan_dir, "subdomains.json")
            data = self._load_json(file_path, default={"subdomains": []})
            
            subdomain_set = set(subdomain_list)
            for sub in data["subdomains"]:
                if sub["domain"] in subdomain_set:
                    sub["is_new_from_asn"] = True
                    sub["source"] = "asn"
            
            self._save_json(file_path, data)
            return True
        except Exception as e:
            print(f"Error marking subdomains: {e}")
            return False
    
    def save_domain_details(self, scan_id: str, domain: str, details: Dict) -> bool:
        """Save detailed information about a domain."""
        try:
            scan_dir = self._get_scan_dir(scan_id)
            file_path = os.path.join(scan_dir, "domain_details.json")
            data = self._load_json(file_path, default={})
            
            data[domain] = {
                **details,
                "last_updated": datetime.now().isoformat()
            }
            
            self._save_json(file_path, data)
            return True
        except Exception as e:
            print(f"Error saving domain details: {e}")
            return False
    
    def get_domain_details(self, scan_id: str, domain: str) -> Optional[Dict]:
        """Get detailed information about a domain."""
        try:
            scan_dir = self._get_scan_dir(scan_id)
            file_path = os.path.join(scan_dir, "domain_details.json")
            data = self._load_json(file_path, default={})
            return data.get(domain)
        except Exception as e:
            print(f"Error getting domain details: {e}")
            return None
    
    def _load_json(self, file_path: str, default: Any = None) -> Any:
        """Load JSON file or return default."""
        if not os.path.exists(file_path):
            return default
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except:
            return default
    
    def _save_json(self, file_path: str, data: Any) -> None:
        """Save data to JSON file."""
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)


# Singleton instance
_manager_instance: Optional[SubdomainManager] = None


def get_subdomain_manager() -> SubdomainManager:
    """Get or create the global SubdomainManager instance."""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = SubdomainManager()
    return _manager_instance
