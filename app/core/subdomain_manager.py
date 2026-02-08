"""
Subdomain Manager - MongoDB-based storage for subdomains and domain details
"""
import os
from typing import List, Dict, Optional, Any
from datetime import datetime

class SubdomainManager:
    """Manages subdomain storage and retrieval using MongoDB."""
    
    def __init__(self, db=None):
        self.db = db  # Store MongoDB database reference
    
    def set_db(self, db):
        """Set the MongoDB database instance (called after app initialization)."""
        self.db = db
    
    def save_subdomains(self, scan_id: str, subdomains: List[Any], source: str = "recon", asn_scan_id: str = None) -> bool:
        """
        Save subdomains to MongoDB.
        
        Args:
            scan_id: Unique scan identifier
            subdomains: List of subdomain strings OR dicts
            source: Source of subdomains ('recon', 'asn', 'extraction', etc.)
            asn_scan_id: Optional ASN scan ID if source is ASN
        """
        try:
            timestamp = datetime.now().isoformat()
            source_type = "asn" if source == "asn" or asn_scan_id else "recon"
            
            if self.db is None:
                print("[!] MongoDB not available in SubdomainManager")
                return False

            # Bulk operations would be better for performance, but keeping it simple/safe for now
            # as per previous logic, but now exclusively MongoDB
            
            ops_count = 0
            for item in subdomains:
                domain_val = item if isinstance(item, str) else item.get("domain")
                if not domain_val:
                    continue
                
                # Build document
                if isinstance(item, dict):
                    doc = item.copy()
                    if "domain" not in doc:
                        doc["domain"] = domain_val
                else:
                    doc = {"domain": domain_val}
                
                # Add required fields
                doc["scan_id"] = scan_id
                doc["source"] = source
                doc["source_type"] = source_type
                doc["is_from_asn"] = (source_type == "asn")
                
                if asn_scan_id:
                    doc["asn_scan_id"] = asn_scan_id
                
                # Set discovered_at only for new records
                update_doc = {
                    "$set": doc,
                    "$setOnInsert": {"discovered_at": timestamp}
                }
                
                # Update last_checked for all
                update_doc["$set"]["last_checked"] = timestamp
                
                # Upsert individual subdomain document
                self.db.subdomains.update_one(
                    {"scan_id": scan_id, "domain": domain_val},
                    update_doc,
                    upsert=True
                )
                ops_count += 1
            
            print(f"[*] Saved {ops_count} subdomain records to MongoDB")
            return True
        except Exception as e:
            print(f"[!] MongoDB subdomain save error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_subdomains(self, scan_id: str, filters: Optional[Dict] = None, page: int = 1, per_page: int = 50) -> Dict[str, Any]:
        """
        Get subdomains with optional filters and pagination.
        
        Args:
            scan_id: Scan identifier or 'all'
            filters: Dict with keys: source, is_new_from_asn, search_term
            page: Page number (1-indexed)
            per_page: Items per page
        """
        try:
            if self.db is None:
                return {"subdomains": [], "total": 0, "page": page, "pages": 0}
            
            query = {}
            if scan_id != "all":
                query["scan_id"] = scan_id
            
            if filters:
                if filters.get("source"):
                    query["source"] = filters["source"]
                if filters.get("is_new_from_asn") is not None:
                    query["is_new_from_asn"] = filters["is_new_from_asn"]
                if filters.get("search_term"):
                    query["domain"] = {"$regex": filters["search_term"], "$options": "i"}
                if filters.get("status"):
                    try:
                        query["status_code"] = int(filters["status"])
                    except ValueError:
                        pass
                if filters.get("has_site"):
                     if filters["has_site"] == "yes":
                         query["status_code"] = {"$exists": True, "$ne": None}
                     elif filters["has_site"] == "no":
                         # status_code is missing or null
                         query["$or"] = [{"status_code": {"$exists": False}}, {"status_code": None}]

            # Sort
            sort_order = [("discovered_at", -1)] # Default new first
            sort_by = filters.get("sort_by")
            if sort_by == "oldest":
                sort_order = [("discovered_at", 1)]
            elif sort_by == "domain":
                sort_order = [("domain", 1)]
            elif sort_by == "status":
                sort_order = [("status_code", -1)]

            # Pagination
            skip = (page - 1) * per_page
            
            total = self.db.subdomains.count_documents(query)
            cursor = self.db.subdomains.find(query).sort(sort_order).skip(skip).limit(per_page)
            
            results = list(cursor)
            
            # Cleanup _id
            for r in results:
                if '_id' in r:
                    del r['_id']
            
            import math
            total_pages = math.ceil(total / per_page) if per_page > 0 else 0
            
            return {
                "subdomains": results,
                "total": total,
                "page": page,
                "pages": total_pages
            }

        except Exception as e:
            print(f"Error getting subdomains: {e}")
            return {"subdomains": [], "total": 0, "page": page, "pages": 0, "error": str(e)}

    def search_all_subdomains(self, query: str = "", limit: int = 100) -> List[Dict]:
        """Legacy support wrapper for search with limit."""
        result = self.get_subdomains("all", filters={"search_term": query}, page=1, per_page=limit)
        return result.get("subdomains", [])
    
    def save_domain_details(self, scan_id: str, domain: str, details: Dict) -> bool:
        """Save detailed information about a domain into the subdomain document."""
        try:
            if self.db is None:
                return False
                
            # Update the existing subdomain document with details
            self.db.subdomains.update_one(
                {"scan_id": scan_id, "domain": domain},
                {"$set": details, "$currentDate": {"last_updated": True}},
                upsert=True 
            )
            return True
        except Exception as e:
            print(f"Error saving domain details: {e}")
            return False
            
    def get_domain_details(self, scan_id: str, domain: str) -> Optional[Dict]:
        """Get details from MongoDB."""
        try:
            if self.db is None:
                return None
            
            # Find in subdomains collection
            doc = self.db.subdomains.find_one({"scan_id": scan_id, "domain": domain})
            if not doc and scan_id == "all":
                 # Fallback: find any instance of this domain
                 doc = self.db.subdomains.find_one({"domain": domain})
            
            if doc and '_id' in doc:
                del doc['_id']
            return doc
        except Exception as e:
            print(f"Error getting domain details: {e}")
            return None


# Singleton instance
_manager_instance: Optional[SubdomainManager] = None


def get_subdomain_manager() -> SubdomainManager:
    """Get or create the global SubdomainManager instance."""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = SubdomainManager()
    return _manager_instance
