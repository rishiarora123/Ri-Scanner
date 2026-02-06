from flask import Blueprint, render_template, request, jsonify, Response, current_app
import threading
import os
import json
import asyncio
from werkzeug.utils import secure_filename
from .core import core
from bson import json_util
import re
from bson.regex import Regex

main_bp = Blueprint('main', __name__)

import subprocess
import time
from .core.fuzzer_helper import AsyncFuzzer, get_directory_fuzzer
from .core.tools_checker import get_tools_checker
from .core.subdomain_manager import get_subdomain_manager
from .core.tech_detector import get_tech_detector
from .core.crawler_helper import get_crawler_helper

# Global state for active scans and fuzzing
ACTIVE_FUZZ_JOBS = {}
FUZZ_RESULTS = []

# Global Context
scan_status = {
    "phase": "Idle",
    "masscan_progress": 0,
    "masscan_total": 0,
    "masscan_ranges_done": 0,
    "masscan_ranges_total": 0,
    "masscan_chunks_status": [],
    "extraction_progress": 0,
    "extraction_total": 0,
    "found_count": 0,
    "active_threads": 0,
    "estimated_remaining": "N/A"
}
scan_logs = []
scan_context = {
    "stop_event": threading.Event(),
    "keep_files": False
}

def run_async_in_thread(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(coro)
    loop.close()

@main_bp.route("/")
def home():
    return render_template("index.html")

@main_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@main_bp.route("/results")
def results_page():
    return render_template("results.html")

@main_bp.route("/settings")
def settings_page():
    return render_template("settings.html")

# NEW ROUTES - ASN Tab
@main_bp.route("/asn")
def asn_page():
    """ASN scanner page."""
    return render_template("asn.html")

# NEW ROUTES - Subdomains Tab
@main_bp.route("/subdomains")
def subdomains_page():
    """Subdomains tab page."""
    return render_template("subdomains.html")

@main_bp.route("/subdomains/list/<scan_id>", methods=["GET"])
def get_subdomains_list(scan_id):
    """Get list of all subdomains for a scan."""
    try:
        manager = get_subdomain_manager()
        
        # Get filters from query params
        filters = {}
        if request.args.get("source"):
            filters["source"] = request.args.get("source")
        if request.args.get("is_new_from_asn"):
            filters["is_new_from_asn"] = request.args.get("is_new_from_asn") == "true"
        if request.args.get("search"):
            filters["search_term"] = request.args.get("search")
        
        if scan_id == "all" or not scan_id:
            # Global search across all scans
            subdomains = manager.search_all_subdomains(filters.get("search_term", ""), limit=500)
        else:
            subdomains = manager.get_subdomains(scan_id, filters)
        
        # Apply status code filter if provided
        status_filter = request.args.get("status")
        if status_filter:
            try:
                status_code = int(status_filter)
                subdomains = [s for s in subdomains if s.get("status_code") == status_code]
            except ValueError:
                pass  # Invalid status code, skip filter
        
        return jsonify({"success": True, "subdomains": subdomains})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@main_bp.route("/subdomains/details/<scan_id>/<domain>", methods=["GET"])
def get_subdomain_details(scan_id, domain):
    """Get detailed information about a subdomain."""
    try:
        manager = get_subdomain_manager()
        tech_detector = get_tech_detector()
        
        details = None
        
        # If scan_id is 'all', search across all scans
        if scan_id == "all":
            base_dir = "Data/subdomains"
            if os.path.exists(base_dir):
                for potential_scan_id in os.listdir(base_dir):
                    if potential_scan_id.startswith("."):
                        continue
                    details = manager.get_domain_details(potential_scan_id, domain)
                    if details:
                        break
        else:
            # Check if we have cached details for specific scan
            details = manager.get_domain_details(scan_id, domain)
        
        if not details:
            # Detect tech stack on-demand
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            details = loop.run_until_complete(tech_detector.detect(domain))
            loop.close()
            
            # Save for future (use domain as scan_id if we don't have one)
            save_scan_id = scan_id if scan_id != "all" else domain
            manager.save_domain_details(save_scan_id, domain, details)
        
        return jsonify({"success": True, "details": details})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@main_bp.route("/subdomains/add_from_asn", methods=["POST"])
def add_subdomains_from_asn():
    """Add subdomains from ASN to Subdomains tab."""
    try:
        data = request.get_json()
        scan_id = data.get("scan_id")
        subdomains = data.get("subdomains", [])
        
        manager = get_subdomain_manager()
        success = manager.save_subdomains(scan_id, subdomains, source="asn")
        
        # Auto-start fuzzing for new domains
        if success:
            fuzzer = get_directory_fuzzer()
            threading.Thread(
                target=run_async_in_thread,
                args=(fuzzer.auto_fuzz_queue(scan_id, subdomains),)
            ).start()
        
        return jsonify({"success": success})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# NEW ROUTES - Fuzzing
@main_bp.route("/fuzzing/start/<scan_id>/<domain>", methods=["POST"])
def start_fuzzing(scan_id, domain):
    """Start directory fuzzing for a domain."""
    try:
        fuzzer = get_directory_fuzzer()
        
        # Start fuzzing in background
        threading.Thread(
            target=run_async_in_thread,
            args=(fuzzer.fuzz_domain(scan_id, domain),)
        ).start()
        
        return jsonify({"success": True, "status": "started"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@main_bp.route("/fuzzing/results/<scan_id>/<domain>", methods=["GET"])
def get_fuzzing_results(scan_id, domain):
    """Get fuzzing results for a domain."""
    try:
        fuzzer = get_directory_fuzzer()
        
        # Get filters
        status_filter = request.args.get("status_filter")
        search_term = request.args.get("search")
        
        results = fuzzer.get_results(scan_id, domain, status_filter, search_term)
        status = fuzzer.get_fuzzing_status(domain) or "completed"
        
        return jsonify({
            "success": True,
            "status": status,
            "results": results,
            "total": len(results)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# NEW ROUTES - Crawler
@main_bp.route("/crawler/start/<scan_id>/<domain>", methods=["POST"])
def start_crawler(scan_id, domain):
    """Start crawler for a domain."""
    try:
        crawler = get_crawler_helper()
        
        # Start crawler in background
        async def run_crawler():
            results = await crawler.run_katana(domain)
            crawler.save_crawler_results(scan_id, domain, results)
        
        threading.Thread(
            target=run_async_in_thread,
            args=(run_crawler(),)
        ).start()
        
        return jsonify({"success": True, "status": "started"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@main_bp.route("/crawler/results/<scan_id>/<domain>", methods=["GET"])
def get_crawler_results(scan_id, domain):
    """Get crawler results for a domain."""
    try:
        crawler = get_crawler_helper()
        results = crawler.get_crawler_results(scan_id, domain)
        
        if results:
            return jsonify({"success": True, "results": results})
        else:
            return jsonify({"success": False, "error": "No results found"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# EXISTING ROUTES (keep all existing routes below)
@main_bp.route("/start_scan", methods=["POST"])
def start_scan():
    """Start a new scan with input validation and user-friendly error messages."""
    from .validators import (validate_domain, validate_asn_list, validate_file_upload, 
                             validate_scan_rate, get_friendly_error)
    from .error_handlers import api_error_handler
    
    mode = request.form.get("mode")
    
    if not mode:
        return jsonify({"error": "⚠️ Please select a scan mode"}), 400
    
    target = None
    bgp_url = request.form.get("bgp_url")
    
    # Validate scan rate
    masscan_rate_str = request.form.get("masscan_rate", "10000")
    valid, msg, masscan_rate = validate_scan_rate(masscan_rate_str)
    if not valid:
        return jsonify({"error": msg}), 400
    
    masscan_chunks = int(request.form.get("masscan_chunks", 0))
    
    if not os.path.exists("Tmp"):
        os.makedirs("Tmp")
    
    # Validate input based on scan mode
    if mode == "recon":
        domain_input = request.form.get("domain", "").strip()
        valid, result = validate_domain(domain_input)
        if not valid:
            return jsonify({"error": result}), 400
        target = result
        
    elif mode == "asn_list":
        asns_input = request.form.get("asns", "").strip()
        valid, msg, asn_list = validate_asn_list(asns_input)
        if not valid:
            return jsonify({"error": msg}), 400
        target = ",".join(asn_list)  # Use normalized ASN list
        
    elif mode in ["masscan_file", "ip_file"]:
        if 'file' not in request.files:
            return jsonify({"error": get_friendly_error("file_not_selected")}), 400
        
        file = request.files['file']
        valid, msg = validate_file_upload(file)
        if not valid:
            return jsonify({"error": msg}), 400
        
        filename = secure_filename(file.filename)
        save_path = os.path.join("Tmp", filename)
        
        try:
            file.save(save_path)
        except Exception as e:
            return jsonify({"error": f"📁 Failed to save file: {str(e)}"}), 500
        
        target = save_path
    
    else:
        return jsonify({"error": f"⚠️ Unknown scan mode: {mode}"}), 400
    
    # Reset Status
    global scan_status, scan_logs, scan_context
    scan_status.update({
        "phase": "🚀 Initializing scan...", 
        "masscan_progress": 0, "masscan_total": 0, 
        "masscan_ranges_done": 0, "masscan_ranges_total": 0, 
        "masscan_chunks_status": [], 
        "extraction_progress": 0, "extraction_total": 0, 
        "found_count": 0, "active_threads": 0,
        "estimated_remaining": "Calculating..."
    })
    scan_logs = [f"✅ Scan started - Mode: {mode.upper()}", f"🎯 Target: {target}"]
    
    # Reset Context
    scan_context["stop_event"].clear()
    scan_context["keep_files"] = False
    
    # Run the core logic in a separate thread
    try:
        t = threading.Thread(
            target=run_async_in_thread, 
            args=(core.run_scan_logic(mode, target, 50, bgp_url, masscan_rate, masscan_chunks, scan_context),)
        )
        t.daemon = True
        t.start()
        
        return jsonify({
            "status": "started",
            "message": f"✅ Scan started successfully! Target: {target}"
        })
    
    except Exception as e:
        log_message(f"❌ Failed to start scan: {str(e)}")
        return jsonify({"error": f"❌ Failed to start scan: {str(e)}"}), 500


@main_bp.route("/stop_scan", methods=["POST"])
def stop_scan():
    data = request.get_json() or {}
    keep_files = data.get("save", False)
    
    scan_context["keep_files"] = keep_files
    scan_context["stop_event"].set()
    
    # Force kill masscan immediately
    try:
        subprocess.run(["sudo", "killall", "masscan"], capture_output=True)
    except Exception: 
        pass
        
    scan_status["phase"] = "Stopping..."
    return jsonify({"status": "stopped"})

@main_bp.route("/get_status", methods=["GET"])
def get_status_route():
    return jsonify(scan_status)

@main_bp.route("/update_status", methods=["POST"])
def update_status_route():
    global scan_status
    data = request.get_json()
    if data:
        if "chunk_update" in data:
            update = data.pop("chunk_update")
            idx = update.get("id")
            
            if idx is not None and "masscan_chunks_status" in scan_status:
                existing = None
                for chunk in scan_status["masscan_chunks_status"]:
                    if chunk.get("id") == idx:
                        existing = chunk
                        break
                
                if existing:
                    for k, v in update.items():
                        existing[k] = v
                else:
                    scan_status["masscan_chunks_status"].append(update)
        
        for k, v in data.items():
            if k == "masscan_chunks_status" and not v and scan_status.get("masscan_chunks_status"):
                 continue
            scan_status[k] = v
            
    return jsonify({"status": "ok"})

@main_bp.route("/log_update", methods=["POST"])
def log_message():
    data = request.get_json()
    msg = data.get("log") or data.get("message")
    if msg:
        scan_logs.append(msg)
        if len(scan_logs) > 1000: 
            scan_logs.pop(0)
    return jsonify({"status": "ok"})

@main_bp.route("/get_logs", methods=["GET"])
def get_logs_route():
    # Return list directly to match frontend expectation
    return jsonify(scan_logs)

@main_bp.route("/search/title", methods=["GET"])
def search_title():
    """Legacy search endpoint for results.html - searches MongoDB extraction_results"""
    query = request.args.get("q", "")
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    
    results = []
    
    # Try MongoDB extraction_results collection first
    try:
        if hasattr(current_app, 'db') and current_app.db is not None:
            if query:
                # Search with regex pattern
                cursor = current_app.db.extraction_results.find({
                    "$or": [
                        {"title": {"$regex": query, "$options": "i"}},
                        {"domain": {"$regex": query, "$options": "i"}},
                        {"ip": {"$regex": query, "$options": "i"}}
                    ]
                }).limit(per_page * page)
            else:
                # Get all results
                cursor = current_app.db.extraction_results.find().limit(per_page * page)
            
            results = list(cursor)
            
            # Clean up MongoDB _id field and format for frontend
            for r in results:
                if '_id' in r:
                    del r['_id']
                # Flatten nested structures for compatibility
                if 'ssl_info' in r and r['ssl_info'].get('jarm_hash'):
                    r['jarm_hash'] = r['ssl_info']['jarm_hash']
                if 'fingerprints' in r and r['fingerprints'].get('favicon_hash'):
                    r['favicon_hash'] = r['fingerprints']['favicon_hash']
                    
    except Exception as e:
        print(f"MongoDB search error: {e}")
    
    # If no MongoDB results, fallback to subdomain search
    if not results:
        manager = get_subdomain_manager()
        
        # Query subdomains collection directly
        try:
            if hasattr(current_app, 'db') and current_app.db is not None:
                if query:
                    cursor = current_app.db.subdomains.find({
                        "domain": {"$regex": query, "$options": "i"}
                    }).limit(per_page * page)
                else:
                    cursor = current_app.db.subdomains.find().limit(per_page * page)
                
                subdomains = list(cursor)
                
                # Format for results.html
                for r in subdomains:
                    if '_id' in r:
                        del r['_id']
                    results.append({
                        "domain": r.get("domain"),
                        "ip": r.get("ip", "N/A"),
                        "title": f"Subdomain: {r.get('domain')}",
                        "status_code": r.get("status_code", 200),
                        "technologies": r.get("technologies", []),
                        "source": r.get("source", "recon"),
                        "port": r.get("port", "N/A"),
                        "request": f"https://{r.get('domain')}",
                        "favicon_hash": r.get("favicon_hash", "N/A")
                    })
        except Exception as e:
            print(f"Subdomain search fallback error: {e}")
        
    return jsonify(results)

@main_bp.route("/insert", methods=["POST"])
def insert_results():
    """Receive and save detailed extraction results to extraction_results collection."""
    try:
        from datetime import datetime
        results = request.get_json()
        if not results or not isinstance(results, list):
             return jsonify({"status": "error", "message": "Invalid format"})
             
        manager = get_subdomain_manager()
        count = 0
        timestamp = datetime.now().isoformat()
        
        for item in results:
            # Extract inner data (schema agnostic)
            data = None
            # Handle list wrapper if present
            if isinstance(item, list) and len(item) > 0:
                item = item[0]
                
            for key in ['http_responseForIP', 'https_responseForIP', 'http_responseForDomainName', 'https_responseForDomainName']:
                if key in item:
                    data = item[key]
                    if isinstance(data, list) and len(data) > 0:
                        data = data[0]
                    break
            
            if not data: continue
            
            domain = data.get("domain")
            ip = data.get("ip")
            port = data.get("port")
            if not ip or not port: continue
            
            scan_id = domain if domain else f"{ip}:{port}"
            
            # Build extraction result document according to schema
            extraction_doc = {
                "scan_id": scan_id,
                "ip": ip,
                "port": port,
                "protocol": "https" if port in [443, 8443, 4443] else "http",
                "domain": domain,
                "request": data.get("request"),
                "title": data.get("title"),
                "status_code": data.get("status_code"),
                "response_time_ms": data.get("response_time_ms"),
                "content_length": data.get("content_length"),
                
                "technologies": data.get("technologies", []),
                "waf": data.get("waf"),
                
                "ssl_info": {},
                "fingerprints": {},
                "response_headers": data.get("response_headers", {}),
                
                "redirected_url": data.get("redirected_url"),
                "final_status_code": data.get("final_status_code", data.get("status_code")),
                
                "discovered_at": timestamp,
                "last_probed": timestamp,
                
                "source_context": {
                    "from_asn": False,  # Will be updated when ASN support is added
                    "from_subdomain_enum": domain is not None,
                    "discovery_method": "masscan"
                }
            }
            
            # Add SSL info if available
            if data.get("jarm_hash"):
                extraction_doc["ssl_info"]["jarm_hash"] = data["jarm_hash"]
            if data.get("cert_subject"):
                extraction_doc["ssl_info"]["cert_subject"] = data["cert_subject"]
            if data.get("cert_issuer"):
                extraction_doc["ssl_info"]["cert_issuer"] = data["cert_issuer"]
                
            # Add fingerprints
            if data.get("favicon_hash"):
                extraction_doc["fingerprints"]["favicon_hash"] = data["favicon_hash"]
            if data.get("favicon_url"):
                extraction_doc["fingerprints"]["favicon_url"] = data["favicon_url"]
            
            # Save to MongoDB extraction_results collection
            try:
                if hasattr(current_app, 'db') and current_app.db is not None:
                    current_app.db.extraction_results.update_one(
                        {"scan_id": scan_id, "ip": ip, "port": port},
                        {"$set": extraction_doc, "$setOnInsert": {"discovered_at": timestamp}},
                        upsert=True
                    )
            except Exception as e:
                print(f"MongoDB extraction save error: {e}")
            
            # Save details to file (legacy compatibility)
            if domain:
                manager.save_domain_details(domain, domain, data)
                
                # Also update subdomain info
                sub_update = {
                    "domain": domain,
                    "ip": ip,
                    "status_code": data.get("status_code"),
                    "technologies": data.get("technologies", [])
                }
                manager.save_subdomains(domain, [sub_update], source="extraction")
            
            count += 1
            
        return jsonify({"status": "ok", "processed": count})
    except Exception as e:
        print(f"Insert error: {e}")
        return jsonify({"status": "error", "error": str(e)})

@main_bp.route("/export", methods=["POST"])
def export_results():
    """Handle export notification from core logic."""
    try:
        data = request.get_json()
        filename = data.get("filename")
        # In the future, we could trigger a UI notification here
        return jsonify({"status": "received", "filename": filename})
    except Exception as e:
         return jsonify({"status": "error", "error": str(e)})

@main_bp.route("/search/advanced", methods=["POST"])
def search_advanced():
    """Advanced search endpoint with MongoDB support for extraction_results"""
    data = request.get_json()
    filters = data.get("filters", [])
    
    results = []
    
    # Try MongoDB extraction_results first
    try:
        if hasattr(current_app, 'db') and current_app.db is not None:
            mongo_query = {}
            
            for f in filters:
                field = f.get("field")
                operator = f.get("operator")
                value = f.get("value")
                
                if not value.strip():
                    continue
                
                if operator == "contains":
                    mongo_query[field] = {"$regex": value, "$options": "i"}
                elif operator == "not_contains":
                    mongo_query[field] = {"$not": {"$regex": value, "$options": "i"}}
                elif operator == "equals":
                    mongo_query[field] = value
                elif operator == "not_equals":
                    mongo_query[field] = {"$ne": value}
            
            cursor = current_app.db.extraction_results.find(mongo_query).limit(100)
            results = list(cursor)
            
            # Clean up MongoDB _id field and flatten nested structures
            for r in results:
                if '_id' in r:
                    del r['_id']
                # Flatten for compatibility
                if 'ssl_info' in r and r['ssl_info'].get('jarm_hash'):
                    r['jarm_hash'] = r['ssl_info']['jarm_hash']
                if 'fingerprints' in r and r['fingerprints'].get('favicon_hash'):
                    r['favicon_hash'] = r['fingerprints']['favicon_hash']
                    
    except Exception as e:
        print(f"MongoDB advanced search error: {e}")
    
    # Fallback to subdomain collection search
    if not results:
        query = ""
        for f in filters:
            if f["field"] in ["domain", "title"]:
                query = f["value"]
                break
        
        try:
            if hasattr(current_app, 'db') and current_app.db is not None:
                if query:
                    cursor = current_app.db.subdomains.find({
                        "domain": {"$regex": query, "$options": "i"}
                    }).limit(100)
                else:
                    cursor = current_app.db.subdomains.find().limit(100)
                
                subdomains = list(cursor)
                
                for r in subdomains:
                    if '_id' in r:
                        del r['_id']
                    results.append({
                        "domain": r.get("domain"),
                        "ip": r.get("ip", "N/A"),
                        "title": f"Subdomain: {r.get('domain')}",
                        "status_code": r.get("status_code", 200),
                        "technologies": r.get("technologies", []),
                        "source": r.get("source", "recon"),
                        "port": r.get("port", "N/A"),
                        "request": f"https://{r.get('domain')}",
                        "favicon_hash": r.get("favicon_hash", "N/A")
                    })
        except Exception as e:
            print(f"Subdomain search fallback error: {e}")
    
    return jsonify(results)

# ... (keep all other existing routes: fuzzing, results, settings, tools, etc.)

@main_bp.route("/settings/api_keys", methods=["GET"])
def get_api_keys():
    """Get current API key settings (masked)."""
    checker = get_tools_checker()
    settings = checker.get_settings()
    
    masked = {}
    for key, value in settings.items():
        if value:
            masked[key] = "***" + value[-4:] if len(value) > 4 else "***"
        else:
            masked[key] = ""
    
    return jsonify(masked)

@main_bp.route("/settings/save", methods=["POST"])
def save_settings():
    """Save API key settings."""
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400
    
    valid_keys = [
        "SHODAN_API_KEY",
        "SECURITYTRAILS_KEY", "CHAOS_API_KEY", "ZOOMEYE_API_KEY",
        "FOFA_EMAIL", "FOFA_KEY", "VT_API_KEY", "FACEBOOK_CT_TOKEN"
    ]
    
    filtered = {k: v for k, v in data.items() if k in valid_keys and v}
    
    checker = get_tools_checker()
    success = checker.save_settings(filtered)
    
    return jsonify({"success": success})

@main_bp.route("/tools/status", methods=["GET"])
def get_tools_status():
    """Get status of all recon tools."""
    checker = get_tools_checker()
    checker.clear_cache()
    status = checker.get_full_status()
    return jsonify(status)

@main_bp.route("/tools/install", methods=["POST"])
def install_tool():
    """Install a specific tool."""
    data = request.get_json()
    tool_id = data.get("tool_id")
    package_manager = data.get("package_manager", "auto")
    
    if not tool_id:
        return jsonify({"success": False, "message": "No tool_id provided"}), 400
    
    checker = get_tools_checker()
    success, message = checker.install_tool(tool_id, package_manager)
    
    return jsonify({"success": success, "message": message})

# ASN Routes
@main_bp.route("/asn/history", methods=["GET"])
def get_asn_history():
    """Get ASN scan history from MongoDB."""
    try:
        if not hasattr(current_app, 'db') or current_app.db is None:
            return jsonify({"success": False, "error": "Database not available"}), 500
        
        # Get ASN scans from MongoDB (from extraction_results where source is ASN)
        scans = []
        
        # Try to get unique ASN scans
        pipeline = [
            {"$match": {"source_context.from_asn": True}},
            {"$group": {
                "_id": "$scan_id",
                "asn_numbers": {"$first": "$source_context.asn_numbers"},
                "total_ips": {"$sum": 1},
                "servers_found": {"$sum": 1},
                "created_at": {"$first": "$discovered_at"},
                "status": {"$first": "completed"}
            }},
            {"$sort": {"created_at": -1}},
            {"$limit": 50}
        ]
        
        results = list(current_app.db.extraction_results.aggregate(pipeline))
        
        for r in results:
            scans.append({
                "scan_id": r["_id"],
                "asn_numbers": r.get("asn_numbers", []),
                "total_ips": r.get("total_ips", 0),
                "servers_found": r.get("servers_found", 0),
                "created_at": r.get("created_at", ""),
                "status": r.get("status", "completed")
            })
        
        return jsonify({"success": True, "scans": scans})
    except Exception as e:
        current_app.logger.error(f"ASN history error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@main_bp.route("/asn/results/<scan_id>", methods=["GET"])
def get_asn_results(scan_id):
    """Get results for a specific ASN scan."""
    try:
        if not hasattr(current_app, 'db') or current_app.db is None:
            return jsonify({"success": False, "error": "Database not available"}), 500
        
        # Get all results for this scan
        results = list(current_app.db.extraction_results.find({"scan_id": scan_id}))
        
        # Group by IP ranges (simplified - would need proper CIDR calculation)
        ip_ranges = {}
        total_ips = 0
        servers_found = len(results)
        websites_found = len([r for r in results if r.get("domain")])
        
        for r in results:
            ip = r.get("ip", "")
            # Simple grouping by /24 network
            if ip:
                network = ".".join(ip.split(".")[:3]) + ".0/24"
                if network not in ip_ranges:
                    ip_ranges[network] = {
                        "cidr": network,
                        "total_ips": 0,
                        "active_servers": 0,
                        "scan_status": "completed"
                    }
                ip_ranges[network]["total_ips"] += 1
                ip_ranges[network]["active_servers"] += 1
                total_ips += 1
        
        return jsonify({
            "success": True,
            "ip_ranges": list(ip_ranges.values()),
            "total_ips": total_ips,
            "servers_found": servers_found,
            "websites_found": websites_found
        })
    except Exception as e:
        current_app.logger.error(f"ASN results error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
