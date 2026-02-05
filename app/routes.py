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
from .core.fuzzer_helper import AsyncFuzzer
from .core.tools_checker import get_tools_checker

# Global state for active scans and fuzzing
ACTIVE_FUZZ_JOBS = {}
FUZZ_RESULTS = [] # Snapshot of latest hits for dashboard

# Global Context
scan_status = {
    "phase": "Idle",
    "masscan_progress": 0,
    "masscan_total": 0,
    "masscan_ranges_done": 0,
    "masscan_ranges_total": 0,
    "masscan_chunks_status": [],  # List of {id, status, ip_ranges, total, processed}
    "extraction_progress": 0,
    "extraction_total": 0,
    "found_count": 0,
    "active_threads": 0,
    "estimated_remaining": "N/A"
}
scan_logs = []
# Context acts as a mutable shared object
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

@main_bp.route("/start_scan", methods=["POST"])
def start_scan():
    mode = request.form.get("mode")
    target = None
    bgp_url = request.form.get("bgp_url")
    masscan_rate = int(request.form.get("masscan_rate", 10000))
    masscan_chunks = int(request.form.get("masscan_chunks", 0))
    
    if not os.path.exists("Tmp"):
        os.makedirs("Tmp")

    if mode == "recon":
        target = request.form.get("domain")
    elif mode == "asn_list":
        target = request.form.get("asns")
    elif mode in ["masscan_file", "ip_file"]:
        if 'file' not in request.files:
            return "No file uploaded", 400
        file = request.files['file']
        if file.filename == '':
            return "No selected file", 400
        
        filename = secure_filename(file.filename)
        save_path = os.path.join("Tmp", filename)
        file.save(save_path)
        target = save_path

    # Reset Status
    global scan_status, scan_logs, scan_context
    scan_status.update({
        "phase": "Initializing...", 
        "masscan_progress": 0, "masscan_total": 0, 
        "masscan_ranges_done": 0, "masscan_ranges_total": 0, 
        "masscan_chunks_status": [], 
        "extraction_progress": 0, "extraction_total": 0, 
        "found_count": 0, "active_threads": 0,
        "estimated_remaining": "Calculating..."
    })
    scan_logs = []

    # Reset Context
    scan_context["stop_event"].clear()
    scan_context["keep_files"] = False
    
    # Run the core logic in a separate thread
    t = threading.Thread(target=run_async_in_thread, args=(core.run_scan_logic(mode, target, 50, bgp_url, masscan_rate, masscan_chunks, scan_context),))
    t.start()

    return jsonify({"status": "started"})

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
                # Find existing chunk or create placeholder
                existing = None
                for chunk in scan_status["masscan_chunks_status"]:
                    if chunk.get("id") == idx:
                        existing = chunk
                        break
                
                if existing:
                    # Update existing chunk with new data
                    for k, v in update.items():
                        existing[k] = v
                else:
                    # Add new chunk
                    scan_status["masscan_chunks_status"].append(update)
        
        # Merge dicts
        for k, v in data.items():
            if k == "masscan_chunks_status" and not v and scan_status.get("masscan_chunks_status"):
                 continue # Don't overwrite existing chunks with empty list
            scan_status[k] = v
            
    return jsonify({"status": "ok"})

@main_bp.route("/log_update", methods=["POST"]) # Renamed from /log to be distinct
def log_message():
    data = request.get_json()
    msg = data.get("log") or data.get("message")
    if msg:
        scan_logs.append(msg)
        if len(scan_logs) > 1000: 
            scan_logs.pop(0)
    return jsonify({"status": "ok"})

@main_bp.route("/get_logs", methods=["GET"])
def get_logs():
    return jsonify(scan_logs)

@main_bp.route("/export", methods=["POST"])
def export_data():
    try:
        # Check database availability
        if current_app.db is None:
            return jsonify({"error": "Database unavailable"}), 503
            
        data = request.get_json()
        filename = data.get("filename")
        if not filename:
            return jsonify({"error": "Filename is required"}), 400
        
        # Sanitize filename to prevent path traversal
        safe_filename = secure_filename(os.path.basename(filename))
        if not safe_filename:
            safe_filename = "export.json"
        
        # Ensure .json extension
        if not safe_filename.endswith('.json'):
            safe_filename += '.json'
        
        # Restrict exports to Tmp directory
        if not os.path.exists("Tmp"):
            os.makedirs("Tmp")
        safe_path = os.path.join("Tmp", safe_filename)
            
        cursor = current_app.db["sslchecker"].find({}, {"_id": 0})
        results = list(cursor)
        
        with open(safe_path, 'w') as f:
            json.dump(results, f, indent=4, default=json_util.default)
            
        return jsonify({"status": "exported", "count": len(results), "path": os.path.abspath(safe_path)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main_bp.route("/insert", methods=["POST"])
def insert():
    try:
        # Check database availability
        if current_app.db is None:
            return jsonify({"error": "Database unavailable"}), 503
            
        results_json = request.get_json()
        if results_json:
            current_app.db["sslchecker"].insert_many(results_json)
        return jsonify({"message": "Inserted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Search Endpoints ---

@main_bp.route("/search/title", methods=["GET"])
def search_title():
    try:
        # Check database availability
        if current_app.db is None:
            return jsonify({"error": "Database unavailable"}), 503
            
        query = request.args.get("q", "").strip()
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))
        
        # Clamp values
        page = max(1, page)
        per_page = min(max(10, per_page), 200)
        skip = (page - 1) * per_page
        
        if not query:
            # Return recent results if no query
            total = current_app.db["sslchecker"].count_documents({})
            results = list(current_app.db["sslchecker"].find({}, {"_id": 0}).sort("_id", -1).skip(skip).limit(per_page))
        else:
            regex = Regex(rf".*{re.escape(query)}.*", "i")
            db_query = {
                "$or": [
                    {"http_responseForIP.title": regex},
                    {"https_responseForIP.title": regex},
                    {"http_responseForDomainName.title": regex},
                    {"https_responseForDomainName.title": regex},
                    {"http_responseForIP.domain": regex},
                    {"https_responseForIP.domain": regex},
                    {"http_responseForIP.ip": regex},
                    {"http_responseForIP.port": regex},
                    {"https_responseForIP.port": regex},
                ]
            }
            total = current_app.db["sslchecker"].count_documents(db_query)
            results = list(current_app.db["sslchecker"].find(db_query, {"_id": 0}).skip(skip).limit(per_page))
        
        total_pages = (total + per_page - 1) // per_page if total > 0 else 1
        
        return jsonify({
            "results": results,
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages
        })
    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500


@main_bp.route("/search/advanced", methods=["POST"])
def search_advanced():
    """
    Advanced search with filters and pagination support.
    
    Request body:
    {
        "filters": [
            {"field": "title", "operator": "contains", "value": "login"},
            {"field": "waf", "operator": "equals", "value": "Cloudflare"},
            {"field": "ip", "operator": "not_contains", "value": "192.168"}
        ],
        "page": 1,
        "per_page": 50
    }
    
    Operators: equals, not_equals, contains, not_contains
    Fields: title, ip, domain, waf, technologies, port, jarm_hash, favicon_hash, status_code
    """
    try:
        # Check database availability
        if current_app.db is None:
            return jsonify({"error": "Database unavailable"}), 503
            
        data = request.get_json() or {}
        filters = data.get("filters", [])
        
        # Parse pagination from request body or query params
        page = int(data.get("page", request.args.get("page", 1)))
        per_page = int(data.get("per_page", request.args.get("per_page", 50)))
        
        # Clamp values
        page = max(1, page)
        per_page = min(max(10, per_page), 200)
        skip = (page - 1) * per_page
        
        if not filters:
            # Return recent results if no filters
            total = current_app.db["sslchecker"].count_documents({})
            results = list(current_app.db["sslchecker"].find({}, {"_id": 0}).sort("_id", -1).skip(skip).limit(per_page))
            total_pages = (total + per_page - 1) // per_page if total > 0 else 1
            return jsonify({
                "results": results,
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": total_pages
            })
        
        # Build MongoDB query from filters
        query_conditions = []
        
        for f in filters:
            field = f.get("field", "").strip()
            operator = f.get("operator", "contains")
            value = f.get("value", "").strip()
            
            if not field or not value:
                continue
            
            # Map field names to possible document paths
            field_paths = _get_field_paths(field)
            
            # Handle numeric types for exact matches
            processed_value = value
            if field in ["status_code", "port"]:
                try:
                    processed_value = int(value)
                except ValueError:
                    pass
            
            # Build condition based on operator
            if operator == "equals":
                condition = {"$or": [{path: processed_value} for path in field_paths]}
            elif operator == "not_equals":
                condition = {"$and": [{path: {"$ne": processed_value}} for path in field_paths]}
            elif operator == "contains":
                # For numeric fields, 'contains' acts like 'equals' if it's an integer
                if isinstance(processed_value, int):
                    condition = {"$or": [{path: processed_value} for path in field_paths]}
                else:
                    regex = Regex(rf".*{re.escape(value)}.*", "i")
                    condition = {"$or": [{path: regex} for path in field_paths]}
            elif operator == "not_contains":
                if isinstance(processed_value, int):
                    condition = {"$and": [{path: {"$ne": processed_value}} for path in field_paths]}
                else:
                    regex = Regex(rf".*{re.escape(value)}.*", "i")
                    condition = {"$and": [{path: {"$not": regex}} for path in field_paths]}
            else:
                continue
            
            query_conditions.append(condition)
        
        # Combine all conditions with AND
        if query_conditions:
            db_query = {"$and": query_conditions}
        else:
            db_query = {}
        
        total = current_app.db["sslchecker"].count_documents(db_query)
        results = list(current_app.db["sslchecker"].find(db_query, {"_id": 0}).skip(skip).limit(per_page))
        total_pages = (total + per_page - 1) // per_page if total > 0 else 1
        
        return jsonify({
            "results": results,
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages
        })
        
    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500


@main_bp.route("/fuzz/start", methods=["POST"])
def start_fuzz():
    """
    Starts an asynchronous fuzzing job for selected targets.
    """
    try:
        data = request.get_json() or {}
        targets = data.get("targets", [])
        if not targets:
            return jsonify({"error": "No targets selected"}), 400

        job_id = str(int(time.time()))
        ACTIVE_FUZZ_JOBS[job_id] = {
            "status": "running",
            "targets": targets,
            "results_count": 0,
            "start_time": time.time()
        }

        # Start background thread for asyncio fuzzer
        def run_fuzzer_thread(app, targets_list, job_id_str):
            with app.app_context():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                wordlist = os.path.join(app.root_path, "static", "wordlists", "common.txt")
                fuzzer = AsyncFuzzer(targets_list, wordlist)
                
                async def progress_cb(target, result):
                    # Store in Redis/Global
                    FUZZ_RESULTS.insert(0, result)
                    if len(FUZZ_RESULTS) > 100: FUZZ_RESULTS.pop()
                    
                    ACTIVE_FUZZ_JOBS[job_id_str]["results_count"] += 1
                    
                    # Update MongoDB
                    try:
                        # Find which document contains this target (could be IP or URL)
                        query = {"$or": [
                            {"http_responseForIP.request": target},
                            {"https_responseForIP.request": target},
                            {"http_responseForDomainName.request": target},
                            {"https_responseForDomainName.request": target},
                            {"http_responseForIP.ip": target},
                            {"https_responseForIP.ip": target}
                        ]}
                        app.db["sslchecker"].update_one(query, {"$addToSet": {"fuzz_results": result}})
                    except Exception as e:
                        print(f"DB Update Error (Fuzz): {e}")

                try:
                    loop.run_until_complete(fuzzer.run(progress_callback=progress_cb))
                    ACTIVE_FUZZ_JOBS[job_id_str]["status"] = "completed"
                except Exception as e:
                    print(f"Fuzzer Job Error: {e}")
                    ACTIVE_FUZZ_JOBS[job_id_str]["status"] = "failed"
                finally:
                    loop.close()

        # Get the actual app object from the proxy
        app_instance = current_app._get_current_object()
        thread = threading.Thread(target=run_fuzzer_thread, args=(app_instance, targets, job_id))
        thread.daemon = True
        thread.start()

        return jsonify({"job_id": job_id, "message": "Fuzzing started"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@main_bp.route("/fuzz/status", methods=["GET"])
def get_fuzz_status():
    """Returns status of all fuzzing jobs and recent hits."""
    return jsonify({
        "jobs": ACTIVE_FUZZ_JOBS,
        "recent_hits": FUZZ_RESULTS[:20]
    })


def _get_field_paths(field: str) -> list:
    """Map a field name to its possible paths in the document."""
    base_paths = [
        "http_responseForIP",
        "https_responseForIP", 
        "http_responseForDomainName",
        "https_responseForDomainName"
    ]
    
    # Some fields need nested access, some are at list level
    if field in ["title", "ip", "domain", "port", "jarm_hash", "favicon_hash", "waf", "request", "redirected_url", "status_code"]:
        paths = []
        for base in base_paths:
            paths.append(f"{base}.{field}")
            # Also check if it's an array (http can return multiple ports)
            paths.append(f"{base}.0.{field}")
        return paths
    elif field == "technologies":
        # Technologies is an array field
        paths = []
        for base in base_paths:
            paths.append(f"{base}.technologies")
            paths.append(f"{base}.0.technologies")
        return paths
    else:
        return [field]


@main_bp.route("/result/<result_id>", methods=["GET"])
def get_result_detail(result_id):
    """Get full details for a specific result."""
    try:
        from bson import ObjectId
        result = current_app.db["sslchecker"].find_one({"_id": ObjectId(result_id)})
        if result:
            result["_id"] = str(result["_id"])
            return jsonify(result)
        return jsonify({"error": "Not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==================== SETTINGS & TOOLS MANAGEMENT ====================

@main_bp.route("/settings/get", methods=["GET"])
def get_settings():
    """Get current API key settings (values are masked for security)."""
    checker = get_tools_checker()
    settings = checker.get_settings()
    
    # Mask sensitive values except for indication if set
    masked = {}
    for key, value in settings.items():
        if value:
            # Show first 4 and last 4 chars only
            if len(value) > 12:
                masked[key] = value[:4] + "*" * 8 + value[-4:]
            else:
                masked[key] = value  # Short values shown as-is
        else:
            masked[key] = ""
    
    return jsonify(masked)


@main_bp.route("/settings/save", methods=["POST"])
def save_settings():
    """Save API key settings."""
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "error": "No data provided"}), 400
    
    # Filter only valid API key settings
    valid_keys = [
        "SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET",
        "SECURITYTRAILS_KEY", "CHAOS_API_KEY", "ZOOMEYE_API_KEY",
        "FOFA_EMAIL", "FOFA_KEY", "VT_API_KEY", "FACEBOOK_CT_TOKEN"
    ]
    
    filtered = {k: v for k, v in data.items() if k in valid_keys and v}
    
    checker = get_tools_checker()
    success = checker.save_settings(filtered)
    
    return jsonify({"success": success})


@main_bp.route("/tools/status", methods=["GET"])
def get_tools_status():
    """Get status of all recon tools (installed, API keys, etc.)."""
    checker = get_tools_checker()
    checker.clear_cache()  # Force fresh check
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
