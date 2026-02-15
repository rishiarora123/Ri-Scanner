from flask import Blueprint, render_template, request, jsonify, Response, current_app
import threading
import os
import json
import asyncio
import re
import time
import shutil
import subprocess
from datetime import datetime
from werkzeug.utils import secure_filename
from .core import core
from .core.subdomain_manager import get_subdomain_manager
from .core.job_manager import job_manager
from .core.fuzzing_manager import fuzzing_manager
from .error_handlers import api_error_handler

main_bp = Blueprint('main', __name__)

# ── Global Scan State ─────────────────────────────────────────────
scan_status = {
    "phase": "Idle",
    "masscan_progress": 0, "masscan_total": 0,
    "masscan_ranges_done": 0, "masscan_ranges_total": 0,
    "masscan_chunks_status": [],
    "masscan_pct": 0, "masscan_eta": "--", "masscan_status": "Pending",
    "extraction_progress": 0, "extraction_total": 0,
    "naabu_progress": 0, "naabu_total": 0,
    "naabu_pct": 0, "naabu_eta": "--", "naabu_status": "Pending",
    "found_count": 0,
    "active_threads": 0,
    "estimated_remaining": "N/A",
    # FIX: Phase-gate fields — drive the Dashboard UI prompt panel
    "waiting_for_user": False,
    "current_gate": None,
    "next_phase": None,
    "phase1_complete": False,
    "phase1_subdomains_total": 0,
    "phase1_live": 0,
    "phase1_dead": 0,
    "phase1_tools_used": [],
    "phase2_complete": False,
    "phase4_complete": False,
    "phase3_strategy": "sequential",
}
scan_logs = []
scan_context = {
    "stop_event": threading.Event(),
    "keep_files": False,
    # FIX: Phase-gate events — the scan thread blocks on these until
    # the user confirms continuation via /continue_scan.
    "gate_phase2": threading.Event(),   # After Phase 1 → before Phase 2
    "gate_phase4": threading.Event(),   # After Phase 2 → before Phase 4 (ASN)
    "gate_phase3": threading.Event(),   # After Phase 4 → before Phase 3 (Infra)
    "phase3_strategy": "sequential",    # Default scan strategy
}

# Wire shared state into core.py (no HTTP overhead)
core.set_shared_state(scan_status, scan_logs)

SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "settings.json")

def run_async_in_thread(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(coro)
    loop.close()


# ── Page Routes ───────────────────────────────────────────────────

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

@main_bp.route("/asn")
def asn_page():
    return render_template("asn.html")

@main_bp.route("/subdomains")
def subdomains_page():
    return render_template("subdomains.html")


# ── Scan Control ──────────────────────────────────────────────────

@main_bp.route("/start_scan", methods=["POST"])
@api_error_handler
def start_scan():
    from .validators import validate_domain, validate_asn_list, validate_file_upload
    
    mode = request.form.get("mode")
    if not mode:
        return jsonify({"error": "⚠️ Please select a scan mode"}), 400
    
    target = None
    
    try:
        masscan_rate = int(request.form.get("masscan_rate", 10000))
    except (ValueError, TypeError):
        masscan_rate = 10000

    try:
        threads = int(request.form.get("threads", 10))
    except (ValueError, TypeError):
        threads = 10
    
    ports = request.form.get("ports", "80,443").strip().replace(" ", "")
    if not ports: ports = "80,443"
    
    if mode == "recon":
        input_raw = request.form.get("domain", "").strip()
        if not input_raw:
            return jsonify({"error": "⚠️ Target list is required"}), 400
        
        from .core.utils import search_bgp_intel, resolve_asn_to_ips
        import re
        
        targets_raw = re.split(r'[,\s\n]+', input_raw)
        final_targets = []
        
        for item in targets_raw:
            item = item.strip()
            if not item: continue
            
            # 1. BGP URL check
            if "bgp.he.net" in item and item.startswith("http"):
                bgp_data = search_bgp_intel(item)
                # Add scraped IPs
                final_targets.extend(bgp_data.get("ipv4", []))
                # Resolve scraped ASNs
                for asn_obj in bgp_data.get("asns", []):
                    asn = asn_obj["asn"]
                    if asn.startswith("AS"): asn = asn[2:]
                    final_targets.extend(resolve_asn_to_ips(asn))
            
            # 2. IP/CIDR check
            elif re.match(r'^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d+)?$', item):
                final_targets.append(item)
            
            # 3. ASN check
            elif re.match(r'^AS\d+$', item, re.I):
                final_targets.append(item.upper())
            
            # 4. Domain fallback
            else:
                valid, result = validate_domain(item)
                if valid:
                    final_targets.append(result)
        
        if not final_targets:
            return jsonify({"error": "⚠️ No valid targets identified in list"}), 400
            
        target = ",".join(list(set(final_targets))) # Deduplicate
        # mode remains "recon" to trigger Phase 1-4 pipeline in core.py
    
    elif mode == "asn_list":
        asns_input = request.form.get("asns", "").strip()
        valid, msg, asn_list = validate_asn_list(asns_input)
        if not valid:
            return jsonify({"error": msg}), 400
        target = ",".join(asn_list)
    else:
        return jsonify({"error": f"⚠️ Unsupported scan mode: {mode}"}), 400
    
    # Reset Status
    global scan_status, scan_logs, scan_context
    scan_status.update({
        "phase": "🚀 Initializing scan...", 
        "masscan_progress": 0, "masscan_total": 0,
        "masscan_ranges_done": 0, "masscan_ranges_total": 0,
        "naabu_progress": 0, "naabu_total": 0,
        "found_count": 0, "active_threads": threads,
        "estimated_remaining": "Calculating..."
    })
    scan_logs.clear()
    scan_logs.append(f"✅ Deep Scan started - Target: {target}")
    
    scan_context["stop_event"].clear()
    # FIX: Reset all phase gates for the new scan
    scan_context["gate_phase2"].clear()
    scan_context["gate_phase4"].clear()
    scan_context["gate_phase3"].clear()
    scan_context["phase3_strategy"] = "sequential"  # Reset to safe default
    
    try:
        t = threading.Thread(
            target=run_async_in_thread, 
            args=(core.run_scan_logic(mode, target, threads=threads, ports=ports, masscan_rate=masscan_rate, scan_context=scan_context),)
        )
        t.daemon = True
        t.start()
        
        return jsonify({
            "status": "started",
            "message": f"✅ Scan started successfully! Target: {target}"
        })
    except Exception as e:
        return jsonify({"error": f"❌ Failed to start scan: {str(e)}"}), 500


@main_bp.route("/stop_scan", methods=["POST"])
@api_error_handler
def stop_scan():
    data = request.get_json(silent=True) or {}
    scan_context["keep_files"] = data.get("save", False)
    scan_context["stop_event"].set()
    # FIX: Also release all phase gates so the scan thread unblocks and exits
    scan_context["gate_phase2"].set()
    scan_context["gate_phase4"].set()
    scan_context["gate_phase3"].set()
    try:
        subprocess.run(["sudo", "killall", "-q", "masscan"], capture_output=True)
    except Exception: pass
    try:
        subprocess.run(["sudo", "killall", "-q", "naabu"], capture_output=True)
    except Exception: pass
    scan_status["phase"] = "Stopping..."
    scan_status["waiting_for_user"] = False  # FIX: Clear waiting flag on stop
    return jsonify({"status": "stopped"})


# ── FIX: Phase-Gate Control Endpoint ─────────────────────────────────
# Called by the Dashboard UI when the user clicks "Continue" or "Stop".
# Releases the next gate so the scan thread can proceed.

@main_bp.route("/continue_scan", methods=["POST"])
@api_error_handler
def continue_scan():
    """Release the current phase gate so the scan proceeds to the next phase."""
    data = request.get_json(silent=True) or {}
    action = data.get("action", "continue")  # "continue" or "stop"
    phase3_strategy = data.get("phase3_strategy", None)  # Only relevant before Phase 3
    
    if action == "stop":
        # Graceful stop: set stop event + release gates so thread exits
        scan_context["stop_event"].set()
        scan_context["gate_phase2"].set()
        scan_context["gate_phase4"].set()
        scan_context["gate_phase3"].set()
        scan_status["phase"] = "Stopped"
        scan_status["waiting_for_user"] = False
        return jsonify({"status": "stopped"})
    
    # If user provided a Phase 3 strategy, store it
    if phase3_strategy:
        scan_context["phase3_strategy"] = phase3_strategy
    
    # Release whichever gate is currently blocking
    gate_released = None
    for gate_name in ["gate_phase2", "gate_phase4", "gate_phase3"]:
        if not scan_context[gate_name].is_set():
            scan_context[gate_name].set()
            gate_released = gate_name
            break
    
    if gate_released:
        return jsonify({"status": "continued", "gate_released": gate_released})
    else:
        return jsonify({"status": "no_gate_waiting"})


# ── Status & Logs (Direct shared state — no HTTP middleman) ──────

@main_bp.route("/get_status", methods=["GET"])
def get_status_route():
    return jsonify(scan_status)

@main_bp.route("/update_status", methods=["POST"])
@api_error_handler
def update_status_route():
    """Legacy endpoint — status is now updated via shared state, but kept for backward compatibility."""
    data = request.get_json()
    if data:
        for k, v in data.items():
            scan_status[k] = v
    return jsonify({"status": "ok"})

@main_bp.route("/log_update", methods=["POST"])
@api_error_handler
def log_message():
    """Legacy endpoint — logs are now appended via shared state."""
    data = request.get_json()
    msg = data.get("log") or data.get("message")
    if msg:
        scan_logs.append(msg)
        if len(scan_logs) > 500: scan_logs.pop(0)
    return jsonify({"status": "ok"})

@main_bp.route("/get_logs", methods=["GET"])
def get_logs_route():
    return jsonify(scan_logs)


# ── Search (with regex injection fix) ─────────────────────────────

@main_bp.route("/search/title", methods=["GET"])
@api_error_handler
def search_title():
    """Search MongoDB extraction_results, ip_scans, and subdomains (regex-safe)."""
    query = request.args.get("q", "")
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    
    total_count = 0
    results = []
    
    try:
        if hasattr(current_app, 'db') and current_app.db is not None:
            # 1. Search extraction_results
            mongo_query_extract = {}
            if query:
                safe_query = re.escape(query)
                mongo_query_extract = {
                    "$or": [
                        {"domain": {"$regex": safe_query, "$options": "i"}},
                        {"ip": {"$regex": safe_query, "$options": "i"}}
                    ]
                }
            
            # 2. Search ip_scans
            mongo_query_ip = {}
            if query:
                safe_query = re.escape(query)
                mongo_query_ip = {"ip": {"$regex": safe_query, "$options": "i"}}
            
            # 3. Search subdomains (ONLY completed scans with intelligence)
            mongo_query_subdomains = {
                "$and": [
                    {"$or": [{"status_code": {"$exists": True}}, {"last_intelligence_scan": {"$exists": True}}]}
                ]
            }
            if query:
                safe_query = re.escape(query)
                mongo_query_subdomains["$and"].append({
                    "$or": [
                        {"domain": {"$regex": safe_query, "$options": "i"}},
                        {"primary_ip": {"$regex": safe_query, "$options": "i"}}
                    ]
                })
            
            cursor_extract = current_app.db.extraction_results.find(mongo_query_extract)
            extract_results = list(cursor_extract)
            
            cursor_ip = current_app.db.ip_scans.find(mongo_query_ip)
            ip_results = list(cursor_ip)
            
            cursor_subdomains = current_app.db.subdomains.find(mongo_query_subdomains)
            subdomain_results = list(cursor_subdomains)
            
            # Normalize and merge all three collections
            combined = []
            
            for r in extract_results:
                if '_id' in r: del r['_id']
                r['_sort_date'] = r.get('discovered_at', '')
                r['_type'] = 'extraction'
                combined.append(r)
                
            for r in ip_results:
                if '_id' in r: del r['_id']
                r['_sort_date'] = r.get('timestamp', '')
                r['_type'] = 'ip_scan'
                combined.append(r)
            
            for r in subdomain_results:
                if '_id' in r: del r['_id']
                r['_sort_date'] = r.get('collected_at', r.get('last_updated', ''))
                r['_type'] = 'subdomain_intel'
                # Normalize subdomain data for display
                if not r.get('ip'):
                    r['ip'] = r.get('primary_ip', 'N/A')
                if not r.get('port'):
                    r['port'] = 80  # Default
                if not r.get('title'):
                    r['title'] = r.get('domain', 'Subdomain')
                combined.append(r)
                
            # Sort descending by date
            combined.sort(key=lambda x: x.get('_sort_date', ''), reverse=True)
            
            total_count = len(combined)
            
            # Paginate
            start = (page - 1) * per_page
            end = start + per_page
            results = combined[start:end]
            
    except Exception as e:
        print(f"Search error: {e}")
            
    return jsonify({
        "results": results,
        "total": total_count,
        "page": page,
        "per_page": per_page
    })


# ── Export Results ────────────────────────────────────────────────

@main_bp.route("/export", methods=["POST"])
@api_error_handler
def export_results():
    """Export scan results as JSON or CSV."""
    data = request.get_json(silent=True) or {}
    fmt = data.get("format", "json").lower()
    
    try:
        if not hasattr(current_app, 'db') or current_app.db is None:
            return jsonify({"error": "Database not available"}), 500
        
        cursor = current_app.db.extraction_results.find({}).sort("discovered_at", -1).limit(10000)
        results = list(cursor)
        for r in results:
            if '_id' in r: r['_id'] = str(r['_id'])
        
        if fmt == "csv":
            if not results:
                return Response("No results", mimetype="text/csv",
                                headers={"Content-Disposition": "attachment; filename=results.csv"})
            
            # Build CSV
            all_keys = set()
            for r in results:
                all_keys.update(r.keys())
            # Prioritize common columns
            priority = ["ip", "port", "domain", "title", "status_code", "protocol", "asn", "org", "country", "technologies", "discovered_at"]
            ordered_keys = [k for k in priority if k in all_keys]
            ordered_keys += sorted(all_keys - set(ordered_keys))
            
            lines = [",".join(ordered_keys)]
            for r in results:
                row = []
                for k in ordered_keys:
                    val = r.get(k, "")
                    if isinstance(val, (list, dict)):
                        val = json.dumps(val)
                    val = str(val).replace('"', '""')
                    row.append(f'"{val}"')
                lines.append(",".join(row))
            
            csv_content = "\n".join(lines)
            return Response(csv_content, mimetype="text/csv",
                            headers={"Content-Disposition": "attachment; filename=ri_scanner_results.csv"})
        else:
            # JSON export
            return Response(
                json.dumps(results, indent=2, default=str),
                mimetype="application/json",
                headers={"Content-Disposition": "attachment; filename=ri_scanner_results.json"}
            )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Subdomains ────────────────────────────────────────────────────

@main_bp.route("/subdomains/list/<scan_id>", methods=["GET"])
@api_error_handler
def get_subdomains_list(scan_id):
    manager = get_subdomain_manager()
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    filters = {}
    
    source_arg = request.args.get("source")
    if source_arg and source_arg != "all":
        filters["source"] = source_arg
        
    if request.args.get("search"):
        filters["search_term"] = request.args.get("search")
    
    data = manager.get_subdomains(scan_id, filters, page=page, per_page=per_page)
    return jsonify({
        "success": True, 
        "subdomains": data["subdomains"],
        "total": data["total"],
        "page": data["page"],
        "pages": data["pages"]
    })


@main_bp.route("/subdomains/details/<scan_id>/<path:domain>", methods=["GET"])
@api_error_handler
def get_subdomain_details(scan_id, domain):
    """Get detailed info for a specific subdomain."""
    try:
        if not hasattr(current_app, 'db') or current_app.db is None:
            return jsonify({"success": False, "error": "Database not available"}), 500
        
        # Search in subdomains collection first
        sub = current_app.db.subdomains.find_one({"domain": domain})
        if sub and '_id' in sub:
            del sub['_id']
        
        # Also check extraction_results for enriched data
        extraction = current_app.db.extraction_results.find_one({"domain": domain})
        if extraction and '_id' in extraction:
            del extraction['_id']
        
        # Merge data
        details = sub or {}
        if extraction:
            details.update(extraction)
        details["domain"] = domain
        
        return jsonify({"success": True, "details": details})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@main_bp.route("/subdomains/trigger_scan", methods=["POST"])
@api_error_handler
def trigger_scan():
    """Manually trigger intelligence gathering for a specific domain."""
    data = request.get_json()
    domain = data.get("domain")
    if not domain:
        return jsonify({"success": False, "error": "No domain provided"}), 400

    from .core.advanced_recon import AdvancedRecon
    from .core.core import log_event
    import threading
    from datetime import datetime

    def run_deep_scan(target_domain):
        recon = AdvancedRecon()
        log_event(f"🚀 Manual intelligence gathering started for {target_domain}")
        # Run intelligence gathering
        results = recon.gather_intelligence(target_domain)
        # Store results
        if results:
            current_app.db.subdomains.update_one(
                {"domain": target_domain},
                {"$set": results, "$set": {"last_intelligence_scan": datetime.now().isoformat()}},
                upsert=True
            )
            log_event(f"✅ Intelligence gathering completed for {target_domain}")
        else:
            log_event(f"⚠️ Intelligence gathering failed for {target_domain}")

    # Start in background thread
    thread = threading.Thread(target=run_deep_scan, args=(domain,))
    thread.daemon = True
    thread.start()

    return jsonify({"success": True, "message": f"Scan started for {domain}"})


# ── Jobs ──────────────────────────────────────────────────────────

@main_bp.route("/jobs/status", methods=["GET"])
def get_jobs_status():
    return jsonify(job_manager.get_status())


# ── Settings & API Keys ──────────────────────────────────────────

def _load_settings():
    """Load settings from settings.json"""
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as f:
                return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load settings: {e}")
    return {}

def _save_settings(settings):
    """Save settings to settings.json"""
    try:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=2)
        return True
    except Exception as e:
        print(f"[!] Failed to save settings: {e}")
        return False


@main_bp.route("/settings/get", methods=["GET"])
@api_error_handler
def get_settings():
    """Return current API key settings (values masked for security)."""
    settings = _load_settings()
    # Mask values — only show last 4 characters
    masked = {}
    for key, value in settings.items():
        if value and len(str(value)) > 4:
            masked[key] = "•" * (len(str(value)) - 4) + str(value)[-4:]
        else:
            masked[key] = value
    return jsonify(masked)


@main_bp.route("/settings/save", methods=["POST"])
@api_error_handler
def save_settings():
    """Save API key settings."""
    new_settings = request.get_json()
    if not new_settings:
        return jsonify({"success": False, "error": "No data provided"}), 400
    
    # Load existing settings and update
    existing = _load_settings()
    for key, value in new_settings.items():
        if value and not value.startswith("•"):
            # Only update if not a masked value
            existing[key] = value
    
    if _save_settings(existing):
        return jsonify({"success": True, "message": "Settings saved"})
    return jsonify({"success": False, "error": "Failed to save"}), 500


# ── Tools Status ──────────────────────────────────────────────────

TOOL_DEFINITIONS = {
    "recon": {
        "name": "Reconnaissance",
        "icon": "🔍",
        "tools": [
            {"id": "subfinder", "name": "Subfinder", "description": "Subdomain discovery tool", "check_cmd": "subfinder", "install": {"go": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"}},
            {"id": "assetfinder", "name": "Assetfinder", "description": "Find domains and subdomains", "check_cmd": "assetfinder", "install": {"go": "go install github.com/tomnomnom/assetfinder@latest"}},
            {"id": "chaos", "name": "Chaos", "description": "ProjectDiscovery Chaos client", "check_cmd": "chaos", "install": {"go": "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest"}, "requires_api": True, "api_key": "CHAOS_API_KEY"},
        ]
    },
    "scanning": {
        "name": "Port Scanning",
        "icon": "📡",
        "tools": [
            {"id": "masscan", "name": "Masscan", "description": "Fast port scanner", "check_cmd": "masscan", "install": {"brew": "brew install masscan", "apt": "sudo apt install masscan"}},
            {"id": "naabu", "name": "Naabu", "description": "Port scanning tool by ProjectDiscovery", "check_cmd": "naabu", "install": {"go": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"}},
            {"id": "nmap", "name": "Nmap", "description": "Network exploration and security auditing", "check_cmd": "nmap", "install": {"brew": "brew install nmap", "apt": "sudo apt install nmap"}},
        ]
    },
    "analysis": {
        "name": "Analysis",
        "icon": "🔬",
        "tools": [
            {"id": "whois", "name": "Whois", "description": "Domain/IP WHOIS lookup", "check_cmd": "whois", "install": {"brew": "brew install whois", "apt": "sudo apt install whois"}},
            {"id": "dig", "name": "Dig", "description": "DNS lookup utility", "check_cmd": "dig", "install": {"brew": "brew install bind", "apt": "sudo apt install dnsutils"}},
            {"id": "nc", "name": "Netcat", "description": "Network utility for port checking", "check_cmd": "nc", "install": {"brew": "brew install netcat", "apt": "sudo apt install netcat-openbsd"}},
        ]
    }
}


@main_bp.route("/tools/status", methods=["GET"])
@api_error_handler
def check_tools_status():
    """Check which tools are installed and which API keys are configured."""
    settings = _load_settings()
    
    result = {"categories": {}, "summary": {"total": 0, "installed": 0, "missing_cli": 0, "api_ready": 0}}
    
    for cat_id, cat_def in TOOL_DEFINITIONS.items():
        cat_tools = []
        for tool_def in cat_def["tools"]:
            # Check if installed
            installed = shutil.which(tool_def["check_cmd"]) is not None
            
            # Check API key
            requires_api = tool_def.get("requires_api", False)
            api_key_name = tool_def.get("api_key", "")
            api_configured = bool(settings.get(api_key_name)) if requires_api else False
            
            tool_info = {
                "id": tool_def["id"],
                "name": tool_def["name"],
                "description": tool_def["description"],
                "installed": installed,
                "is_api_only": False,
                "requires_api": requires_api,
                "api_configured": api_configured,
                "install_cmds": tool_def.get("install", {})
            }
            cat_tools.append(tool_info)
            
            result["summary"]["total"] += 1
            if installed:
                result["summary"]["installed"] += 1
            else:
                result["summary"]["missing_cli"] += 1
            if requires_api and api_configured:
                result["summary"]["api_ready"] += 1
        
        result["categories"][cat_id] = {
            "name": cat_def["name"],
            "icon": cat_def["icon"],
            "tools": cat_tools
        }
    
    return jsonify(result)


@main_bp.route("/tools/install", methods=["POST"])
@api_error_handler
def install_tool():
    """Install a missing tool - SECURITY: Requires running on localhost only"""
    # SECURITY FIX: Only allow installations from localhost
    if request.remote_addr not in ('127.0.0.1', 'localhost', '::1'):
        return jsonify({"success": False, "message": "Installation only allowed from localhost"}), 403
    
    data = request.get_json()
    tool_id = data.get("tool_id")
    
    if not tool_id:
        return jsonify({"success": False, "message": "No tool_id provided"}), 400
    
    # Find tool definition - SECURITY: Validate tool exists in whitelist
    tool_def = None
    for cat in TOOL_DEFINITIONS.values():
        for t in cat["tools"]:
            if t["id"] == tool_id:
                tool_def = t
                break
    
    if not tool_def:
        return jsonify({"success": False, "message": f"Unknown tool: {tool_id}"}), 404
    
    install_cmds = tool_def.get("install", {})
    if not install_cmds:
        return jsonify({"success": False, "message": "No install command available"}), 400
    
    # Try install commands in order of preference
    for pm, cmd in install_cmds.items():
        try:
            env = os.environ.copy()
            if pm == "go":
                go_bin = os.path.expanduser("~/go/bin")
                env["PATH"] = f"{go_bin}:{env.get('PATH', '')}"
            
            # SECURITY FIX: Use list-based subprocess.run with shell=False 
            # Parse the command safely - these are from hardcoded TOOL_DEFINITIONS
            import shlex
            cmd_list = shlex.split(cmd)
            proc = subprocess.run(cmd_list, capture_output=True, text=True, timeout=300, env=env)
            
            if proc.returncode == 0:
                return jsonify({"success": True, "message": f"Installed via {pm}"})
            else:
                continue
        except subprocess.TimeoutExpired:
            return jsonify({"success": False, "message": "Installation timed out (5 min)"}), 500
        except Exception as e:
            continue
    
    return jsonify({"success": False, "message": "All installation methods failed"}), 500


@main_bp.route("/tools/bgp_search", methods=["GET"])
@api_error_handler
def bgp_search():
    """Search for ASNs or scrape URL."""
    from .core.utils import search_bgp_intel
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"asns": [], "ipv4": []})
    
    results = {"asns": [], "ipv4": []}
    
    def run_search():
        nonlocal results
        results = search_bgp_intel(query)
        
    t = threading.Thread(target=run_search)
    t.start()
    t.join(timeout=15)
    
    return jsonify(results)


# ── Fuzzing ───────────────────────────────────────────────────────

@main_bp.route("/fuzzing/check_tool", methods=["GET"])
@api_error_handler
def check_fuzzing_tool():
    """Check if ffuf is installed."""
    installed = fuzzing_manager.is_ffuf_installed()
    return jsonify({"installed": installed})

@main_bp.route("/fuzzing/start/<scan_id>/<path:domain>", methods=["POST"])
@api_error_handler
def start_fuzzing(scan_id, domain):
    """Start subdirectory fuzzing for a domain."""
    data = request.get_json(silent=True) or {}
    wordlist = data.get("wordlist") # Optional custom wordlist path
    
    # Run async start
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(fuzzing_manager.start_fuzzing(scan_id, domain, wordlist))
    loop.close()
    
    if result.get("success"):
        return jsonify(result)
    else:
        return jsonify(result), 400

@main_bp.route("/fuzzing/stop/<scan_id>/<path:domain>", methods=["POST"])
@api_error_handler
def stop_fuzzing(scan_id, domain):
    """Stop fuzzing for a domain."""
    success = fuzzing_manager.stop_fuzzing(domain, scan_id)
    return jsonify({"success": success})

@main_bp.route("/fuzzing/results/<scan_id>/<path:domain>", methods=["GET"])
@api_error_handler
def get_fuzzing_results(scan_id, domain):
    """Get fuzzing discovered paths."""
    if not hasattr(current_app, 'db') or current_app.db is None:
        return jsonify({"results": []})
    
    # Simple query
    cursor = current_app.db.fuzzing_results.find(
        {"scan_id": scan_id, "domain": domain}
    ).sort("status_code", 1)
    
    results = list(cursor)
    for r in results:
        if '_id' in r: del r['_id']
        
    return jsonify({"results": results})


# ── Subdomain Export ──────────────────────────────────────────────

@main_bp.route("/subdomains/export/<scan_id>", methods=["GET"])
@api_error_handler
def export_subdomains(scan_id):
    """Export subdomains as JSON."""
    try:
        if not hasattr(current_app, 'db') or current_app.db is None:
            return jsonify({"error": "Database not available"}), 500
        
        query = {} if scan_id == "all" else {"scan_id": scan_id}
        cursor = current_app.db.subdomains.find(query).limit(50000)
        results = list(cursor)
        for r in results:
            if '_id' in r: r['_id'] = str(r['_id'])
        
        return Response(
            json.dumps(results, indent=2, default=str),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=subdomains.json"}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── IP-Specific Scanning ──────────────────────────────────────────

@main_bp.route("/api/scan/ip", methods=["POST"])
@api_error_handler
def scan_single_ip():
    """
    Scan a single IP address and return comprehensive intelligence
    
    Request JSON:
    {
        "ip": "1.2.3.4",
        "ports": "80,443,8443",
        "scan_id": "optional-scan-id"
    }
    
    Response includes:
    - Basic IP info (is_private, is_reserved)
    - Reverse DNS / PTR records
    - ASN & ISP information
    - Open ports & services
    - SSL/TLS certificates
    - HTTP headers & technology stack
    - Geolocation data
    - Associated domains
    - CDN/WAF detection
    - Threat intelligence
    - Scan summary
    """
    try:
        data = request.get_json()
        ip = data.get("ip", "").strip()
        ports = data.get("ports", "").strip()
        scan_id = data.get("scan_id", "manual_ip_scan")
        
        # Validate IP format
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": f"Invalid IP address: {ip}"}), 400
        
        from .core.ip_scanner import IPScanner
        
        # Run IP scan in thread
        def run_ip_scan():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            scanner = IPScanner()
            results = loop.run_until_complete(scanner.scan_ip(ip, ports=ports if ports else None))
            loop.close()
            return results
        
        ip_scan_results = run_ip_scan()
        
        # Store results in database
        try:
            current_app.db.ip_scans.insert_one({
                "ip": ip,
                "ports": ports,
                "scan_id": scan_id,
                "results": ip_scan_results,
                "timestamp": datetime.now().isoformat()
            })
        except Exception as db_error:
            pass  # Log but don't fail if DB insert fails
        
        return jsonify({
            "status": "success",
            "ip": ip,
            "scan_id": scan_id,
            "data": ip_scan_results
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@main_bp.route("/api/scan/ip/<ip>", methods=["GET"])
@api_error_handler
def get_ip_scan_results(ip):
    """
    Get previously scanned IP results
    
    Returns: Complete IP scan data
    """
    try:
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": f"Invalid IP address: {ip}"}), 400
        
        # Try to retrieve from database
        result = current_app.db.ip_scans.find_one({"ip": ip}, sort=[("timestamp", -1)])
        
        if result:
            if '_id' in result:
                result['_id'] = str(result['_id'])
            return jsonify({
                "status": "found",
                "data": result
            }), 200
        else:
            return jsonify({
                "status": "not_found",
                "message": f"No scan results found for IP {ip}"
            }), 404
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@main_bp.route("/api/scan/ip/<ip>/quick", methods=["GET"])
@api_error_handler
def quick_ip_scan(ip):
    """
    Quick IP scan - returns cached results or performs fresh scan
    
    Query parameters:
    - force_refresh: bool (force new scan instead of cache)
    
    Response: Quick summary of IP intelligence
    """
    try:
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"error": f"Invalid IP address: {ip}"}), 400
        
        force_refresh = request.args.get("force_refresh", "false").lower() == "true"
        
        # Check cache first if not forcing refresh
        if not force_refresh:
            cached = current_app.db.ip_scans.find_one({"ip": ip}, sort=[("timestamp", -1)])
            if cached:
                if '_id' in cached:
                    cached['_id'] = str(cached['_id'])
                return jsonify({
                    "status": "cached",
                    "data": cached.get("results", {}).get("scan_summary", {})
                }), 200
        
        # Run fresh scan
        from .core.ip_scanner import IPScanner
        
        def run_ip_scan():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            scanner = IPScanner()
            results = loop.run_until_complete(scanner.scan_ip(ip))
            loop.close()
            return results
        
        ip_scan_results = run_ip_scan()
        
        return jsonify({
            "status": "success",
            "data": ip_scan_results.get("scan_summary", {})
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@main_bp.route("/api/batch/scan-ips", methods=["POST"])
@api_error_handler
def batch_scan_ips():
    """
    Batch scan multiple IPs
    
    Request JSON:
    {
        "ips": ["1.2.3.4", "5.6.7.8", "9.10.11.12"],
        "scan_id": "batch-scan-id"
    }
    
    Response: List of scan results for each IP
    """
    try:
        data = request.get_json()
        ips = data.get("ips", [])
        scan_id = data.get("scan_id", "batch_ip_scan")
        
        import ipaddress
        
        # Validate all IPs
        valid_ips = []
        invalid_ips = []
        
        for ip in ips:
            try:
                ipaddress.ip_address(ip.strip())
                valid_ips.append(ip.strip())
            except ValueError:
                invalid_ips.append(ip.strip())
        
        if not valid_ips:
            return jsonify({"error": "No valid IP addresses provided"}), 400
        
        from .core.ip_scanner import IPScanner
        
        # Run batch scan
        def run_batch_scan():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            async def scan_all():
                scanner = IPScanner()
                tasks = [scanner.scan_ip(ip) for ip in valid_ips]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                return results
            
            results = loop.run_until_complete(scan_all())
            loop.close()
            return results
        
        batch_results = run_batch_scan()
        
        # Store results
        try:
            for i, ip in enumerate(valid_ips):
                if not isinstance(batch_results[i], Exception):
                    current_app.db.ip_scans.insert_one({
                        "ip": ip,
                        "scan_id": scan_id,
                        "results": batch_results[i],
                        "batch": True,
                        "timestamp": datetime.now().isoformat()
                    })
        except Exception as db_error:
            pass
        
        # Prepare response
        successful_scans = []
        failed_scans = []
        
        for i, ip in enumerate(valid_ips):
            if isinstance(batch_results[i], Exception):
                failed_scans.append({"ip": ip, "error": str(batch_results[i])})
            else:
                successful_scans.append({
                    "ip": ip,
                    "scan_summary": batch_results[i].get("scan_summary", {})
                })
        
        return jsonify({
            "status": "completed",
            "scan_id": scan_id,
            "total_ips": len(ips),
            "valid_ips": len(valid_ips),
            "invalid_ips": len(invalid_ips),
            "successful_scans": len(successful_scans),
            "failed_scans": len(failed_scans),
            "data": successful_scans,
            "errors": failed_scans
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
