from flask import Blueprint, render_template, request, jsonify, Response, current_app
import threading
import os
import json
import asyncio
from werkzeug.utils import secure_filename
from .core import core
from bson import json_util
import re
from .core.subdomain_manager import get_subdomain_manager
from .core.job_manager import job_manager

main_bp = Blueprint('main', __name__)

import subprocess
import time

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

@main_bp.route("/asn")
def asn_page():
    return render_template("asn.html")

@main_bp.route("/subdomains")
def subdomains_page():
    return render_template("subdomains.html")

@main_bp.route("/jobs/status", methods=["GET"])
def get_jobs_status():
    return jsonify(job_manager.get_status())

@main_bp.route("/subdomains/list/<scan_id>", methods=["GET"])
def get_subdomains_list(scan_id):
    try:
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
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@main_bp.route("/start_scan", methods=["POST"])
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
        # Check if an IP file was uploaded
        if 'ip_file' in request.files and request.files['ip_file'].filename:
            file = request.files['ip_file']
            filename = f"upload_{int(time.time())}.txt"
            if not os.path.exists("Tmp"): os.makedirs("Tmp")
            file_path = os.path.join("Tmp", filename)
            file.save(file_path)
            target = file_path
            mode = "ip_file" # Override mode for core logic
        else:
            domain_input = request.form.get("domain", "").strip()
            if not domain_input:
                return jsonify({"error": "⚠️ Domain or IP File is required"}), 400
            valid, result = validate_domain(domain_input)
            if not valid:
                return jsonify({"error": result}), 400
            target = result
    
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
    scan_logs = [f"✅ Deep Scan started - Target: {target}"]
    
    scan_context["stop_event"].clear()
    
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
def stop_scan():
    scan_context["stop_event"].set()
    try:
        subprocess.run(["sudo", "killall", "-q", "masscan"], capture_output=True)
    except Exception: pass
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
        for k, v in data.items():
            scan_status[k] = v
    return jsonify({"status": "ok"})

@main_bp.route("/log_update", methods=["POST"])
def log_message():
    data = request.get_json()
    msg = data.get("log") or data.get("message")
    if msg:
        scan_logs.append(msg)
        if len(scan_logs) > 500: scan_logs.pop(0)
    return jsonify({"status": "ok"})

@main_bp.route("/get_logs", methods=["GET"])
def get_logs_route():
    return jsonify(scan_logs)

@main_bp.route("/search/title", methods=["GET"])
def search_title():
    """Search MongoDB extraction_results"""
    query = request.args.get("q", "")
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 50))
    
    total_count = 0
    results = []
    
    try:
        if hasattr(current_app, 'db') and current_app.db is not None:
            mongo_query = {}
            if query:
                mongo_query = {
                    "$or": [
                        {"domain": {"$regex": query, "$options": "i"}},
                        {"ip": {"$regex": query, "$options": "i"}}
                    ]
                }
            total_count = current_app.db.extraction_results.count_documents(mongo_query)
            cursor = current_app.db.extraction_results.find(mongo_query).sort("discovered_at", -1).skip((page - 1) * per_page).limit(per_page)
            results = list(cursor)
            for r in results:
                if '_id' in r: del r['_id']
    except Exception as e:
        print(f"Search error: {e}")
            
    return jsonify({
        "results": results,
        "total": total_count,
        "page": page,
        "per_page": per_page
    })

@main_bp.route("/export", methods=["POST"])
def export_results():
    return jsonify({"status": "ok"})
