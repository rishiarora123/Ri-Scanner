from pymongo import MongoClient
from datetime import datetime

def inject_dummy_data():
    client = MongoClient("mongodb://localhost:27017")
    db = client.Ripro
    
    domain = "alumni.cuchd.in"
    
    # Comprehensive intelligence data mapping to all 7 tabs
    intel_data = {
        "domain": domain,
        "ip": "52.74.41.140",
        "primary_ip": "52.74.41.140",
        "status_code": 200,
        "response_time_ms": 142,
        "title": "Alumni Association - Chandigarh University",
        "http_headers": {
            "Server": "nginx/1.18.0 (Ubuntu)",
            "Date": "Sun, 15 Feb 2026 18:00:00 GMT",
            "Content-Type": "text/html; charset=UTF-8",
            "Connection": "keep-alive",
            "X-Powered-By": "PHP/7.4.3",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
        },
        "technologies": ["PHP", "Nginx", "jQuery", "Bootstrap", "Google Analytics", "MySQL", "Ubuntu", "WordPress"],
        "endpoints": [
            "/login.php",
            "/register.php",
            "/events/",
            "/gallery/",
            "/contact-us.php",
            "/api/v1/alumni/list",
            "/assets/js/main.js",
            "/.well-known/security.txt"
        ],
        "api_endpoints": [
            "/api/v1/auth/login",
            "/api/v1/members/profile",
            "/api/v2/events/register",
            "/api/v1/notifications",
            "/api/v3/search"
        ],
        "waf": "Cloudflare WAF",
        "cdn": "Cloudflare",
        "asn": "AS133982",
        "org": "Chandigarh University",
        "country": "IN",
        "ssl_info": {
            "issuer": "Cloudflare Inc ECC CA-3",
            "valid_until": "Dec 31, 2026",
            "valid": True
        },
        "dns_records": {
            "A": ["52.74.41.140"],
            "CNAME": ["cuchd.in"],
            "MX": ["mail.cuchd.in"]
        },
        "last_intelligence_scan": datetime.now().isoformat(),
        "source": "subdomain",
        "waf_detected": "Cloudflare WAF",
        "ssl_certificate": {"valid": True, "issuer": "Cloudflare"}
    }
    
    # Update both collections
    db.subdomains.update_one({"domain": domain}, {"$set": intel_data}, upsert=True)
    db.extraction_results.update_one({"domain": domain}, {"$set": intel_data}, upsert=True)
    
    print(f"[+] FORCE Injected intelligence data for {domain}")

if __name__ == "__main__":
    inject_dummy_data()
