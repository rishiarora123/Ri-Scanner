"""
Ri-Scanner Pro - Flask Application Factory

Professional security reconnaissance tool with MongoDB integration.
"""
import os
from flask import Flask, jsonify
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use system env vars


def create_app():
    """
    Create and configure the Flask application.
    
    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__)
    
    # Configuration from environment variables with defaults
    app.config.update(
        MONGO_URI=os.getenv("MONGO_URI", "mongodb://localhost:27017/"),
        MONGO_DB=os.getenv("MONGO_DB", "Ripro"),
        SECRET_KEY=os.getenv("SECRET_KEY", os.urandom(24).hex()),
    )
    
    # Initialize MongoDB connection
    _init_db(app)
    
    # Initialize SubdomainManager with db reference (for background thread access)
    if hasattr(app, 'db') and app.db is not None:
        from .core.subdomain_manager import get_subdomain_manager
        manager = get_subdomain_manager()
        manager.set_db(app.db)
        print("✓ SubdomainManager initialized with MongoDB")
    
    # Register Blueprints
    from .routes import main_bp
    app.register_blueprint(main_bp)

    @app.errorhandler(Exception)
    def handle_exception(e):
        """Global error handler to prevent HTML error pages in JSON API."""
        # Log the error
        app.logger.error(f"Global Error Catch: {str(e)}")
        # Return JSON instead of HTML
        return jsonify({
            "error": "Internal Server Error",
            "message": str(e)
        }), 500
    
    return app


def _init_db(app: Flask) -> None:
    """
    Initialize MongoDB connection, attach to Flask app, and create indexes.
    
    Args:
        app: Flask application instance
    """
    try:
        client = MongoClient(
            app.config["MONGO_URI"],
            serverSelectionTimeoutMS=5000  # 5 second timeout
        )
        # Verify connection
        client.admin.command('ping')
        
        app.db = client[app.config["MONGO_DB"]]
        print(f"✓ MongoDB connected: {app.config['MONGO_DB']}")
        
        # Create collections and indexes
        _create_indexes(app.db)
        
    except ConnectionFailure as e:
        print(f"✗ MongoDB connection failed: {e}")
        print("  Make sure MongoDB is running: brew services start mongodb-community")
        app.db = None
        
    except Exception as e:
        print(f"✗ MongoDB error: {e}")
        app.db = None


def _create_indexes(db) -> None:
    """
    Create indexes for all collections in the Ripro database.
    
    Args:
        db: MongoDB database instance
    """
    try:
        # ASN Scans Collection
        db.asn_scans.create_index("scan_id", unique=True)
        db.asn_scans.create_index("asn_numbers")
        db.asn_scans.create_index("created_at")
        
        # Subdomains Collection
        db.subdomains.create_index([("scan_id", 1), ("domain", 1)], unique=True)
        db.subdomains.create_index("source_type")
        db.subdomains.create_index("is_from_asn")
        db.subdomains.create_index("asn_scan_id")
        db.subdomains.create_index("discovered_at")
        
        # Masscan Results Collection
        db.masscan_results.create_index([("scan_id", 1), ("ip", 1), ("port", 1)], unique=True)
        db.masscan_results.create_index("asn_scan_id")
        db.masscan_results.create_index("probed")
        db.masscan_results.create_index("discovered_at")
        
        # Extraction Results Collection
        db.extraction_results.create_index([("scan_id", 1), ("ip", 1), ("port", 1)])
        db.extraction_results.create_index("domain")
        db.extraction_results.create_index("asn_scan_id")
        db.extraction_results.create_index("status_code")
        db.extraction_results.create_index("technologies")
        db.extraction_results.create_index("waf")
        db.extraction_results.create_index("discovered_at")
        
        # Fuzzing Results Collection
        db.fuzzing_results.create_index([("scan_id", 1), ("domain", 1), ("path", 1)], unique=True)
        db.fuzzing_results.create_index("domain")
        db.fuzzing_results.create_index("status_code")
        db.fuzzing_results.create_index("interesting")
        
        # Crawler Results Collection
        db.crawler_results.create_index([("scan_id", 1), ("domain", 1), ("url", 1)], unique=True)
        db.crawler_results.create_index("domain")
        db.crawler_results.create_index("url_type")
        
        print("✓ MongoDB indexes created successfully")
        
    except Exception as e:
        print(f"⚠ Index creation warning: {e}")
