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
        MONGO_DB=os.getenv("MONGO_DB", "scannerdb"),
        SECRET_KEY=os.getenv("SECRET_KEY", os.urandom(24).hex()),
    )
    
    # Initialize MongoDB connection
    _init_db(app)
    
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
    Initialize MongoDB connection and attach to Flask app.
    
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
        
    except ConnectionFailure as e:
        print(f"✗ MongoDB connection failed: {e}")
        print("  Make sure MongoDB is running: brew services start mongodb-community")
        app.db = None
        
    except Exception as e:
        print(f"✗ MongoDB error: {e}")
        app.db = None
