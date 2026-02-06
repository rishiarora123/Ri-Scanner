"""
Unified error handling system for Ri-Scanner Pro.
Provides consistent, user-friendly error responses across all routes.
"""
from functools import wraps
from flask import jsonify, current_app
from pymongo.errors import PyMongoError


def api_error_handler(f):
    """
    Decorator for API routes to handle errors consistently.
    Returns JSON responses with user-friendly messages.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        
        except ValueError as e:
            # Input validation errors
            return jsonify({
                "success": False,
                "error": str(e)
            }), 400
        
        except PermissionError as e:
            # Permission-related errors
            return jsonify({
                "success": False,
                "error": "🔒 Permission denied. Please check your access rights."
            }), 403
        
        except PyMongoError as e:
            # MongoDB errors
            current_app.logger.error(f"MongoDB error in {f.__name__}: {e}")
            return jsonify({
                "success": False,
                "error": "📡 Database error. Please ensure MongoDB is running."
            }), 500
        
        except FileNotFoundError as e:
            # File not found errors
            return jsonify({
                "success": False,
                "error": f"📁 File not found: {str(e)}"
            }), 404
        
        except Exception as e:
            # Catch-all for unexpected errors
            current_app.logger.error(
                f"Unhandled error in {f.__name__}: {e}",
                exc_info=True
            )
            return jsonify({
                "success": False,
                "error": "❌ An unexpected error occurred. Please try again."
            }), 500
    
    return decorated


def check_mongodb_connection():
    """
    Check if MongoDB connection is available.
    Raises ValueError with user-friendly message if not connected.
    """
    if not hasattr(current_app, 'db') or current_app.db is None:
        raise ValueError(
            "📡 Database not available. Please ensure MongoDB is running.\n"
            "Run: brew services start mongodb-community"
        )


def handle_scan_error(error: Exception, scan_type: str = "scan") -> dict:
    """
    Handle errors during scanning operations.
    
    Args:
        error: Exception that occurred
        scan_type: Type of scan (for logging)
    
    Returns:
        Error response dictionary
    """
    error_msg = str(error)
    
    # Map common errors to user-friendly messages
    if "permission" in error_msg.lower() or "sudo" in error_msg.lower():
        return {
            "success": False,
            "error": "🔒 This scan requires administrator access. Please run the application with sudo."
        }
    
    elif "masscan" in error_msg.lower():
        return {
            "success": False,
            "error": "⚠️ Port scanner (Masscan) is not available. Please install it: brew install masscan"
        }
    
    elif "timeout" in error_msg.lower():
        return {
            "success": False,
            "error": "⏱️ The scan timed out. Please try again with a smaller target or slower scan speed."
        }
    
    elif "network" in error_msg.lower() or "connection" in error_msg.lower():
        return {
            "success": False,
            "error": "🌐 Network connection issue. Please check your internet connection."
        }
    
    else:
        current_app.logger.error(f"{scan_type} error: {error}")
        return {
            "success": False,
            "error": f"❌ {scan_type.capitalize()} failed: {error_msg}"
        }
