from flask import Flask
from pymongo import MongoClient

def create_app():
    app = Flask(__name__)
    
    # MongoDB Config
    app.config["MONGO_URI"] = "mongodb://localhost:27017/"
    
    # Initialize DB (Lazy loading usually, but here we keep it simple)
    client = MongoClient(app.config["MONGO_URI"])
    try:
        app.db = client["scannerdb"]
        print("MongoDB connection successful")
    except Exception as e:
        print(f"Error connecting to MongoDB: {str(e)}")
        
    # Register Blueprints / Routes
    from .routes import main_bp
    app.register_blueprint(main_bp)

    return app
