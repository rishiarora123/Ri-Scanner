import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.curdir))

try:
    print("Attempting to import app factory...")
    from app import create_app
    
    print("Creating app instance...")
    app = create_app()
    
    print("✓ App created successfully!")
except ImportError as e:
    print(f"✗ Import Error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Application Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
