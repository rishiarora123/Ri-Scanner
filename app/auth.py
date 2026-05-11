"""
Authentication module for Ri-Scanner Pro.

Provides user registration, login, logout, and session management
using Flask-Login with bcrypt-hashed passwords stored in MongoDB.
"""
import os
import re
import bcrypt
import secrets
from datetime import datetime
from functools import wraps
from typing import Optional, Tuple

from flask import (
    Blueprint, request, jsonify, render_template,
    redirect, url_for, flash, current_app, g
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)

# ── Constants ─────────────────────────────────────────────────────
MIN_PASSWORD_LENGTH = 8
MAX_USERNAME_LENGTH = 32
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,32}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

# Routes that can be accessed without login (login, register, static assets)
PUBLIC_ENDPOINTS = {
    'auth.login', 'auth.register', 'auth.logout',
    'static', 'auth.api_login', 'auth.api_register',
}

# ── Login Manager ─────────────────────────────────────────────────
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
login_manager.session_protection = 'strong'

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


# ── User Model ────────────────────────────────────────────────────
class User(UserMixin):
    """User model backed by MongoDB."""

    def __init__(self, doc: dict):
        self._doc = doc
        self.id = str(doc['_id'])
        self.username = doc['username']
        self.email = doc.get('email', '')
        self.role = doc.get('role', 'operator')
        self.api_key = doc.get('api_key', '')
        self.created_at = doc.get('created_at')
        self.last_login = doc.get('last_login')
        self.is_active_user = doc.get('is_active', True)

    @property
    def is_admin(self) -> bool:
        return self.role == 'admin'

    @property
    def is_active(self) -> bool:
        return self.is_active_user

    def get_id(self) -> str:
        return self.id


# ── Password Utilities ────────────────────────────────────────────
def hash_password(password: str) -> bytes:
    """Hash a password using bcrypt with auto-generated salt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))


def verify_password(password: str, hashed: bytes) -> bool:
    """Verify a password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed)
    except (ValueError, TypeError):
        return False


def generate_api_key() -> str:
    """Generate a cryptographically secure API key."""
    return f"rsk_{secrets.token_urlsafe(32)}"


# ── Validation ────────────────────────────────────────────────────
def validate_username(username: str) -> Tuple[bool, str]:
    """Validate username format."""
    if not username:
        return False, "Username is required"
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > MAX_USERNAME_LENGTH:
        return False, f"Username must be at most {MAX_USERNAME_LENGTH} characters"
    if not USERNAME_PATTERN.match(username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, ""


def validate_password(password: str) -> Tuple[bool, str]:
    """Validate password strength."""
    if not password:
        return False, "Password is required"
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, ""


def validate_email(email: str) -> Tuple[bool, str]:
    """Validate email format (optional field)."""
    if not email:
        return True, ""
    if not EMAIL_PATTERN.match(email):
        return False, "Invalid email format"
    return True, ""


# ── User CRUD ─────────────────────────────────────────────────────
def get_users_collection():
    """Get the users MongoDB collection."""
    if not hasattr(current_app, 'db') or current_app.db is None:
        return None
    return current_app.db.users


def get_user_by_id(user_id: str) -> Optional[User]:
    """Fetch user by ObjectId string."""
    from bson import ObjectId
    coll = get_users_collection()
    if coll is None:
        return None
    try:
        doc = coll.find_one({'_id': ObjectId(user_id)})
        return User(doc) if doc else None
    except Exception:
        return None


def get_user_by_username(username: str) -> Optional[User]:
    """Fetch user by username (case-insensitive)."""
    coll = get_users_collection()
    if coll is None:
        return None
    doc = coll.find_one({'username_lower': username.lower()})
    return User(doc) if doc else None


def get_user_by_api_key(api_key: str) -> Optional[User]:
    """Fetch user by API key."""
    coll = get_users_collection()
    if coll is None:
        return None
    doc = coll.find_one({'api_key': api_key})
    return User(doc) if doc else None


def create_user(username: str, password: str, email: str = '',
                role: str = 'operator') -> Tuple[bool, str, Optional[User]]:
    """
    Create a new user in the database.

    Returns:
        (success, message, user or None)
    """
    coll = get_users_collection()
    if coll is None:
        return False, "Database not available", None

    # Validation
    valid, msg = validate_username(username)
    if not valid:
        return False, msg, None
    valid, msg = validate_password(password)
    if not valid:
        return False, msg, None
    valid, msg = validate_email(email)
    if not valid:
        return False, msg, None

    # Check uniqueness
    if coll.find_one({'username_lower': username.lower()}):
        return False, "Username already taken", None

    # Create document
    doc = {
        'username': username,
        'username_lower': username.lower(),
        'email': email,
        'password_hash': hash_password(password),
        'role': role,
        'api_key': generate_api_key(),
        'is_active': True,
        'created_at': datetime.utcnow(),
        'last_login': None,
    }
    result = coll.insert_one(doc)
    doc['_id'] = result.inserted_id
    return True, "User created successfully", User(doc)


def update_last_login(user_id: str) -> None:
    """Update the last_login timestamp for a user."""
    from bson import ObjectId
    coll = get_users_collection()
    if coll is None:
        return
    try:
        coll.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'last_login': datetime.utcnow()}}
        )
    except Exception:
        pass


def count_users() -> int:
    """Return total number of users (used to detect first-run)."""
    coll = get_users_collection()
    if coll is None:
        return 0
    return coll.count_documents({})


# ── Flask-Login User Loader ───────────────────────────────────────
@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return get_user_by_id(user_id)


@login_manager.unauthorized_handler
def unauthorized():
    """Handle unauthorized access — JSON for API, redirect for pages."""
    if request.path.startswith('/api/') or \
       request.headers.get('Accept', '').startswith('application/json'):
        return jsonify({'error': 'Authentication required'}), 401
    return redirect(url_for('auth.login', next=request.url))


# ── API Key Authentication (alternative to session) ───────────────
@auth_bp.before_app_request
def check_api_key():
    """
    Allow API key auth via X-API-Key header or Authorization: Bearer.
    Works on any endpoint — useful for both /api/ and legacy routes.
    """
    if current_user.is_authenticated:
        return  # Already authenticated by session

    api_key = request.headers.get('X-API-Key', '').strip()
    if not api_key:
        auth_header = request.headers.get('Authorization', '').strip()
        if auth_header.lower().startswith('bearer '):
            api_key = auth_header[7:].strip()

    if not api_key:
        return

    user = get_user_by_api_key(api_key)
    if user and user.is_active_user:
        # Log in the user for this request only (no session)
        login_user(user, remember=False)


# ── Auth Routes ───────────────────────────────────────────────────
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page + form handler."""
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))

    if request.method == 'GET':
        # Show first-run hint if no users exist
        first_run = count_users() == 0
        return render_template('auth/login.html', first_run=first_run)

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    remember = request.form.get('remember') == 'on'

    user = get_user_by_username(username)
    if not user or not verify_password(password, user._doc['password_hash']):
        flash('Invalid username or password', 'error')
        return render_template('auth/login.html'), 401

    if not user.is_active_user:
        flash('Account is disabled', 'error')
        return render_template('auth/login.html'), 403

    login_user(user, remember=remember)
    update_last_login(user.id)

    next_url = request.args.get('next') or url_for('main.home')
    # Prevent open redirect
    if not next_url.startswith('/'):
        next_url = url_for('main.home')

    return redirect(next_url)


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Register page + form handler. First user becomes admin automatically."""
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))

    if request.method == 'GET':
        return render_template('auth/register.html', first_run=count_users() == 0)

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    confirm = request.form.get('confirm_password', '')
    email = request.form.get('email', '').strip()

    if password != confirm:
        flash('Passwords do not match', 'error')
        return render_template('auth/register.html'), 400

    # First user is admin, subsequent users are operators
    role = 'admin' if count_users() == 0 else 'operator'

    success, msg, user = create_user(username, password, email, role)
    if not success:
        flash(msg, 'error')
        return render_template('auth/register.html'), 400

    login_user(user)
    update_last_login(user.id)
    flash(f'Welcome, {user.username}! Your account has been created.', 'success')
    return redirect(url_for('main.home'))


@auth_bp.route('/logout')
@login_required
def logout():
    """Log out the current user."""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile')
@login_required
def profile():
    """Show current user profile + API key."""
    return render_template('auth/profile.html', user=current_user)


@auth_bp.route('/regenerate_api_key', methods=['POST'])
@login_required
def regenerate_api_key():
    """Rotate the current user's API key."""
    from bson import ObjectId
    coll = get_users_collection()
    if coll is None:
        return jsonify({'error': 'Database unavailable'}), 503

    new_key = generate_api_key()
    coll.update_one(
        {'_id': ObjectId(current_user.id)},
        {'$set': {'api_key': new_key}}
    )
    return jsonify({'api_key': new_key})


# ── Init Hook ─────────────────────────────────────────────────────
def init_auth(app):
    """Wire authentication into a Flask app."""
    login_manager.init_app(app)
    app.register_blueprint(auth_bp)

    # Create unique indexes for users collection
    if hasattr(app, 'db') and app.db is not None:
        try:
            app.db.users.create_index('username_lower', unique=True)
            app.db.users.create_index('api_key', unique=True, sparse=True)
            print("✓ Auth indexes created")
        except Exception as e:
            print(f"⚠ Auth index creation: {e}")
