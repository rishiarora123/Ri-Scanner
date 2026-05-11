"""
Authentication module for Ri-Scanner Pro.

Provides user registration, login, logout, session management,
CSRF protection, rate limiting, account lockout, and admin user
management. Backed by MongoDB with bcrypt-hashed passwords.
"""
import os
import re
import bcrypt
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional, Tuple

from flask import (
    Blueprint, request, jsonify, render_template,
    redirect, url_for, flash, current_app, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── Constants ─────────────────────────────────────────────────────
MIN_PASSWORD_LENGTH = 8
MAX_USERNAME_LENGTH = 32
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,32}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

# Account lockout
MAX_FAILED_LOGINS = 10
LOCKOUT_WINDOW_MIN = 15  # 10 failed logins in 15 min → 15 min lockout

# Roles
ROLE_ADMIN = 'admin'
ROLE_OPERATOR = 'operator'

# ── Login Manager + CSRF + Limiter ────────────────────────────────
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
login_manager.session_protection = 'strong'

csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],  # No global limit; specific rules per route
    storage_uri="memory://",
)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


# ── User Model ────────────────────────────────────────────────────
class User(UserMixin):
    """User model backed by MongoDB."""

    def __init__(self, doc: dict):
        self._doc = doc
        self.id = str(doc['_id'])
        self.username = doc['username']
        self.email = doc.get('email', '')
        self.role = doc.get('role', ROLE_OPERATOR)
        self.api_key = doc.get('api_key', '')
        self.created_at = doc.get('created_at')
        self.last_login = doc.get('last_login')
        self.is_active_user = doc.get('is_active', True)
        self.failed_logins = doc.get('failed_logins', [])
        self.locked_until = doc.get('locked_until')

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    @property
    def is_active(self) -> bool:
        return self.is_active_user

    @property
    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > datetime.utcnow()

    def get_id(self) -> str:
        return self.id


# ── Decorators ────────────────────────────────────────────────────
def admin_required(f):
    """Require admin role for the wrapped view."""
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            if request.path.startswith('/api/') or request.headers.get('Accept', '').startswith('application/json'):
                return jsonify({'error': 'Admin access required'}), 403
            abort(403)
        return f(*args, **kwargs)
    return wrapper


# ── Password Utilities ────────────────────────────────────────────
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))


def verify_password(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed)
    except (ValueError, TypeError):
        return False


def generate_api_key() -> str:
    return f"rsk_{secrets.token_urlsafe(32)}"


# ── Validation ────────────────────────────────────────────────────
def validate_username(username: str) -> Tuple[bool, str]:
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
    if not email:
        return True, ""
    if not EMAIL_PATTERN.match(email):
        return False, "Invalid email format"
    return True, ""


# ── User CRUD ─────────────────────────────────────────────────────
def get_users_collection():
    if not hasattr(current_app, 'db') or current_app.db is None:
        return None
    return current_app.db.users


def get_user_by_id(user_id: str) -> Optional[User]:
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
    coll = get_users_collection()
    if coll is None:
        return None
    doc = coll.find_one({'username_lower': username.lower()})
    return User(doc) if doc else None


def get_user_by_api_key(api_key: str) -> Optional[User]:
    coll = get_users_collection()
    if coll is None or not api_key:
        return None
    doc = coll.find_one({'api_key': api_key})
    return User(doc) if doc else None


def list_all_users():
    """Return all users (admin only)."""
    coll = get_users_collection()
    if coll is None:
        return []
    return [User(doc) for doc in coll.find().sort('created_at', -1)]


def create_user(username: str, password: str, email: str = '',
                role: str = ROLE_OPERATOR) -> Tuple[bool, str, Optional[User]]:
    coll = get_users_collection()
    if coll is None:
        return False, "Database not available", None

    valid, msg = validate_username(username)
    if not valid:
        return False, msg, None
    valid, msg = validate_password(password)
    if not valid:
        return False, msg, None
    valid, msg = validate_email(email)
    if not valid:
        return False, msg, None
    if role not in (ROLE_ADMIN, ROLE_OPERATOR):
        return False, "Invalid role", None

    if coll.find_one({'username_lower': username.lower()}):
        return False, "Username already taken", None

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
        'failed_logins': [],
        'locked_until': None,
    }
    result = coll.insert_one(doc)
    doc['_id'] = result.inserted_id
    audit_log('user.created', User(doc), {'role': role})
    return True, "User created successfully", User(doc)


def update_last_login(user_id: str) -> None:
    from bson import ObjectId
    coll = get_users_collection()
    if coll is None:
        return
    try:
        coll.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'last_login': datetime.utcnow(),
                      'failed_logins': [], 'locked_until': None}}
        )
    except Exception:
        pass


def record_failed_login(username: str) -> Optional[datetime]:
    """
    Record a failed login attempt. Lock the account if too many recent failures.
    Returns the locked_until datetime if account is now locked.
    """
    coll = get_users_collection()
    if coll is None:
        return None
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=LOCKOUT_WINDOW_MIN)
    doc = coll.find_one({'username_lower': username.lower()})
    if not doc:
        return None

    # Filter to recent failures only, append this one
    recent = [t for t in doc.get('failed_logins', []) if t > window_start]
    recent.append(now)

    update = {'failed_logins': recent}
    locked_until = None
    if len(recent) >= MAX_FAILED_LOGINS:
        locked_until = now + timedelta(minutes=LOCKOUT_WINDOW_MIN)
        update['locked_until'] = locked_until
        update['failed_logins'] = []  # reset counter after lockout
        audit_log('user.locked', User(doc), {'until': locked_until.isoformat()})

    coll.update_one({'_id': doc['_id']}, {'$set': update})
    return locked_until


def count_users() -> int:
    coll = get_users_collection()
    if coll is None:
        return 0
    return coll.count_documents({})


# ── Audit Log ─────────────────────────────────────────────────────
def audit_log(event: str, user: Optional[User] = None, details: dict = None) -> None:
    """Record an audit event. Best-effort — failure to log shouldn't break the action."""
    if not hasattr(current_app, 'db') or current_app.db is None:
        return
    try:
        current_app.db.audit_log.insert_one({
            'event': event,
            'user_id': user.id if user else None,
            'username': user.username if user else None,
            'ip': get_remote_address(),
            'user_agent': request.headers.get('User-Agent', '')[:200] if request else '',
            'details': details or {},
            'timestamp': datetime.utcnow(),
        })
    except Exception:
        pass


# ── Flask-Login User Loader ───────────────────────────────────────
@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    return get_user_by_id(user_id)


@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith('/api/') or \
       request.headers.get('Accept', '').startswith('application/json'):
        return jsonify({'error': 'Authentication required'}), 401
    return redirect(url_for('auth.login', next=request.url))


# ── API Key Authentication ────────────────────────────────────────
@auth_bp.before_app_request
def check_api_key():
    """Allow API key auth via X-API-Key or Authorization: Bearer header."""
    if current_user.is_authenticated:
        return

    api_key = request.headers.get('X-API-Key', '').strip()
    if not api_key:
        auth_header = request.headers.get('Authorization', '').strip()
        if auth_header.lower().startswith('bearer '):
            api_key = auth_header[7:].strip()

    if not api_key:
        return

    user = get_user_by_api_key(api_key)
    if user and user.is_active_user and not user.is_locked:
        login_user(user, remember=False)


# ── CSRF Exemption for API Key Requests ───────────────────────────
@auth_bp.before_app_request
def exempt_api_key_csrf():
    """Requests authenticated via API key are exempt from CSRF (no session)."""
    if request.headers.get('X-API-Key') or \
       request.headers.get('Authorization', '').lower().startswith('bearer '):
        request._csrf_exempt = True


# ── Auth Routes ───────────────────────────────────────────────────
@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=['POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))

    if request.method == 'GET':
        return render_template('auth/login.html', first_run=count_users() == 0)

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    remember = request.form.get('remember') == 'on'

    user = get_user_by_username(username)

    # Check lockout BEFORE password verify (timing safety)
    if user and user.is_locked:
        remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60) + 1
        flash(f'Account temporarily locked. Try again in {remaining} minutes.', 'error')
        audit_log('login.blocked_locked', user, {'username': username})
        return render_template('auth/login.html'), 423  # Locked

    if not user or not verify_password(password, user._doc['password_hash']):
        if user:
            record_failed_login(username)
            audit_log('login.failed', user, {'username': username})
        else:
            audit_log('login.failed', None, {'username': username})
        flash('Invalid username or password', 'error')
        return render_template('auth/login.html'), 401

    if not user.is_active_user:
        flash('Account is disabled. Contact an administrator.', 'error')
        audit_log('login.blocked_disabled', user)
        return render_template('auth/login.html'), 403

    login_user(user, remember=remember)
    update_last_login(user.id)
    audit_log('login.success', user)

    next_url = request.args.get('next') or url_for('main.home')
    if not next_url.startswith('/'):
        next_url = url_for('main.home')
    return redirect(next_url)


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=['POST'])
def register():
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

    role = ROLE_ADMIN if count_users() == 0 else ROLE_OPERATOR
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
    audit_log('logout', current_user)
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile')
@login_required
def profile():
    return render_template('auth/profile.html', user=current_user)


@auth_bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Allow logged-in users to change their own password."""
    if request.method == 'GET':
        return render_template('auth/change_password.html')

    current = request.form.get('current_password', '')
    new = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')

    if not verify_password(current, current_user._doc['password_hash']):
        flash('Current password is incorrect', 'error')
        return render_template('auth/change_password.html'), 401

    if new != confirm:
        flash('New passwords do not match', 'error')
        return render_template('auth/change_password.html'), 400

    valid, msg = validate_password(new)
    if not valid:
        flash(msg, 'error')
        return render_template('auth/change_password.html'), 400

    if verify_password(new, current_user._doc['password_hash']):
        flash('New password must be different from current', 'error')
        return render_template('auth/change_password.html'), 400

    from bson import ObjectId
    coll = get_users_collection()
    coll.update_one(
        {'_id': ObjectId(current_user.id)},
        {'$set': {'password_hash': hash_password(new)}}
    )
    audit_log('user.password_changed', current_user)
    flash('Password changed successfully', 'success')
    return redirect(url_for('auth.profile'))


@auth_bp.route('/regenerate_api_key', methods=['POST'])
@login_required
def regenerate_api_key():
    from bson import ObjectId
    coll = get_users_collection()
    if coll is None:
        return jsonify({'error': 'Database unavailable'}), 503
    new_key = generate_api_key()
    coll.update_one(
        {'_id': ObjectId(current_user.id)},
        {'$set': {'api_key': new_key}}
    )
    audit_log('user.api_key_regenerated', current_user)
    return jsonify({'api_key': new_key})


# ── Admin Routes ──────────────────────────────────────────────────
@admin_bp.route('/users')
@admin_required
def users():
    """Admin user management page."""
    users_list = list_all_users()
    return render_template('admin/users.html', users=users_list, current_id=current_user.id)


@admin_bp.route('/users/<user_id>/role', methods=['POST'])
@admin_required
def change_role(user_id):
    """Promote or demote a user."""
    new_role = request.form.get('role')
    if new_role not in (ROLE_ADMIN, ROLE_OPERATOR):
        return jsonify({'error': 'Invalid role'}), 400
    if user_id == current_user.id:
        return jsonify({'error': "Can't change your own role"}), 400

    from bson import ObjectId
    coll = get_users_collection()
    target = coll.find_one({'_id': ObjectId(user_id)})
    if not target:
        return jsonify({'error': 'User not found'}), 404

    coll.update_one({'_id': ObjectId(user_id)}, {'$set': {'role': new_role}})
    audit_log('admin.role_changed', current_user,
              {'target': target['username'], 'new_role': new_role})
    return jsonify({'success': True, 'role': new_role})


@admin_bp.route('/users/<user_id>/toggle_active', methods=['POST'])
@admin_required
def toggle_active(user_id):
    """Enable or disable a user account."""
    if user_id == current_user.id:
        return jsonify({'error': "Can't disable your own account"}), 400

    from bson import ObjectId
    coll = get_users_collection()
    target = coll.find_one({'_id': ObjectId(user_id)})
    if not target:
        return jsonify({'error': 'User not found'}), 404

    new_state = not target.get('is_active', True)
    update = {'is_active': new_state}
    if new_state:
        # Unlocking — clear lockout
        update['locked_until'] = None
        update['failed_logins'] = []
    coll.update_one({'_id': ObjectId(user_id)}, {'$set': update})
    audit_log('admin.user_disabled' if not new_state else 'admin.user_enabled',
              current_user, {'target': target['username']})
    return jsonify({'success': True, 'is_active': new_state})


@admin_bp.route('/users/<user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Permanently delete a user."""
    if user_id == current_user.id:
        return jsonify({'error': "Can't delete your own account"}), 400

    from bson import ObjectId
    coll = get_users_collection()
    target = coll.find_one({'_id': ObjectId(user_id)})
    if not target:
        return jsonify({'error': 'User not found'}), 404

    coll.delete_one({'_id': ObjectId(user_id)})
    audit_log('admin.user_deleted', current_user, {'target': target['username']})
    return jsonify({'success': True})


@admin_bp.route('/audit')
@admin_required
def audit():
    """View audit log (last 200 entries)."""
    if not hasattr(current_app, 'db') or current_app.db is None:
        return render_template('admin/audit.html', entries=[])
    entries = list(current_app.db.audit_log.find()
                   .sort('timestamp', -1).limit(200))
    return render_template('admin/audit.html', entries=entries)


# ── Error Handlers ────────────────────────────────────────────────
def init_csrf_error_handler(app):
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        # AJAX/API requests get JSON 400
        is_api = (
            request.path.startswith('/api/')
            or request.path.startswith('/admin/')
            or request.headers.get('Accept', '').startswith('application/json')
            or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
            or request.is_json
        )
        if is_api:
            return jsonify({'error': 'CSRF token missing or invalid'}), 400
        flash('Your session expired. Please try again.', 'error')
        return redirect(url_for('auth.login'))


# ── Init Hook ─────────────────────────────────────────────────────
def init_auth(app):
    """Wire authentication, CSRF, and rate limiting into a Flask app."""
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    init_csrf_error_handler(app)

    # Custom CSRF check that respects API key exemption
    @app.before_request
    def _csrf_protect_with_api_key_exemption():
        # Skip CSRF for API key requests (already validated by key)
        if getattr(request, '_csrf_exempt', False):
            return
        # Skip for safe methods and the API key endpoints handled by Flask-WTF default

    if hasattr(app, 'db') and app.db is not None:
        try:
            app.db.users.create_index('username_lower', unique=True)
            app.db.users.create_index('api_key', unique=True, sparse=True)
            app.db.audit_log.create_index([('timestamp', -1)])
            app.db.audit_log.create_index('user_id')
            app.db.audit_log.create_index('event')
            print("✓ Auth indexes created")
        except Exception as e:
            print(f"⚠ Auth index creation: {e}")
