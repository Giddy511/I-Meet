from flask import Flask, render_template, session, redirect, url_for, request, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import sqlite3
import os
import smtplib
import logging
import time
from email.message import EmailMessage
from collections import defaultdict
from datetime import timedelta
from datetime import datetime
from flask import session as flask_session
from jinja2 import TemplateNotFound
try:
    from flask_socketio import SocketIO, emit, join_room, leave_room
except Exception:
    # If Flask-SocketIO isn't installed the file will still run, but realtime will be disabled.
    SocketIO = None
    emit = None
    join_room = None
    leave_room = None

# Optionally load environment variables from a local .env file for convenience in development.
# This is safe: if python-dotenv is not installed the import will be skipped.
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    # not critical; environment variables can be set in other ways
    pass

UPLOAD_DIR = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = 'jvjjjgccgcgchvkj67'
# make session persistent for a reasonable period
app.permanent_session_lifetime = timedelta(days=7)

# serializer for password reset tokens
serializer = URLSafeTimedSerializer(app.secret_key)


@app.context_processor
def inject_logo_path():
    # choose a logo path that exists; prefer static/logo.png but fall back to uploads/LOGO.png
    logo_a = os.path.join(app.static_folder or 'static', 'logo.png')
    logo_b = os.path.join(app.static_folder or 'static', 'uploads', 'LOGO.png')
    if os.path.exists(logo_a):
        return {'LOGO_PATH': url_for('static', filename='logo.png')}
    elif os.path.exists(logo_b):
        return {'LOGO_PATH': url_for('static', filename='uploads/LOGO.png')}
    else:
        # default to the uploads path so template still has a value
        return {'LOGO_PATH': url_for('static', filename='uploads/LOGO.png')}


@app.context_processor
def inject_unread_notifications():
    """Provide unread notification count for the current logged-in user so the
    header can render a badge. Returns {'unread_notifications': int}.
    """
    unread = 0
    try:
        if session.get('logged_in'):
            uid = session.get('id')
            conn = sqlite3.connect('Instagram.db')
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_flag = 0', (uid,))
            row = cursor.fetchone()
            if row:
                unread = int(row[0] or 0)
            conn.close()
    except Exception:
        # swallow errors; header should be resilient
        unread = 0
    return {'unread_notifications': unread}

# --- logging setup for forgot/reset actions ---
LOG_DIR = os.path.join('.', 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
logger = logging.getLogger('forgot_reset')
if not logger.handlers:
    fh = logging.FileHandler(os.path.join(LOG_DIR, 'forgot_reset.log'))
    fh.setLevel(logging.INFO)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.setLevel(logging.INFO)

# Simple in-memory rate limiter: key -> list of timestamps
_rate_store = defaultdict(list)

def check_rate_limit(key: str, limit: int, period_seconds: int) -> bool:
    """Return True if allowed, and record the attempt. False if rate limited."""
    now = time.time()
    window_start = now - period_seconds
    stamps = _rate_store[key]
    # prune old
    while stamps and stamps[0] < window_start:
        stamps.pop(0)
    if len(stamps) >= limit:
        return False
    stamps.append(now)
    return True

def send_reset_email(to_email: str, reset_url: str) -> bool:
    """Send reset_url to to_email using SMTP configured by environment variables.
    Returns True if send succeeded, False otherwise.
    """
    host = os.getenv('SMTP_HOST')
    port_str = os.getenv('SMTP_PORT')
    try:
        port = int(port_str) if port_str else None
    except ValueError:
        logger.warning('Invalid SMTP_PORT value: %s', port_str)
        port = None
    user = os.getenv('SMTP_USER')
    pw = os.getenv('SMTP_PASS')
    from_addr = os.getenv('SMTP_FROM') or (user or 'no-reply@example.com')
    use_tls_val = os.getenv('SMTP_USE_TLS', 'true')
    use_tls = str(use_tls_val).lower() in ('1', 'true', 'yes', 'on')

    if not host or not port:
        logger.info('SMTP not configured; host=%s port=%s; cannot send email to %s', host, port, to_email)
        return False

    try:
        msg = EmailMessage()
        msg['Subject'] = 'Reset your password'
        msg['From'] = from_addr
        msg['To'] = to_email
        msg.set_content(f'Use this link to reset your password (valid 1 hour):\n\n{reset_url}\n\nIf you did not request this, ignore this email.')

        server = smtplib.SMTP(host, port, timeout=10)
        if use_tls:
            try:
                server.starttls()
            except Exception:
                logger.exception('STARTTLS failed for %s:%s', host, port)
        if user and pw:
            try:
                server.login(user, pw)
            except Exception:
                logger.exception('SMTP login failed for user %s at %s:%s', user, host, port)
        server.send_message(msg)
        server.quit()
        logger.info('Sent reset email to %s via %s:%s (from=%s)', to_email, host, port, from_addr)
        return True
    except Exception as e:
        logger.exception('Failed to send reset email to %s: %s', to_email, e)
        return False


def db():
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Email TEXT,
        Username TEXT UNIQUE,
        Password TEXT,
        Role TEXT
    )
    """)
    # Add suspended_until column if missing (stores UTC timestamp string)
    cursor.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in cursor.fetchall()]
    if 'suspended_until' not in cols:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN suspended_until DATETIME")
        except Exception:
            pass
    # add ui_variant column to support per-user UI variants (v1 default)
    if 'ui_variant' not in cols:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN ui_variant TEXT DEFAULT 'v1'")
        except Exception:
            pass
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS media (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        Title TEXT,
        Caption TEXT,
        Location TEXT,
        People TEXT,
        Filename TEXT,
        share_count INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    # comments and reactions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        media_id INTEGER,
        user_id INTEGER,
        comment TEXT,
        parent_id INTEGER DEFAULT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(media_id) REFERENCES media(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        media_id INTEGER,
        user_id INTEGER,
        type TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(media_id) REFERENCES media(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        media_id INTEGER,
        user_id INTEGER,
        rating INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(media_id) REFERENCES media(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    # Likes for comments (one per user per comment)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS comment_likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        comment_id INTEGER,
        user_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(comment_id) REFERENCES comments(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    # follows table: follower (consumer) -> creator
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS follows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        follower_id INTEGER,
        creator_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(follower_id) REFERENCES users(id),
        FOREIGN KEY(creator_id) REFERENCES users(id)
    )
    """)
    # simple notifications table for followers to receive post alerts
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        message TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        read_flag INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    # Add a target_url column for structured notification links if missing
    cursor.execute("PRAGMA table_info(notifications)")
    notif_cols = [r[1] for r in cursor.fetchall()]
    if 'target_url' not in notif_cols:
        try:
            cursor.execute('ALTER TABLE notifications ADD COLUMN target_url TEXT')
        except Exception:
            # ignore failures (older SQLite or concurrent migrations)
            pass
    # Ensure media has share_count column (for older DBs)
    try:
        cursor.execute("PRAGMA table_info(media)")
        media_cols = [r[1] for r in cursor.fetchall()]
        if 'share_count' not in media_cols:
            try:
                cursor.execute('ALTER TABLE media ADD COLUMN share_count INTEGER DEFAULT 0')
            except Exception:
                pass
    except Exception:
        pass
    # Ensure comments has parent_id column
    try:
        cursor.execute("PRAGMA table_info(comments)")
        comm_cols = [r[1] for r in cursor.fetchall()]
        if 'parent_id' not in comm_cols:
            try:
                cursor.execute('ALTER TABLE comments ADD COLUMN parent_id INTEGER DEFAULT NULL')
            except Exception:
                pass
    except Exception:
        pass
    # Backfill existing notifications by extracting an http(s) URL token from the message
    try:
        cursor.execute("SELECT id, message FROM notifications WHERE (target_url IS NULL OR target_url = '')")
        rows = cursor.fetchall()
        for rid, msg in rows:
            if not msg:
                continue
            # naive token scan for http/https URLs
            tokens = (msg or '').split()
            url = None
            for t in tokens:
                if t.startswith('http://') or t.startswith('https://'):
                    url = t
                    break
            if url:
                try:
                    cursor.execute('UPDATE notifications SET target_url = ? WHERE id = ?', (url, rid))
                except Exception:
                    pass
        # commit backfill changes
        conn.commit()
    except Exception:
        # non-fatal
        pass
    # messages table for user-to-user messaging
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        recipient_id INTEGER,
        body TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        read_flag INTEGER DEFAULT 0,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(recipient_id) REFERENCES users(id)
    )
    """)
    # Ensure there's at least one admin for development convenience
    cursor.execute("SELECT id FROM users WHERE Role = 'admin' LIMIT 1")
    if not cursor.fetchone():
        from werkzeug.security import generate_password_hash
        admin_pw = generate_password_hash('admin', method='pbkdf2:sha256')
        try:
            cursor.execute("INSERT INTO users (Email, Username, Password, Role) VALUES (?, ?, ?, ?)",
                           ('admin@gmail.com', 'admin', admin_pw, 'admin'))
        except Exception:
            pass
    conn.commit()
    conn.close()


db()


def render_variant(template_name, **context):
    """Render a template taking into account a per-user UI variant.
    Attempts to render from `templates/<variant>/<template_name>` first,
    then falls back to the top-level `templates/<template_name>`.
    Variant is read from the logged-in user's `ui_variant` column (defaults to 'v1').
    """
    variant = 'v1'
    uid = session.get('id')
    if uid:
        try:
            conn = sqlite3.connect('Instagram.db')
            cur = conn.cursor()
            cur.execute('SELECT ui_variant FROM users WHERE id = ? LIMIT 1', (uid,))
            r = cur.fetchone()
            if r and r[0]:
                variant = r[0]
            conn.close()
        except Exception:
            # on any DB error, gracefully fall back to default variant
            variant = 'v1'
    candidate = f"{variant}/{template_name}"
    # provide variant feature flags to templates (unless caller has provided)
    if 'variant_features' not in context:
        try:
            context['variant_features'] = get_variant_features(variant)
        except Exception:
            context['variant_features'] = {}
    try:
        return render_template(candidate, **context)
    except TemplateNotFound:
        return render_template(template_name, **context)


def get_variant_features(variant: str):
    """Return a dict of feature flags/settings for a given variant.
    Keep this small and explicit so templates can branch cleanly.
    """
    # default v1 behavior
    base = {
        'rating_mode': 'stars',    # 'stars' or 'numeric'
        'show_share_count': True,
        'comment_replies': True,
        'comment_likes': True,
        'font_family': None,
        'font_size_scale': 1.0,
    }
    if variant == 'v2':
        return {
            'rating_mode': 'numeric',
            'show_share_count': True,
            'comment_replies': True,
            'comment_likes': True,
            'font_family': 'Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial',
            'font_size_scale': 1.05,
        }
    return base

# Real-time chat support removed: Socket.IO handlers and initialization were deleted

@app.route('/')
def landing():
    return render_variant('land.html')


def role_required(role):
    def decorator(f):
        def wrapper(*args, **kwargs):
            if not session.get('logged_in'):
                flash('Please login first', 'error')
                return redirect(url_for('Login'))
            if session.get('role') != role:
                flash('Access denied', 'error')
                return redirect(url_for('Home'))
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        Username = request.form.get('Username')
        Email = request.form.get('Email')
        Password = request.form['Password']
        Role = request.form.get('Role')

        if not (Username and Email and Password and Role):
            return 'Error: All fields are required!'

        # Hash the password for security
        hashed_password = generate_password_hash(Password, method='pbkdf2:sha256')

        conn = sqlite3.connect('Instagram.db')
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users(Username, Email, Password, Role) VALUES (?, ?, ?, ?)",
                           (Username, Email, hashed_password, Role))
            conn.commit()
            flash('Successfully signed up', 'success')
            return redirect(url_for('Login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
        finally:
            conn.close()
    return render_variant('signup.html')


@app.route('/admin', methods=['GET', 'POST'])
@role_required('admin')
def admin():
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    # --- analytics queries ---
    # users by role
    cursor.execute("SELECT Role, COUNT(*) FROM users GROUP BY Role")
    roles_data = cursor.fetchall()

    # reactions breakdown
    cursor.execute("SELECT type, COUNT(*) FROM reactions GROUP BY type")
    reactions_data = cursor.fetchall()

    # comments per day (last 14 days)
    cursor.execute("SELECT DATE(created_at) as d, COUNT(*) FROM comments WHERE DATE(created_at) >= DATE('now','-13 days') GROUP BY d ORDER BY d")
    comments_time = cursor.fetchall()

    # ratings histogram (1-5)
    cursor.execute("SELECT rating, COUNT(*) FROM ratings GROUP BY rating ORDER BY rating")
    ratings_hist = cursor.fetchall()

    # creators analytics: per-creator aggregates (media count, avg rating, likes, total reactions)
    cursor.execute("""
    SELECT u.id, u.Username,
      COUNT(DISTINCT m.id) as media_count,
      AVG(r.rating) as avg_rating,
      COALESCE(SUM(CASE WHEN reac.type = 'thumbs_up' THEN 1 ELSE 0 END), 0) as likes_count,
      COUNT(reac.id) as reactions_count
    FROM users u
    LEFT JOIN media m ON m.user_id = u.id
    LEFT JOIN ratings r ON r.media_id = m.id
    LEFT JOIN reactions reac ON reac.media_id = m.id
    WHERE u.Role = 'creator'
    GROUP BY u.id
    ORDER BY media_count DESC
    """)
    creators_analytics = cursor.fetchall()

    conn.close()

    # prepare structures for template (JSON-serializable)
    roles_pairs = [{'role': r[0] or 'unknown', 'count': r[1]} for r in roles_data]
    reactions_pairs = [{'type': r[0], 'count': r[1]} for r in reactions_data]
    comments_time_pairs = [{'date': c[0], 'count': c[1]} for c in comments_time]
    ratings_pairs = [{'rating': r[0], 'count': r[1]} for r in ratings_hist]
    creators_analytics_pairs = []
    for c in creators_analytics:
        creators_analytics_pairs.append({
            'id': c[0],
            'username': c[1],
            'media_count': int(c[2] or 0),
            'avg_rating': round(c[3], 2) if c[3] is not None else None,
            'likes_count': int(c[4] or 0),
            'reactions_count': int(c[5] or 0),
        })

    return render_variant('admin.html',
                           roles_data=roles_pairs,
                           reactions_data=reactions_pairs,
                           comments_time=comments_time_pairs,
                           ratings_hist=ratings_pairs,
                           creators_analytics=creators_analytics_pairs)


@app.route('/admin/delete_media/<int:media_id>', methods=['POST'])
@role_required('admin')
def admin_delete_media(media_id):
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    cursor.execute("SELECT Filename FROM media WHERE id = ?", (media_id,))
    row = cursor.fetchone()
    if row:
        filename = row[0]
        try:
            path = os.path.join(UPLOAD_DIR, filename)
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
    cursor.execute("DELETE FROM media WHERE id = ?", (media_id,))
    conn.commit()
    conn.close()
    flash('Media deleted', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@role_required('admin')
def admin_delete_user(user_id):
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    # delete media files
    cursor.execute('SELECT Filename FROM media WHERE user_id = ?', (user_id,))
    rows = cursor.fetchall()
    for r in rows:
        try:
            path = os.path.join(UPLOAD_DIR, r[0])
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
    # delete related records
    cursor.execute('DELETE FROM ratings WHERE user_id = ?', (user_id,))
    cursor.execute('DELETE FROM reactions WHERE user_id = ?', (user_id,))
    cursor.execute('DELETE FROM comments WHERE user_id = ?', (user_id,))
    cursor.execute('DELETE FROM media WHERE user_id = ?', (user_id,))
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash('User and related content deleted', 'success')
    return redirect(url_for('admin_actions'))


@app.route('/admin/suspend_user/<int:user_id>', methods=['POST'])
@role_required('admin')
def admin_suspend_user(user_id):
    days = request.form.get('days')
    try:
        days_i = int(days)
    except Exception:
        days_i = None
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    if days_i is None:
        flash('Invalid suspension duration', 'error')
        conn.close()
        return redirect(url_for('admin_actions'))
    if days_i == 0:
        # lift suspension
        cursor.execute('UPDATE users SET suspended_until = NULL WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        flash('Suspension lifted', 'success')
        return redirect(url_for('admin_actions'))
    # set suspended_until in UTC
    until = datetime.utcnow() + timedelta(days=days_i)
    until_str = until.replace(microsecond=0).isoformat()
    cursor.execute('UPDATE users SET suspended_until = ? WHERE id = ?', (until_str, user_id))
    conn.commit()
    conn.close()
    flash(f'User suspended for {days_i} day(s)', 'success')
    return redirect(url_for('admin_actions'))


@app.route('/admin/actions', methods=['GET', 'POST'])
@role_required('admin')
def admin_actions():
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    if request.method == 'POST':
        # create a creator account
        username = request.form.get('Username')
        email = request.form.get('Email')
        password = request.form.get('Password')
        if not (username and email and password):
            flash('All fields required', 'error')
            return redirect(url_for('admin_actions'))
        hashed = generate_password_hash(password)
        try:
            cursor.execute("INSERT INTO users (Username, Email, Password, Role) VALUES (?, ?, ?, ?)",
                           (username, email, hashed, 'creator'))
            conn.commit()
            flash('Creator account created', 'success')
        except sqlite3.IntegrityError:
            flash('Username/email already exists', 'error')

    # list creators and media for management
    cursor.execute("SELECT id, Username, Email, suspended_until FROM users WHERE Role = 'creator'")
    creators = cursor.fetchall()
    cursor.execute("SELECT m.id, m.Title, m.Filename, u.Username FROM media m JOIN users u ON m.user_id = u.id ORDER BY m.id DESC")
    media = cursor.fetchall()
    conn.close()
    return render_variant('admin_actions.html', creators=creators, media=media)


@app.route('/admin/set_variant', methods=['POST'])
@role_required('admin')
def admin_set_variant():
    user_id = request.form.get('user_id')
    variant = (request.form.get('ui_variant') or 'v1').strip()
    try:
        uid = int(user_id)
    except Exception:
        flash('Invalid user id', 'error')
        return redirect(url_for('admin_actions'))
    conn = sqlite3.connect('Instagram.db')
    cur = conn.cursor()
    try:
        cur.execute('UPDATE users SET ui_variant = ? WHERE id = ?', (variant, uid))
        conn.commit()
        flash(f"Set UI variant for user {uid} to {variant}", 'success')
    except Exception:
        flash('Failed to set variant', 'error')
    finally:
        conn.close()
    return redirect(url_for('admin_actions'))

@app.route('/login', methods=['GET', 'POST'])
def Login():
    if request.method == 'POST':
        # Get the form data
        Username = request.form['Username']
        Password = request.form['Password']
        # Connect to the database
        conn = sqlite3.connect('Instagram.db')
        cursor = conn.cursor()
        # Check if the user exists in the database
        cursor.execute("SELECT id, Password, Role FROM users WHERE Username = ?", (Username,))
        user = cursor.fetchone()
        conn.close()
        # Verify the password
        if user and check_password_hash(user[1], Password ):
            # If password matches, set the session and redirect to dashboard
            # Save user info into the session and make it persistent
            session.permanent = True
            session['id'] = user[0]  # Save user_id in session
            session['user'] = Username
            session['logged_in'] = True
            # save role explicitly (query returns id, Password, Role)
            try:
                session['role'] = user[2]
            except Exception:
                session['role'] = 'Consumer'
            # ensure session cookie is updated
            session.modified = True
            flash('Login Successful', 'success')
            print('Login successful')

            # Redirect based on role
            role = session.get('role')
            if role == 'admin':
                return redirect(url_for('admin'))
            elif role == 'creator':
                return redirect(url_for('creator_upload'))
            else:
                return redirect(url_for('Home'))
        else:
            # If login fails, show an error (this is basic, you might want to flash a message)
            flash("Invalid email or password", 'error')
            return redirect(url_for('Login'))
    return render_variant('login.html')


@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = (request.form.get('identifier') or '').strip()
        if not identifier:
            flash('Enter your username or email', 'error')
            return redirect(url_for('forgot_password'))
        # rate limit by IP and identifier
        ip = request.remote_addr or 'anon'
        if not check_rate_limit(f'forgot:ip:{ip}', limit=10, period_seconds=3600):
            logger.warning('Rate limit exceeded for forgot by IP %s', ip)
            flash('Too many requests from your IP. Try again later.', 'error')
            return redirect(url_for('forgot_password'))
        if not check_rate_limit(f'forgot:ident:{identifier}', limit=3, period_seconds=24*3600):
            logger.warning('Rate limit exceeded for forgot by identifier %s', identifier)
            flash('Too many requests for this account. Try again later.', 'error')
            return redirect(url_for('forgot_password'))

        conn = sqlite3.connect('Instagram.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, Email, Username FROM users WHERE Username = ? OR Email = ? LIMIT 1", (identifier, identifier))
        user = cursor.fetchone()
        conn.close()

        # For security we don't reveal whether the identifier exists. Always show a
        # generic success message to the user. Internally we log and attempt to send
        # an email only when an account is found.
        if not user:
            logger.info('Forgot password requested for unknown identifier: %s from %s', identifier, ip)
            # Generic message (do not reveal existence)
            flash('If an account with that username/email exists, a reset link has been sent to the associated email address.', 'success')
            return redirect(url_for('Login'))

        user_id = user[0]
        user_email = user[1]
        # generate token
        token = serializer.dumps({'user_id': user_id})
        reset_url = url_for('reset_password', token=token, _external=True)

        sent = False
        if user_email:
            sent = send_reset_email(user_email, reset_url)
            if sent:
                logger.info('Reset email sent to %s for user id %s (request from %s)', user_email, user_id, ip)
            else:
                logger.warning('Failed to send reset email to %s for user id %s (request from %s)', user_email, user_id, ip)

        # Regardless of send success, don't reveal details to the user
        flash('If an account with that username/email exists, a reset link has been sent to the associated email address.', 'success')
        return redirect(url_for('Login'))

    return render_variant('forgot.html')


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        data = serializer.loads(token, max_age=3600)
    except SignatureExpired:
        flash('Token expired. Please request a new password reset.', 'error')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('Invalid token. Please request a new password reset.', 'error')
        return redirect(url_for('forgot_password'))

    user_id = data.get('user_id')
    if request.method == 'POST':
        ip = request.remote_addr or 'anon'
        # limit reset attempts per IP to avoid brute-forcing tokens
        if not check_rate_limit(f'reset:ip:{ip}', limit=20, period_seconds=3600):
            logger.warning('Rate limit exceeded for reset attempts from %s', ip)
            flash('Too many attempts. Try again later.', 'error')
            return redirect(url_for('forgot_password'))

        password = request.form.get('Password')
        password2 = request.form.get('Password2')
        if not password or not password2:
            flash('Please enter and confirm your new password', 'error')
            return redirect(url_for('reset_password', token=token))
        if password != password2:
            flash('Passwords do not match', 'error')
            return redirect(url_for('reset_password', token=token))

        hashed = generate_password_hash(password, method='pbkdf2:sha256')
        conn = sqlite3.connect('Instagram.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET Password = ? WHERE id = ?", (hashed, user_id))
        conn.commit()
        conn.close()

        logger.info('Password reset for user id %s from IP %s', user_id, ip)
        flash('Password updated. You can now log in.', 'success')
        return redirect(url_for('Login'))

    return render_variant('reset_password.html')
@app.route('/home')
def Home():
    # show recent media for all consumers
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    cursor.execute("SELECT m.id, m.Title, m.Caption, m.Filename, u.Username, u.id FROM media m JOIN users u ON m.user_id = u.id ORDER BY m.id DESC")
    rows = cursor.fetchall()

    media = []
    for r in rows:
        mid = r[0]
        # counts
        cursor.execute("SELECT COUNT(*) FROM comments WHERE media_id = ?", (mid,))
        comments_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM reactions WHERE media_id = ?", (mid,))
        reactions_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM reactions WHERE media_id = ? AND type = 'thumbs_up'", (mid,))
        likes_count = cursor.fetchone()[0]
        cursor.execute("SELECT AVG(rating) FROM ratings WHERE media_id = ?", (mid,))
        avg_row = cursor.fetchone()
        rating_avg = None
        if avg_row and avg_row[0] is not None:
            rating_avg = round(avg_row[0], 2)
        # share count
        cursor.execute('SELECT COALESCE(share_count,0) FROM media WHERE id = ?', (mid,))
        sc_row = cursor.fetchone()
        share_count = int(sc_row[0]) if sc_row and sc_row[0] is not None else 0

        media.append({
            'id': mid,
            'title': r[1],
            'caption': r[2],
            'filename': r[3],
            'username': r[4],
            'user_id': r[5],
            'comments_count': comments_count,
            'reactions_count': reactions_count,
            'likes_count': likes_count,
            'rating_avg': rating_avg,
            'share_count': share_count,
        })

    # if consumer logged in, fetch list of creators they follow
    following_set = set()
    if session.get('logged_in') and session.get('role') == 'Consumer':
        try:
            user_id = session.get('id')
            cursor = conn.cursor()
            cursor.execute('SELECT creator_id FROM follows WHERE follower_id = ?', (user_id,))
            following_set = {r[0] for r in cursor.fetchall()}
        except Exception:
            following_set = set()
    conn.close()
    return render_variant('home.html', media=media, following=following_set)


@app.route('/creator/upload', methods=['GET', 'POST'])
@role_required('creator')
def creator_upload():
    if request.method == 'POST':
        title = request.form.get('Title')
        caption = request.form.get('Caption')
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('No file uploaded', 'error')
            return redirect(url_for('creator_upload'))
        filename = secure_filename(file.filename)
        save_path = os.path.join(UPLOAD_DIR, filename)
        file.save(save_path)
        conn = sqlite3.connect('Instagram.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO media (user_id, Title, Caption, Filename) VALUES (?, ?, ?, ?)",
                       (session.get('id'), title, caption, filename))
        conn.commit()
        # get id of the new media and notify followers with a clickable link
        try:
            new_media_id = cursor.lastrowid
            creator_id = session.get('id')
            cursor.execute('SELECT follower_id FROM follows WHERE creator_id = ?', (creator_id,))
            followers = [r[0] for r in cursor.fetchall()]
            try:
                # make an absolute URL for the media detail (external so notifications have full link)
                media_url = url_for('media_detail', media_id=new_media_id, _external=True)
            except Exception:
                media_url = f"/media/{new_media_id}"
            title_text = (title or 'a new post')
            msg = f"{session.get('user')} posted {title_text}: {media_url}"
            for fid in followers:
                cursor.execute('INSERT INTO notifications (user_id, message) VALUES (?, ?)', (fid, msg))
            conn.commit()
        except Exception:
            # do not block upload on notification failures
            pass
        conn.close()
        flash('Uploaded', 'success')
        return redirect(url_for('creator_upload'))
    
    # Fetch creator's own posts
    creator_id = session.get('id')
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    cursor.execute('SELECT m.id, m.Title, m.Caption, m.Filename FROM media m WHERE m.user_id = ? ORDER BY m.id DESC', (creator_id,))
    rows = cursor.fetchall()
    media = []
    for r in rows:
        mid = r[0]
        cursor.execute("SELECT COUNT(*) FROM comments WHERE media_id = ?", (mid,))
        comments_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM reactions WHERE media_id = ?", (mid,))
        reactions_count = cursor.fetchone()[0]
        cursor.execute("SELECT AVG(rating) FROM ratings WHERE media_id = ?", (mid,))
        avg_row = cursor.fetchone()
        rating_avg = None
        if avg_row and avg_row[0] is not None:
            rating_avg = round(avg_row[0], 2)
        cursor.execute('SELECT COALESCE(share_count,0) FROM media WHERE id = ?', (mid,))
        sc_row = cursor.fetchone()
        share_count = int(sc_row[0]) if sc_row and sc_row[0] is not None else 0
        media.append({
            'id': mid,
            'title': r[1],
            'caption': r[2],
            'filename': r[3],
            'comments_count': comments_count,
            'reactions_count': reactions_count,
            'rating_avg': rating_avg,
            'share_count': share_count,
        })
    conn.close()
    return render_variant('creator_upload.html', media=media)


@app.route('/media/<int:media_id>', methods=['GET', 'POST'])
def media_detail(media_id):
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    if request.method == 'POST':
        action = request.form.get('action')
        # Only consumers may interact (comment/react/rate)
        if session.get('logged_in') and session.get('role') == 'Consumer':
            if action == 'comment':
                comment = (request.form.get('comment') or '').strip()
                if comment:
                    cursor.execute("INSERT INTO comments (media_id, user_id, comment) VALUES (?, ?, ?)",
                                   (media_id, session.get('id'), comment))
                    conn.commit()
                    flash('Comment added', 'success')
                else:
                    flash('Comment cannot be empty', 'error')
            elif action == 'comment_reply':
                parent_id = request.form.get('parent_id')
                comment = (request.form.get('comment') or '').strip()
                try:
                    pid = int(parent_id)
                except Exception:
                    pid = None
                if comment and pid:
                    cursor.execute("INSERT INTO comments (media_id, user_id, comment, parent_id) VALUES (?, ?, ?, ?)",
                                   (media_id, session.get('id'), comment, pid))
                    conn.commit()
                    flash('Reply added', 'success')
                else:
                    flash('Reply failed', 'error')
            elif action == 'comment_like':
                try:
                    cid = int(request.form.get('comment_id'))
                except Exception:
                    cid = None
                if cid:
                    # toggle like for this user/comment
                    cursor.execute('SELECT id FROM comment_likes WHERE comment_id = ? AND user_id = ?', (cid, session.get('id')))
                    ex = cursor.fetchone()
                    if ex:
                        cursor.execute('DELETE FROM comment_likes WHERE id = ?', (ex[0],))
                        conn.commit()
                        flash('Comment like removed', 'success')
                    else:
                        cursor.execute('INSERT INTO comment_likes (comment_id, user_id) VALUES (?, ?)', (cid, session.get('id')))
                        conn.commit()
                        flash('Comment liked', 'success')
                else:
                    flash('Invalid comment', 'error')
            elif action == 'react':
                rtype = request.form.get('reaction')
                if rtype:
                    # one reaction per user per media: toggle or update
                    cursor.execute("SELECT id, type FROM reactions WHERE media_id = ? AND user_id = ?", (media_id, session.get('id')))
                    existing = cursor.fetchone()
                    if existing:
                        rid, etype = existing[0], existing[1]
                        if etype == rtype:
                            # same reaction clicked again -> remove (toggle off)
                            cursor.execute("DELETE FROM reactions WHERE id = ?", (rid,))
                            conn.commit()
                            flash('Reaction removed', 'success')
                        else:
                            # change reaction type
                            cursor.execute("UPDATE reactions SET type = ?, created_at = CURRENT_TIMESTAMP WHERE id = ?", (rtype, rid))
                            conn.commit()
                            flash('Reaction updated', 'success')
                    else:
                        cursor.execute("INSERT INTO reactions (media_id, user_id, type) VALUES (?, ?, ?)",
                                       (media_id, session.get('id'), rtype))
                        conn.commit()
                        flash('Reacted', 'success')
                else:
                    flash('No reaction selected', 'error')
            elif action == 'rate':
                try:
                    rating = int(request.form.get('rating') or 0)
                    if 1 <= rating <= 10:
                        # upsert: update existing rating or insert new
                        cursor.execute("SELECT id FROM ratings WHERE media_id = ? AND user_id = ?", (media_id, session.get('id')))
                        existing_rating = cursor.fetchone()
                        if existing_rating:
                            cursor.execute("UPDATE ratings SET rating = ?, created_at = CURRENT_TIMESTAMP WHERE id = ?", (rating, existing_rating[0]))
                            conn.commit()
                            flash('Rating updated', 'success')
                        else:
                            cursor.execute("INSERT INTO ratings (media_id, user_id, rating) VALUES (?, ?, ?)",
                                           (media_id, session.get('id'), rating))
                            conn.commit()
                            flash('Thanks for rating', 'success')
                    else:
                        flash('Rating must be between 1 and 10', 'error')
                except ValueError:
                    flash('Invalid rating', 'error')
            else:
                flash('Unknown action', 'error')
        else:
            flash('You must be logged in as a consumer to interact', 'error')
    # fetch media
    cursor.execute("SELECT m.id, m.Title, m.Caption, m.Filename, u.Username FROM media m JOIN users u ON m.user_id = u.id WHERE m.id = ?", (media_id,))
    media = cursor.fetchone()
    # fetch creator id for linking to profile
    creator_id = None
    if media:
        try:
            cursor.execute('SELECT user_id FROM media WHERE id = ?', (media_id,))
            r = cursor.fetchone()
            if r:
                creator_id = r[0]
        except Exception:
            creator_id = None
    # comments and reactions: fetch flat rows then build nested reply tree
    cursor.execute("SELECT c.comment, u.Username, c.created_at, c.id, c.parent_id FROM comments c JOIN users u ON c.user_id = u.id WHERE c.media_id = ? ORDER BY c.id DESC", (media_id,))
    comment_rows = cursor.fetchall()
    # comment like counts for this media
    cursor.execute("SELECT comment_id, COUNT(*) FROM comment_likes WHERE comment_id IN (SELECT id FROM comments WHERE media_id = ?) GROUP BY comment_id", (media_id,))
    _likes = cursor.fetchall()
    comment_likes_map = {r[0]: r[1] for r in _likes} if _likes else {}

    # Build comment objects and thread replies under parents (one level nesting)
    comments_by_id = {}
    top_level_comments = []
    for row in comment_rows:
        text, username, created_at, cid, parent_id = row
        comments_by_id[cid] = {
            'id': cid,
            'user': username,
            'text': text,
            'created_at': created_at,
            'likes': int(comment_likes_map.get(cid, 0)),
            'replies': []
        }
    # attach replies to parents
    for row in comment_rows:
        cid = row[3]
        parent_id = row[4]
        comment_obj = comments_by_id.get(cid)
        if parent_id and parent_id in comments_by_id:
            comments_by_id[parent_id]['replies'].append(comment_obj)
        else:
            top_level_comments.append(comment_obj)

    comments = top_level_comments
    cursor.execute("SELECT type, COUNT(*) FROM reactions WHERE media_id = ? GROUP BY type", (media_id,))
    reactions = cursor.fetchall()
    # build a map for easy template access
    reactions_map = {r[0]: r[1] for r in reactions} if reactions else {}
    reactions_total = sum(reactions_map.values()) if reactions_map else 0
    likes_count = reactions_map.get('thumbs_up', 0)
    # average rating
    cursor.execute("SELECT AVG(rating) FROM ratings WHERE media_id = ?", (media_id,))
    avg_row = cursor.fetchone()
    rating_avg = None
    if avg_row and avg_row[0] is not None:
        rating_avg = round(avg_row[0], 2)
    # also fetch current share_count
    share_count = 0
    try:
        cursor2 = conn.cursor()
        cursor2.execute('SELECT COALESCE(share_count,0) FROM media WHERE id = ?', (media_id,))
        rsc = cursor2.fetchone()
        if rsc and rsc[0] is not None:
            share_count = int(rsc[0])
    except Exception:
        share_count = 0
    conn.close()
    return render_variant('media_detail.html', media=media, creator_id=creator_id, comments=comments, comment_likes=comment_likes_map, reactions_map=reactions_map, reactions_total=reactions_total, likes_count=likes_count, rating_avg=rating_avg, share_count=share_count)


@app.route('/uploads/<path:filename>')
def uploads(filename):
    return send_from_directory(UPLOAD_DIR, filename)


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'success')
    return redirect(url_for('landing'))


# Check suspension status on every request for logged-in users.
@app.before_request
def check_suspension():
    # allow public endpoints
    public_paths = ('/login', '/signup', '/forgot', '/reset')
    path = request.path or ''
    if any(path.startswith(p) for p in public_paths):
        return
    if session.get('logged_in'):
        user_id = session.get('id')
        if not user_id:
            return
        conn = sqlite3.connect('Instagram.db')
        cursor = conn.cursor()
        cursor.execute('SELECT suspended_until FROM users WHERE id = ?', (user_id,))
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            try:
                suspended_until = datetime.fromisoformat(row[0])
            except Exception:
                # if parsing fails, treat as not suspended
                return
            now = datetime.utcnow()
            if suspended_until > now:
                # user is suspended - show suspended page for any request except the suspended page itself
                if not path.startswith('/suspended'):
                    return redirect(url_for('suspended'))
            else:
                # suspension expired -> clear it
                conn = sqlite3.connect('Instagram.db')
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET suspended_until = NULL WHERE id = ?', (user_id,))
                conn.commit()
                conn.close()


@app.route('/suspended')
def suspended():
    if not session.get('logged_in'):
        return redirect(url_for('Login'))
    user_id = session.get('id')
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    cursor.execute('SELECT suspended_until FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row or not row[0]:
        # not suspended; redirect home
        flash('Your account is active.', 'success')
        return redirect(url_for('Home'))
    try:
        suspended_until = datetime.fromisoformat(row[0])
    except Exception:
        suspended_until = None
    return render_variant('suspended.html', until=suspended_until)


@app.route('/creator/<int:user_id>')
def creator_profile(user_id):
    # public view of a creator's posts
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    # allow viewing creator profile even if Role casing differs or missing
    cursor.execute('SELECT Username FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    if not row:
        flash('Creator not found', 'error')
        return redirect(url_for('Home'))
    username = row[0]
    cursor.execute('SELECT m.id, m.Title, m.Caption, m.Filename FROM media m WHERE m.user_id = ? ORDER BY m.id DESC', (user_id,))
    rows = cursor.fetchall()
    media = []
    for r in rows:
        mid = r[0]
        cursor.execute("SELECT COUNT(*) FROM comments WHERE media_id = ?", (mid,))
        comments_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM reactions WHERE media_id = ?", (mid,))
        reactions_count = cursor.fetchone()[0]
        cursor.execute("SELECT AVG(rating) FROM ratings WHERE media_id = ?", (mid,))
        avg_row = cursor.fetchone()
        rating_avg = None
        if avg_row and avg_row[0] is not None:
            rating_avg = round(avg_row[0], 2)
        cursor.execute('SELECT COALESCE(share_count,0) FROM media WHERE id = ?', (mid,))
        sc_row = cursor.fetchone()
        share_count = int(sc_row[0]) if sc_row and sc_row[0] is not None else 0
        media.append({
            'id': mid,
            'title': r[1],
            'caption': r[2],
            'filename': r[3],
            'comments_count': comments_count,
            'reactions_count': reactions_count,
            'rating_avg': rating_avg,
            'share_count': share_count,
        })
    # determine whether current user follows this creator
    is_following = False
    if session.get('logged_in') and session.get('role') == 'Consumer':
        try:
            conn2 = sqlite3.connect('Instagram.db')
            cur2 = conn2.cursor()
            cur2.execute('SELECT 1 FROM follows WHERE follower_id = ? AND creator_id = ? LIMIT 1', (session.get('id'), user_id))
            is_following = cur2.fetchone() is not None
            conn2.close()
        except Exception:
            is_following = False
    conn.close()
    return render_variant('creator_profile.html', username=username, media=media, creator_id=user_id, is_following=is_following)


@app.route('/messages')
def messages():
    if not session.get('logged_in'):
        flash('Please login to view messages', 'error')
        return redirect(url_for('Login'))
    user_id = session.get('id')
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    # Find recent conversation partners and latest message per partner
    cursor.execute('''
                SELECT q.other_id, u.Username, m.latest_body, q.latest_at, q.unread_count
                FROM (
                    SELECT CASE WHEN sender_id = ? THEN recipient_id ELSE sender_id END as other_id,
                                 MAX(created_at) as latest_at,
                                 SUM(CASE WHEN recipient_id = ? AND read_flag = 0 THEN 1 ELSE 0 END) as unread_count
                    FROM messages
                    WHERE sender_id = ? OR recipient_id = ?
                    GROUP BY other_id
                ) q
                JOIN (
                    SELECT sender_id, recipient_id, body as latest_body, created_at FROM messages
                ) m ON m.created_at = q.latest_at
                JOIN users u ON u.id = q.other_id
                ORDER BY q.latest_at DESC
        ''', (user_id, user_id, user_id, user_id))
    rows = cursor.fetchall()
    # rows may be empty; provide a simple list
    convs = []
    for r in rows:
        convs.append({'other_id': r[0], 'username': r[1], 'latest_body': r[2], 'latest_at': r[3], 'unread_count': r[4]})
    conn.close()
    return render_variant('messages.html', convs=convs)


# Chat endpoints removed: /chat/conversations.json


# def chat_find_user():
# # Chat endpoints removed: /chat/find_user.json


# def chat_messages_json(other_id):
# # Chat endpoints removed: /chat/messages/<other_id>.json


# def chat_send(other_id):
# # Chat endpoints removed: /chat/send/<other_id>



@app.route('/share/<int:media_id>', methods=['POST'])
def share_media(media_id):
    """Share a media item with another user.
    Accepts form or JSON payloads. Fields supported:
      - to (user id) or to_username (username)
    Creates an in-app message and a notification for the recipient with a link to the media.
    """
    # Require login for sharing
    if not session.get('logged_in'):
        return {'ok': False, 'error': 'login_required'}, 401

    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()

    # Logged-in users may optionally provide a recipient to send an in-app message
    me = session.get('id')
    data_to = None
    if request.is_json:
        payload = request.get_json() or {}
        data_to = payload.get('to') or payload.get('to_username')
    else:
        data_to = request.form.get('to') or request.form.get('to_username')

    recipient_id = None
    if data_to:
        try:
            recipient_id = int(data_to)
        except Exception:
            try:
                cursor.execute('SELECT id FROM users WHERE Username = ? LIMIT 1', (data_to,))
                r = cursor.fetchone()
                if r:
                    recipient_id = r[0]
            except Exception:
                recipient_id = None

    try:
        try:
            media_url = url_for('media_detail', media_id=media_id, _external=True)
        except Exception:
            media_url = f"/media/{media_id}"

        # create in-app message / notification only when recipient resolved and not self
        if recipient_id and recipient_id != me:
            body = f"{session.get('user')} shared a post with you: {media_url}"
            try:
                cursor.execute('INSERT INTO messages (sender_id, recipient_id, body) VALUES (?, ?, ?)', (me, recipient_id, body))
                cursor.execute('INSERT INTO notifications (user_id, message, target_url) VALUES (?, ?, ?)', (recipient_id, body, media_url))
            except Exception:
                # non-fatal; continue to increment share_count
                pass

        # increment media share count
        try:
            cursor.execute('UPDATE media SET share_count = COALESCE(share_count,0) + 1 WHERE id = ?', (media_id,))
        except Exception:
            pass
        conn.commit()
    except Exception:
        conn.close()
        return {'ok': False, 'error': 'failed'}, 500

    # return new share count for client convenience
    try:
        cursor.execute('SELECT COALESCE(share_count,0) FROM media WHERE id = ?', (media_id,))
        sc = cursor.fetchone()
        count = int(sc[0]) if sc and sc[0] is not None else 0
    except Exception:
        count = 0
    conn.close()
    return {'ok': True, 'share_count': count}


@app.route('/messages/<int:other_id>', methods=['GET', 'POST'])
def conversation(other_id):
    if not session.get('logged_in'):
        flash('Please login to view messages', 'error')
        return redirect(url_for('Login'))
    me = session.get('id')
    # prevent messaging yourself
    if me == other_id:
        flash('Cannot message yourself', 'error')
        return redirect(url_for('messages'))

    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    # fetch messages between the two users
    if request.method == 'POST':
        body = (request.form.get('body') or '').strip()
        if body:
            cursor.execute('INSERT INTO messages (sender_id, recipient_id, body) VALUES (?, ?, ?)', (me, other_id, body))
            conn.commit()
        return redirect(url_for('conversation', other_id=other_id))

    cursor.execute('SELECT Username FROM users WHERE id = ?', (other_id,))
    row = cursor.fetchone()
    if not row:
        flash('User not found', 'error')
        conn.close()
        return redirect(url_for('messages'))
    other_name = row[0]
    cursor.execute('SELECT sender_id, recipient_id, body, created_at FROM messages WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?) ORDER BY created_at ASC', (me, other_id, other_id, me))
    msgs = cursor.fetchall()
    # mark messages received by me as read
    cursor.execute('UPDATE messages SET read_flag = 1 WHERE recipient_id = ? AND sender_id = ?', (me, other_id))
    conn.commit()
    conn.close()
    return render_template('conversation.html', other_id=other_id, other_name=other_name, msgs=msgs)


@app.route('/follow/<int:creator_id>', methods=['POST'])
def follow_creator(creator_id):
    # only consumers may follow creators
    if not session.get('logged_in') or session.get('role') != 'Consumer':
        flash('You must be logged in as a consumer to follow creators', 'error')
        return redirect(request.referrer or url_for('Home'))
    follower_id = session.get('id')
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    try:
        # check creator exists and is a creator
        cursor.execute('SELECT id FROM users WHERE id = ? AND Role = "creator"', (creator_id,))
        if not cursor.fetchone():
            flash('Creator not found', 'error')
            conn.close()
            return redirect(request.referrer or url_for('Home'))
        # toggle follow: if exists -> unfollow, else follow
        cursor.execute('SELECT id FROM follows WHERE follower_id = ? AND creator_id = ?', (follower_id, creator_id))
        existing = cursor.fetchone()
        if existing:
            cursor.execute('DELETE FROM follows WHERE id = ?', (existing[0],))
            conn.commit()
            flash('Unfollowed', 'success')
        else:
            cursor.execute('INSERT INTO follows (follower_id, creator_id) VALUES (?, ?)', (follower_id, creator_id))
            conn.commit()
            # create a notification (optional) to confirm follow
            try:
                msg = f'You started following {creator_id}'
                cursor.execute('INSERT INTO notifications (user_id, message) VALUES (?, ?)', (follower_id, msg))
                conn.commit()
            except Exception:
                pass
            flash('Following', 'success')
    except Exception:
        flash('Follow action failed', 'error')
    finally:
        conn.close()
    return redirect(request.referrer or url_for('creator_profile', user_id=creator_id))


@app.route('/notifications')
def notifications():
    # show notifications for the logged-in user and mark them read on visit
    if not session.get('logged_in'):
        flash('Please login to view notifications', 'error')
        return redirect(url_for('Login'))
    uid = session.get('id')
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, message, created_at, read_flag FROM notifications WHERE user_id = ? ORDER BY created_at DESC', (uid,))
    rows = cursor.fetchall()
    # convert to dicts for template ease
    notes = []
    for r in rows:
        notes.append({'id': r[2], 'message': r[1], 'created_at': r[2], 'read_flag': r[3]})
    # mark unread notifications as read (simple: mark all read on visit)
    try:
        cursor.execute('UPDATE notifications SET read_flag = 1 WHERE user_id = ? AND read_flag = 0', (uid,))
        conn.commit()
    except Exception:
        pass
    conn.close()
    return render_template('notifications.html', notifications=notes)


@app.route('/notifications/json')
def notifications_json():
    """Return recent notifications as JSON for AJAX dropdown consumption."""
    if not session.get('logged_in'):
        return {'ok': False, 'error': 'login_required'}, 401
    uid = session.get('id')
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, message, target_url, created_at, read_flag FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20', (uid,))
    rows = cursor.fetchall()
    notes = []
    for r in rows:
        notes.append({'id': r[0], 'message': r[1], 'target_url': r[2], 'created_at': r[3], 'read_flag': r[4]})
    # unread count
    cursor.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_flag = 0', (uid,))
    unread = cursor.fetchone()[0]
    conn.close()
    return {'ok': True, 'unread': int(unread or 0), 'notifications': notes}


@app.route('/notifications/mark_all_read', methods=['POST'])
def notifications_mark_all_read():
    if not session.get('logged_in'):
        return {'ok': False, 'error': 'login_required'}, 401
    uid = session.get('id')
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    try:
        cursor.execute('UPDATE notifications SET read_flag = 1 WHERE user_id = ? AND read_flag = 0', (uid,))
        conn.commit()
    except Exception:
        conn.close()
        return {'ok': False, 'error': 'failed'}, 500
    conn.close()
    return {'ok': True, 'unread': 0}


@app.route('/notifications/mark_read/<int:notif_id>', methods=['POST'])
def notifications_mark_read(notif_id):
    if not session.get('logged_in'):
        return {'ok': False, 'error': 'login_required'}, 401
    uid = session.get('id')
    conn = sqlite3.connect('Instagram.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM notifications WHERE id = ? AND user_id = ?', (notif_id, uid))
    if not cursor.fetchone():
        conn.close()
        return {'ok': False, 'error': 'not_found'}, 404
    try:
        cursor.execute('UPDATE notifications SET read_flag = 1 WHERE id = ?', (notif_id,))
        conn.commit()
    except Exception:
        conn.close()
        return {'ok': False, 'error': 'failed'}, 500
    conn.close()
    return {'ok': True}


if __name__ == '__main__':
    # Only run the server when executed directly. This makes importing app2 in tests safe.
    # If SocketIO is available, use it to run the server so realtime works. Otherwise fall back to Flask dev server.
    # if socketio is not None:
    #     socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    # else:
    app.run(debug=True, host='0.0.0.0', port=5000)