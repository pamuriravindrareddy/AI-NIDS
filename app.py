# app.py
import sys
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

import os
import re
import json
import time
import sqlite3
import socket
import smtplib
import pandas as pd
import numpy as np
import traceback
import geoip2.database
from email.mime.text import MIMEText
from flask import (
    Flask, render_template, request, redirect,
    url_for, jsonify, session, g, make_response
)
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
from threading import Lock
from functools import wraps
from collections import defaultdict

# Local Imports
import threading
from inference import predict_flow, explain_flow, set_detector_params, get_detector_info, get_model_health
from utils import (
    init_db, log_prediction, DB_PATH, get_metrics_data, get_all_logs_csv,
    get_live_stats, add_alert_subscriber, remove_alert_subscriber, get_alert_subscribers,
    get_severity, get_protocol_name, get_geoip_details, get_admin_overview_data, get_historical_flows,
    find_user_by_login_id, DESIGNATED_ADMIN_EMAIL,
    block_ip_firewall, unblock_ip_firewall, get_active_blocked_ips, get_all_blocked_ips, cleanup_expired_firewall_blocks,
    send_webhook_alert, format_webhook_payload,
    get_ip_threat_reputation, get_recent_threat_intel,
    submit_flow_feedback, get_feedback_summary, get_prediction_by_id
)


# ===============================================================
# CENTRAL BRANDING CONFIGURATION
# ===============================================================
APP_NAME = "AI-NIDS"
APP_FULL_NAME = "AI-Powered Network Intrusion Detection System"
APP_DASHBOARD_TITLE = "AI-NIDS Dashboard"
APP_MONITOR_TITLE = "AI-NIDS Monitor"
APP_ALERT_PREFIX = "AI-NIDS Security Alert"

# ===============================================================
# Configuration & Globals
# ===============================================================
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'ai-nids-secret-key-2026')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Login rate limiting state
LOGIN_ATTEMPTS = defaultdict(list)
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300  # 5 minutes

@app.context_processor
def inject_branding():
    return {
        'APP_NAME': APP_NAME,
        'APP_FULL_NAME': APP_FULL_NAME,
        'APP_DASHBOARD_TITLE': APP_DASHBOARD_TITLE,
        'APP_MONITOR_TITLE': APP_MONITOR_TITLE,
        'APP_ALERT_PREFIX': APP_ALERT_PREFIX,
        'current_user': session.get('user'),
        'current_role': session.get('role', 'user'),
    }

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
init_db()

# Global Session Stats & Markers (Persist across page changes)
SESSION_STATS = {
    'packets': 0,
    'attacks': 0,
    'start_time': time.time()
}
RECENT_GEO_MARKERS = []

# Simulation Control State
SIMULATION_STATE = {
    'running': False,
    'speed': 1.0,
    'thread': None
}

# Global Node & Firewall Config
IOT_CONFIG = {
    'device_name': 'AI-NIDS Gateway Node',
    'ip_address': '127.0.0.1',
    'ipv4_enabled': True,
    'tcp_enabled': True,
    'syn_flood_rule': False,
    'ips_auto_block': True,
    'ips_block_threshold': 0.90,
    'ips_block_duration': 15,
    'webhook_enabled': False,
    'webhook_url': '',
    'abuseipdb_enabled': False,
    'abuseipdb_api_key': '',
    'admin_email': DESIGNATED_ADMIN_EMAIL,
    'status': 'OFF'  # ON/OFF
}

# ===============================================================
# EMAIL CONFIGURATION (CRITICAL SECTION)
# ===============================================================
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

# ✅ Configured sender email:
SMTP_USER = 'ravindra.23bce9622@vitapstudent.ac.in' 

# ✅ Google App Password:
SMTP_PASS = 'xhfngoakwnzuaixy'

# Rate limit emails to avoid spamming (1 email per minute)
last_email_time = 0

# GeoIP Setup
GEOIP_DB = 'GeoLite2-City.mmdb'
try:
    geoip_reader = geoip2.database.Reader(GEOIP_DB)
    print(f"[INFO] ✅ GeoIP DB loaded: {GEOIP_DB}")
except FileNotFoundError:
    print("[WARN] ⚠️ GeoLite2-City.mmdb not found. Random coords will be used.")
    geoip_reader = None

# Threading for Replay
thread = None
thread_lock = Lock()

# ===============================================================
# Helpers
# ===============================================================
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')

def is_valid_email(email: str) -> bool:
    """Validate email address format strictly."""
    if not email or not isinstance(email, str):
        return False
    email = email.strip()
    if len(email) > 254:
        return False
    if not EMAIL_REGEX.match(email):
        return False
    parts = email.split('@')
    if len(parts) != 2:
        return False
    domain = parts[1]
    if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
        return False
    if '..' in email:
        return False
    return True

def get_local_ip():
    """Fetch local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# Initialize IP in config
IOT_CONFIG['ip_address'] = get_local_ip()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'status': 'error', 'message': 'Authentication required. Please log in.'}), 401
            return redirect(url_for('login', next=request.path))

        sess_role = session.get('role')
        sess_email = (session.get('email') or '').strip().lower()
        sess_user = (session.get('user') or '').strip().lower()

        # Strict single-owner check: must have 'admin' role AND match designated admin identity
        is_owner = (
            sess_role == 'admin' and (
                sess_email == DESIGNATED_ADMIN_EMAIL.lower() or
                sess_user == DESIGNATED_ADMIN_EMAIL.lower() or
                sess_user == 'apashamkirikiri320'
            )
        )

        if not is_owner:
            if request.path.startswith('/api/'):
                return jsonify({'status': 'error', 'message': 'Forbidden: Designated administrator privileges required.'}), 403
            return render_template('403.html', user=session.get('user')), 403

        return f(*args, **kwargs)
    return wrapped



def send_alert_email(attack_type, details):
    """Send SMTP notification to admin and subscribed users in a non-blocking background thread."""
    global last_email_time
    
    # Collect all recipients: Admin email + user subscribers
    recipients = []
    admin_addr = IOT_CONFIG.get('admin_email')
    if admin_addr and is_valid_email(admin_addr):
        recipients.append(admin_addr.strip().lower())
    
    try:
        subs = get_alert_subscribers()
        for s in subs:
            if s and is_valid_email(s) and s.strip().lower() not in recipients:
                recipients.append(s.strip().lower())
    except Exception as e:
        print(f"[WARN] Could not retrieve alert subscribers: {e}")

    if not recipients:
        return
    
    # Rate limit: Only send 1 email batch every 60 seconds
    now = time.time()
    if now - last_email_time < 60:
        return

    # Update timestamp immediately to prevent concurrent floods
    last_email_time = now

    def _worker():
        try:
            src_ip = details.get('src_ip', 'Unknown')
            dst_ip = details.get('dst_ip', 'Unknown')
            score = details.get('attack_score', 1.0)
            reason = details.get('reason', 'Threat Signature Detected')
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(details.get('ts', time.time())))
            
            body = f"""⚠️ AI-NIDS SECURITY INTRUSION ALERT ⚠️
============================================================
The AI-Powered Network Intrusion Detection System (AI-NIDS) has detected malicious network activity.

[INCIDENT SUMMARY]
• Attack Classification: {attack_type}
• Detection Mechanism : {reason}
• Anomaly / Attack Score: {score:.4f}
• Detection Timestamp  : {ts}
• Attacker Source IP   : {src_ip}
• Target Destination IP: {dst_ip}
• Target Network Node  : {IOT_CONFIG.get('device_name', 'AI-NIDS Gateway Node')} ({IOT_CONFIG.get('ip_address', '127.0.0.1')})

[RECOMMENDED MITIGATION]
1. Open the AI-NIDS Monitor dashboard (http://localhost:5000/prediction) to observe active traffic.
2. Consider applying IP firewall rules to isolate or block {src_ip}.
3. Review threat metrics and classification telemetry at http://localhost:5000/analysis.

============================================================
Automated alert dispatched from AI-NIDS Security Admin ({SMTP_USER}).
"""
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                for target_email in recipients:
                    try:
                        msg = MIMEText(body)
                        msg['Subject'] = f"[{APP_ALERT_PREFIX}] {attack_type} Detected from {src_ip}"
                        msg['From'] = SMTP_USER
                        msg['To'] = target_email
                        server.send_message(msg)
                        print(f"[EMAIL] 📧 Alert successfully delivered to {target_email}")
                        socketio.emit('email_alert_sent', {
                            'recipient': target_email,
                            'type': attack_type,
                            'src_ip': src_ip,
                            'time': ts
                        })
                    except Exception as deliver_err:
                        print(f"[EMAIL ERROR] Failed delivery to {target_email}: {deliver_err}")

        except Exception as e:
            print(f"[EMAIL ERROR] ❌ Failed to dispatch email alerts: {e}")

    threading.Thread(target=_worker, daemon=True).start()

# ===============================================================
# Routes
# ===============================================================
@app.route('/')
def index():
    return render_template('index.html', config=IOT_CONFIG)

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    if request.method == 'POST':
        # Update Config
        IOT_CONFIG['device_name'] = request.form.get('device_name', IOT_CONFIG['device_name'])
        IOT_CONFIG['ipv4_enabled'] = 'ipv4' in request.form
        IOT_CONFIG['tcp_enabled'] = 'tcp' in request.form
        IOT_CONFIG['syn_flood_rule'] = 'syn_flood' in request.form
        IOT_CONFIG['ips_auto_block'] = 'ips_auto_block' in request.form
        IOT_CONFIG['webhook_enabled'] = 'webhook_enabled' in request.form
        IOT_CONFIG['webhook_url'] = (request.form.get('webhook_url') or '').strip()
        IOT_CONFIG['abuseipdb_enabled'] = 'abuseipdb_enabled' in request.form
        IOT_CONFIG['abuseipdb_api_key'] = (request.form.get('abuseipdb_api_key') or '').strip()
        if request.form.get('ips_block_threshold'):
            try:
                thresh_val = float(request.form.get('ips_block_threshold'))
                IOT_CONFIG['ips_block_threshold'] = max(0.5, min(1.0, thresh_val))
            except (ValueError, TypeError):
                pass
        if request.form.get('ips_block_duration'):
            try:
                dur_val = int(request.form.get('ips_block_duration'))
                IOT_CONFIG['ips_block_duration'] = max(1, dur_val)
            except (ValueError, TypeError):
                pass
        admin_email = (request.form.get('admin_email') or '').strip().lower()
        if admin_email and is_valid_email(admin_email):
            IOT_CONFIG['admin_email'] = admin_email
        IOT_CONFIG['status'] = 'ON' if 'device_status' in request.form else 'OFF'
        print(f"[ADMIN] Config Updated: {IOT_CONFIG}")
        return redirect(url_for('admin'))
    
    # Refresh IP on load
    IOT_CONFIG['ip_address'] = get_local_ip()
    overview_data = get_admin_overview_data()
    model_health = get_model_health()
    return render_template(
        'admin_overview.html',
        config=IOT_CONFIG,
        user=session.get('user'),
        role=session.get('role', 'admin'),
        overview=overview_data,
        model_health=model_health
    )

@app.route('/api/admin/overview')
@admin_required
def api_admin_overview():
    data = get_admin_overview_data()
    data['model_health'] = get_model_health()
    return jsonify(data)

@app.route('/api/flows/history')
@login_required
def api_flows_history():
    page = request.args.get('page', 1)
    per_page = request.args.get('per_page', 50)
    sort_by = request.args.get('sort_by', 'ts')
    sort_dir = request.args.get('sort_dir', 'DESC')
    
    filters = {
        'src_ip': request.args.get('src_ip', ''),
        'dst_ip': request.args.get('dst_ip', ''),
        'label': request.args.get('label', ''),
        'reason': request.args.get('reason', ''),
        'min_score': request.args.get('min_score', ''),
        'max_score': request.args.get('max_score', ''),
        'severity': request.args.get('severity', ''),
        'start_time': request.args.get('start_time', ''),
        'end_time': request.args.get('end_time', '')
    }
    result = get_historical_flows(
        page=page,
        per_page=per_page,
        filters=filters,
        sort_by=sort_by,
        sort_dir=sort_dir
    )
    return jsonify(result)

# ===============================================================
# ACTIVE IPS & FIREWALL MANAGEMENT ENDPOINTS
# ===============================================================
@app.route('/api/ips/blocked', methods=['GET'])
@login_required
def api_get_blocked_ips():
    active_only = request.args.get('active_only', 'true').lower() in ('true', '1')
    if active_only:
        records = get_active_blocked_ips()
    else:
        limit = request.args.get('limit', 50)
        records = get_all_blocked_ips(limit=limit)
    return jsonify({
        'status': 'ok',
        'ips_auto_block': IOT_CONFIG.get('ips_auto_block', True),
        'ips_block_threshold': IOT_CONFIG.get('ips_block_threshold', 0.90),
        'ips_block_duration': IOT_CONFIG.get('ips_block_duration', 15),
        'blocked_count': len(records),
        'records': records
    })

@app.route('/api/ips/unblock', methods=['POST'])
@admin_required
def api_unblock_ip():
    data = request.get_json(silent=True) or request.form.to_dict()
    ip = (data.get('ip') or '').strip()
    if not ip:
        return jsonify({'status': 'error', 'message': 'Missing IP address'}), 400
    success, msg = unblock_ip_firewall(ip)
    socketio.emit('ip_unblocked', {'ip': ip, 'msg': msg})
    return jsonify({'status': 'ok' if success else 'error', 'message': msg, 'ip': ip})

@app.route('/api/ips/block_manual', methods=['POST'])
@admin_required
def api_block_ip_manual():
    data = request.get_json(silent=True) or request.form.to_dict()
    ip = (data.get('ip') or '').strip()
    duration = int(data.get('duration', IOT_CONFIG.get('ips_block_duration', 15)))
    reason = (data.get('reason') or 'Manual Administrative Quarantine').strip()
    if not ip:
        return jsonify({'status': 'error', 'message': 'Missing IP address'}), 400
    success, msg = block_ip_firewall(ip, duration_minutes=duration, reason=reason, score=1.0)
    if success:
        socketio.emit('ip_blocked', {'ip': ip, 'score': 1.0, 'reason': reason, 'duration_minutes': duration})
    return jsonify({'status': 'ok' if success else 'error', 'message': msg, 'ip': ip})

@app.route('/api/test_webhook', methods=['POST'])
@admin_required
def api_test_webhook():
    data = request.get_json(silent=True) or request.form.to_dict()
    url = (data.get('webhook_url') or IOT_CONFIG.get('webhook_url') or '').strip()
    if not url:
        return jsonify({'status': 'error', 'message': 'Please provide a valid Webhook URL.'}), 400

    test_details = {
        'ts': time.time(),
        'src_ip': '198.51.100.42',
        'dst_ip': IOT_CONFIG.get('ip_address', '127.0.0.1'),
        'dst_port': 443,
        'protocol': 'HTTPS',
        'attack_score': 0.98,
        'severity': 'Critical',
        'reason': 'Test Incident Verification: SYN Flood & Recon Scan',
        'country': 'United States',
        'ips_blocked': True
    }

    ok, msg = send_webhook_alert(test_details, url)
    return jsonify({
        'status': 'ok' if ok else 'error',
        'message': msg
    })

@app.route('/api/threat_intel/check', methods=['GET', 'POST'])
@login_required
def api_threat_intel_check():
    ip = (
        request.args.get('ip') or
        (request.get_json(silent=True) and request.get_json(silent=True).get('ip')) or
        (request.form and request.form.get('ip')) or
        ''
    ).strip()
    if not ip:
        return jsonify({'status': 'error', 'message': 'Missing IP address parameter.'}), 400

    api_key = IOT_CONFIG.get('abuseipdb_api_key') if IOT_CONFIG.get('abuseipdb_enabled') else None
    intel = get_ip_threat_reputation(ip, api_key=api_key)
    return jsonify({
        'status': 'ok',
        'threat_intel': intel
    })

# ===============================================================
# HUMAN-IN-THE-LOOP MLOPS: ANALYST FEEDBACK ENDPOINTS
# ===============================================================
@app.route('/api/flows/feedback', methods=['POST'])
@login_required
def api_submit_feedback():
    data = request.get_json(silent=True) or request.form.to_dict()
    flow_id = data.get('flow_id')
    verified_label = int(data.get('verified_label', 1))
    src_ip = (data.get('src_ip') or '').strip()
    original_score = float(data.get('original_score', 1.0)) if data.get('original_score') is not None else None
    notes = (data.get('notes') or '').strip()
    analyst_user = session.get('user', 'analyst')

    ok, msg = submit_flow_feedback(
        flow_id=flow_id,
        verified_label=verified_label,
        analyst_user=analyst_user,
        src_ip=src_ip,
        original_score=original_score,
        notes=notes
    )

    if ok:
        socketio.emit('feedback_recorded', {
            'flow_id': flow_id,
            'src_ip': src_ip,
            'verified_label': verified_label,
            'analyst': analyst_user
        })

    return jsonify({
        'status': 'ok' if ok else 'error',
        'message': msg,
        'summary': get_feedback_summary()
    })

@app.route('/api/flows/feedback/stats', methods=['GET'])
@login_required
def api_get_feedback_stats():
    return jsonify({
        'status': 'ok',
        'summary': get_feedback_summary()
    })

# ===============================================================
# VISUAL EXPLAINABLE AI (XAI / SHAP) ENDPOINTS
# ===============================================================
@app.route('/api/flows/<int:flow_id>/explain', methods=['GET'])
@login_required
def api_explain_flow_by_id(flow_id):
    """Local explainability for a historical flow stored in SQLite."""
    pred = get_prediction_by_id(flow_id)
    if not pred:
        return jsonify({'status': 'error', 'message': f'Flow #{flow_id} not found.'}), 404

    features = {}
    if pred.get('features'):
        try:
            features = json.loads(pred['features'])
        except Exception:
            features = {}

    top_k = int(request.args.get('top_k', 5))
    explanation = explain_flow(features, top_k=top_k)

    return jsonify({
        'status': 'ok',
        'flow_id': flow_id,
        'src_ip': pred.get('src_ip'),
        'dst_ip': pred.get('dst_ip'),
        'timestamp': pred.get('ts'),
        'label': pred.get('label'),
        'attack_score': pred.get('attack_score'),
        'reason': pred.get('reason'),
        'explanation': explanation
    })

@app.route('/api/flows/explain', methods=['POST'])
@login_required
def api_explain_flow_custom():
    """Local explainability for custom flow vectors submitted by analysts."""
    data = request.get_json(silent=True) or request.form.to_dict()
    flow_features = data.get('features') or data
    top_k = int(data.get('top_k', 5))

    explanation = explain_flow(flow_features, top_k=top_k)
    return jsonify({
        'status': 'ok',
        'explanation': explanation
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    portal = (request.args.get('portal') or request.form.get('portal') or 'user').strip().lower()
    is_admin_portal = (portal == 'admin')

    if request.method == 'POST':
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1').split(',')[0].strip()
        now = time.time()
        # Clean older attempts outside lockout window
        LOGIN_ATTEMPTS[client_ip] = [t for t in LOGIN_ATTEMPTS[client_ip] if now - t < LOGIN_LOCKOUT_SECONDS]
        if len(LOGIN_ATTEMPTS[client_ip]) >= LOGIN_MAX_ATTEMPTS:
            error = f"Too many failed login attempts. Temporarily locked out. Please try again in {int(LOGIN_LOCKOUT_SECONDS // 60)} minutes."
            return render_template('login.html', portal=portal, error=error), 429

        login_id = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not login_id or not password:
            LOGIN_ATTEMPTS[client_ip].append(now)
            return render_template('login.html', portal=portal, error="Invalid username or password."), 401

        conn = get_db()
        user = find_user_by_login_id(conn, login_id)
        # user tuple: (id, username, email, password_hash, role)
        if user and check_password_hash(user[3], password):
            user_id = user[0]
            username = user[1]
            user_email = (user[2] or '').strip()
            user_role = user[4] or 'user'

            # Strict single-owner enforcement:
            # ONLY the designated administrator account receives 'admin' role in session
            is_designated_admin = (
                user_role == 'admin' and (
                    user_email.lower() == DESIGNATED_ADMIN_EMAIL.lower() or
                    username.lower() == DESIGNATED_ADMIN_EMAIL.lower() or
                    username.lower() == 'apashamkirikiri320'
                )
            )

            # Reject normal users attempting to enter the administrator portal
            if is_admin_portal and not is_designated_admin:
                LOGIN_ATTEMPTS[client_ip].append(now)
                return render_template(
                    'login.html',
                    portal='admin',
                    error="Access Denied: Standard user accounts cannot log into the SOC Administrator Portal. Please use User Login."
                ), 403

            # Reset rate limit tracker on successful authentication
            LOGIN_ATTEMPTS.pop(client_ip, None)

            # Regenerate session / clear stale data
            session.clear()

            session['user_id'] = user_id
            session['user'] = username
            session['email'] = user_email
            session['role'] = 'admin' if is_designated_admin else 'user'

            if session['role'] == 'admin':
                return redirect(url_for('admin'))
            return redirect(url_for('prediction'))

        # Record failed attempt
        LOGIN_ATTEMPTS[client_ip].append(now)
        return render_template('login.html', portal=portal, error="Invalid username or password."), 401

    return render_template('login.html', portal=portal)

@app.route('/admin/login')
def admin_login():
    return redirect(url_for('login', portal='admin'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        raw_email = (request.form.get('email') or '').strip().lower()

        if not username or not password:
            return render_template('register.html', error="Username and password are required."), 400

        # Disallow registering as the designated administrator or with designated admin email
        if (username.lower() in [DESIGNATED_ADMIN_EMAIL.lower(), 'apashamkirikiri320'] or 
            raw_email == DESIGNATED_ADMIN_EMAIL.lower()):
            return render_template('register.html', error="Registration with administrator credentials or email is prohibited."), 400

        # Validate email if provided
        if raw_email:
            if not is_valid_email(raw_email):
                return render_template('register.html', error="Please provide a valid email address."), 400
            user_email = raw_email
        else:
            user_email = f"{username}@ai-nids.local"

        # Explicitly enforce USER role — ignore any client-supplied role or is_admin fields
        forced_role = 'user'
        hashed = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            conn = get_db()
            conn.execute(
                'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                (username, user_email, hashed, forced_role)
            )
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error="An account with this username or email already exists."), 409

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/admin/change_password', methods=['POST'])
@admin_required
def api_admin_change_password():
    data = request.get_json(silent=True) or request.form or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')

    if not current_password or not new_password:
        return jsonify({'status': 'error', 'message': 'Current and new passwords are required.'}), 400

    if new_password != confirm_password:
        return jsonify({'status': 'error', 'message': 'New password and confirmation do not match.'}), 400

    if len(new_password) < 4:
        return jsonify({'status': 'error', 'message': 'New password must be at least 4 characters long.'}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT id, password FROM users 
        WHERE LOWER(COALESCE(email, '')) = LOWER(?) 
           OR LOWER(username) = LOWER(?)
           OR LOWER(username) = 'apashamkirikiri320'
    """, (DESIGNATED_ADMIN_EMAIL, DESIGNATED_ADMIN_EMAIL))
    admin_row = c.fetchone()

    if not admin_row or not check_password_hash(admin_row[1], current_password):
        return jsonify({'status': 'error', 'message': 'Current password verification failed.'}), 401

    new_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
    c.execute("UPDATE users SET password = ? WHERE id = ?", (new_hash, admin_row[0]))
    conn.commit()
    return jsonify({'status': 'ok', 'message': 'Administrator password updated successfully.'})

def run_simulation(csv_path, speed=1.0):
    """Background simulation thread to feed dataset flows."""
    global SIMULATION_STATE
    try:
        if not os.path.exists(csv_path):
            print(f"[SIMULATION] CSV not found: {csv_path}")
            SIMULATION_STATE['running'] = False
            return

        df = pd.read_csv(csv_path)
        df.columns = df.columns.str.strip()
        records = df.to_dict(orient='records')
        print(f"[SIMULATION] Loaded {len(records)} flows for replay at {speed}x speed.")

        for i, row in enumerate(records):
            if not SIMULATION_STATE['running']:
                print("[SIMULATION] Simulation stopped.")
                break

            payload = row.copy()
            payload['True_Label'] = row.get('Label', 'BENIGN')
            payload['src_ip'] = f"{np.random.randint(1,255)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}.{np.random.randint(0,255)}"
            payload['dst_ip'] = f"192.168.1.{np.random.randint(10, 50)}"

            handle_new_flow(payload)

            cur_speed = max(0.1, float(SIMULATION_STATE.get('speed', 1.0)))
            time.sleep(1.0 / cur_speed)

    except Exception as e:
        print(f"[SIMULATION ERROR] {e}")
        traceback.print_exc()
    finally:
        SIMULATION_STATE['running'] = False

@app.route('/prediction')
@login_required
def prediction():
    stats = get_live_stats(limit=50)
    stats['session_packets'] = SESSION_STATS['packets']
    stats['session_attacks'] = SESSION_STATS['attacks']
    stats['recent_geo'] = RECENT_GEO_MARKERS
    detector_info = get_detector_info()
    return render_template(
        'prediction.html',
        user=session.get('user'),
        status=IOT_CONFIG['status'],
        initial_stats=stats,
        detector_info=detector_info,
        simulation_running=SIMULATION_STATE['running'],
        simulation_speed=SIMULATION_STATE['speed']
    )

@app.route('/analysis')
@login_required
def analysis():
    return render_template('analysis.html', user=session.get('user'))

@app.route('/download_logs')
@admin_required
def download_logs():
    csv_data = get_all_logs_csv()
    response = make_response(csv_data)
    response.headers["Content-Disposition"] = "attachment; filename=ai_nids_attack_logs.csv"
    response.headers["Content-Type"] = "text/csv"
    return response

@app.route('/api/metrics_data')
@login_required
def metrics_data():
    data = get_metrics_data()
    return jsonify(data)

@app.route('/api/live_stats')
@login_required
def api_live_stats():
    stats = get_live_stats(limit=50)
    stats['session_packets'] = SESSION_STATS['packets']
    stats['session_attacks'] = SESSION_STATS['attacks']
    stats['recent_geo'] = RECENT_GEO_MARKERS
    stats['simulation_running'] = SIMULATION_STATE['running']
    stats['simulation_speed'] = SIMULATION_STATE['speed']
    return jsonify(stats)

@app.route('/api/settings', methods=['POST'])
@admin_required
def api_settings():
    data = request.get_json(silent=True) or request.form
    alpha = data.get('alpha')
    beta = data.get('beta')
    thresh = data.get('thresh')
    set_detector_params(alpha=alpha, beta=beta, thresh=thresh)
    return jsonify({'status': 'ok', 'detector': get_detector_info()})

@app.route('/api/simulation', methods=['POST'])
@admin_required
def api_simulation():
    global SIMULATION_STATE, IOT_CONFIG
    data = request.get_json(silent=True) or request.form
    action = data.get('action', 'start')
    speed = float(data.get('speed', SIMULATION_STATE['speed']))
    SIMULATION_STATE['speed'] = speed

    if action == 'start':
        IOT_CONFIG['status'] = 'ON'
        if not SIMULATION_STATE['running']:
            SIMULATION_STATE['running'] = True
            csv_path = os.path.join(os.path.dirname(__file__), 'data', 'CICIDS2017_subset.csv')
            if not os.path.exists(csv_path):
                csv_path = os.path.join(os.path.dirname(__file__), 'IDS_Dataset.csv')
            t = threading.Thread(target=run_simulation, args=(csv_path, speed), daemon=True)
            SIMULATION_STATE['thread'] = t
            t.start()
            return jsonify({'status': 'started', 'speed': speed, 'device_status': 'ON'})
        return jsonify({'status': 'already_running', 'speed': speed})

    elif action == 'stop':
        SIMULATION_STATE['running'] = False
        return jsonify({'status': 'stopped'})

    elif action == 'speed':
        return jsonify({'status': 'speed_updated', 'speed': speed})

    return jsonify({'status': 'unknown_action'})

@app.route('/api/reset_stats', methods=['POST'])
@admin_required
def api_reset_stats():
    global SESSION_STATS, RECENT_GEO_MARKERS
    SESSION_STATS['packets'] = 0
    SESSION_STATS['attacks'] = 0
    SESSION_STATS['start_time'] = time.time()
    RECENT_GEO_MARKERS.clear()
    return jsonify({'status': 'ok'})

@app.route('/api/test_email', methods=['POST'])
@admin_required
def api_test_email():
    data = request.get_json(silent=True) or request.form or {}
    if 'email' in data:
        raw_target = data.get('email')
        target = str(raw_target).strip().lower() if raw_target is not None else ''
    elif 'admin_email' in data:
        raw_target = data.get('admin_email')
        target = str(raw_target).strip().lower() if raw_target is not None else ''
    else:
        target = (IOT_CONFIG.get('admin_email') or '').strip().lower()

    if not target or not is_valid_email(target):
        return jsonify({
            'status': 'error',
            'recipient': target if target else 'None',
            'message': 'Invalid email address format. Please enter a valid email address (e.g., admin@example.com).'
        }), 400

    try:
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        body = f"""✅ AI-NIDS Email Alert System Test Successful!
============================================================
This is a verification test from your AI-Powered Network Intrusion Detection System (AI-NIDS).

• Status: SMTP Gateway Connected & Verified
• Mail Server: {SMTP_SERVER}:{SMTP_PORT} (STARTTLS)
• Sender Account: {SMTP_USER}
• Recipient: {target}
• Monitored Node: {IOT_CONFIG.get('device_name', 'AI-NIDS Gateway Node')} ({IOT_CONFIG.get('ip_address', '127.0.0.1')})
• Timestamp: {ts}

Your intrusion alerting pipeline is active and ready to deliver real-time warnings whenever malicious flows or DDoS threats are detected.
============================================================
Automated test verification dispatched from AI-NIDS.
"""
        msg = MIMEText(body)
        msg['Subject'] = f"[{APP_NAME}] Verification: Email Alert System Active"
        msg['From'] = SMTP_USER
        msg['To'] = target

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=12) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        print(f"[EMAIL] 📧 Admin test email delivered successfully to {target}")
        return jsonify({
            'status': 'success',
            'recipient': target,
            'message': f'Test email delivered successfully to {target}!'
        })
    except Exception as e:
        print(f"[EMAIL ERROR] ❌ Test email failed for {target}: {e}")
        return jsonify({
            'status': 'error',
            'recipient': target,
            'message': f'Failed to send email to {target}: {e}'
        }), 500

@app.route('/api/subscribers', methods=['GET'])
@login_required
def api_get_subscribers():
    try:
        subs = get_alert_subscribers()
        return jsonify({'status': 'ok', 'subscribers': subs, 'admin_email': IOT_CONFIG.get('admin_email')})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/subscribers', methods=['POST'])
@login_required
def api_add_subscriber():
    data = request.get_json(silent=True) or request.form
    email = (data.get('email') or '').strip().lower()
    if not email or '@' not in email or '.' not in email:
        return jsonify({'status': 'error', 'message': 'Please provide a valid email address.'}), 400
    
    success, msg = add_alert_subscriber(email)
    if not success:
        return jsonify({'status': 'error', 'message': msg}), 400

    # Dispatch confirmation/welcome email asynchronously
    def _send_welcome():
        try:
            ts = time.strftime('%Y-%m-%d %H:%M:%S')
            body = f"""✅ Subscription Confirmed: Real-Time Incident Threat Alerts
============================================================
Hello,

Your email ({email}) has been subscribed to receive live security incident notifications from the AI-Powered Network Intrusion Detection System (AI-NIDS).

Whenever a DDoS attack, port scan, SYN flood, or machine learning anomaly is detected on the monitored network, an automated alert report will be delivered from the System Administrator directly to your inbox.

• Monitored Node   : {IOT_CONFIG.get('device_name', 'AI-NIDS Gateway Node')} ({IOT_CONFIG.get('ip_address', '127.0.0.1')})
• Subscribed On    : {ts}
• Admin Dispatch   : {SMTP_USER}

You can manage your subscription or unsubscribe at any time via the AI-NIDS Monitor dashboard (http://localhost:5000/prediction).
============================================================
Automated confirmation from AI-NIDS (AI-Powered Network Intrusion Detection System)
"""
            msg = MIMEText(body)
            msg['Subject'] = f"[{APP_NAME}] You are Subscribed to Attack Alerts"
            msg['From'] = SMTP_USER
            msg['To'] = email

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=12) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
            print(f"[EMAIL] 📧 Welcome email sent to {email}")
        except Exception as e:
            print(f"[EMAIL WARN] Failed sending welcome email to {email}: {e}")

    threading.Thread(target=_send_welcome, daemon=True).start()

    return jsonify({
        'status': 'ok',
        'message': f'Subscribed successfully! Confirmation email dispatched to {email}.',
        'subscribers': get_alert_subscribers()
    })

@app.route('/api/subscribers/delete', methods=['POST'])
@admin_required
def api_remove_subscriber():
    data = request.get_json(silent=True) or request.form
    email = (data.get('email') or '').strip().lower()
    if not email:
        return jsonify({'status': 'error', 'message': 'Email is required'}), 400
    remove_alert_subscriber(email)
    return jsonify({'status': 'ok', 'message': f'{email} unsubscribed.', 'subscribers': get_alert_subscribers()})


@app.route('/api/test_subscriber_email', methods=['POST'])
@login_required
def api_test_subscriber_email():
    data = request.get_json(silent=True) or request.form
    target = (data.get('email') or '').strip().lower()
    if not target or not is_valid_email(target):
        return jsonify({'status': 'error', 'message': 'Please provide a valid email address to test.'}), 400
    
    try:
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        body = f"""⚠️ [AI-NIDS TEST ALERT] Verification from AI-NIDS Administrator ⚠️
============================================================
This is a verification test of the AI-NIDS Threat Alert Pipeline.

• Alert Status       : Test Alert Delivery Confirmed
• Dispatched From    : System Admin ({SMTP_USER})
• Delivered To       : {target}
• Simulated Incident : SYN Flood / Volumetric DDoS Anomaly
• Target Network Node: {IOT_CONFIG.get('device_name', 'AI-NIDS Gateway Node')} ({IOT_CONFIG.get('ip_address', '127.0.0.1')})
• Timestamp          : {ts}

Your email is confirmed and will receive real-time incident reports whenever malicious attacks are detected.
============================================================
Automated alert verification by AI-NIDS.
"""
        msg = MIMEText(body)
        msg['Subject'] = f"[{APP_NAME} TEST ALERT] Verification for {target}"
        msg['From'] = SMTP_USER
        msg['To'] = target

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=12) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        return jsonify({'status': 'ok', 'message': f'Test alert email successfully sent to {target}!'})
    except Exception as e:
        print(f"[EMAIL ERROR] ❌ Test subscriber email failed: {e}")
        return jsonify({'status': 'error', 'message': f'Failed to send email: {e}'}), 500

# ===============================================================
# Socket Logic & Replay
# ===============================================================
@socketio.on('new_flow')
def handle_new_flow(data):
    """Process flow: Rule Check -> Model Check -> Alert."""
    if IOT_CONFIG['status'] != 'ON':
        return  # Ignore traffic if Device is OFF

    try:
        ts = time.time()
        src_ip = data.get('src_ip', '0.0.0.0')
        dst_ip = data.get('dst_ip', '0.0.0.0')
        true_label = 0 if data.get('True_Label', 'BENIGN') == 'BENIGN' else 1
        
        # 1. Custom Rule Checks
        rule_violation = False
        reason = ""

        # Rule: TCP Disabled Policy
        proto = data.get('Protocol', 0) # Assuming 6 is TCP
        # Map protocol if string
        if isinstance(proto, str):
            proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
            proto = proto_map.get(proto.lower(), 0)
        
        if not IOT_CONFIG['tcp_enabled'] and int(proto) == 6:
            rule_violation = True
            reason = "Policy Violation: TCP Disabled"

        # Rule: SYN Flood (High SYN count check)
        syn_count = float(data.get('SYN Flag Count', 0))
        if IOT_CONFIG['syn_flood_rule'] and syn_count > 0: # strict check for demo
            if syn_count >= 1: # In CSV, flags are often 0 or 1. High rate usually detected by volume, but we check flag presence here.
                rule_violation = True
                reason = "DDoS Signature: SYN Flood"

        # 2. ML Model Inference
        res = predict_flow(data)
        
        final_label = res['label']
        attack_score = res['attack_score']
        
        # Priority: Rule > Model
        if rule_violation:
            final_label = 1
            attack_score = 1.0
        elif final_label == 1:
            reason = "ML Anomaly Detection"

        # 3. Prepare Output
        dst_port_raw = data.get('Destination Port') or data.get('dst_port')
        dst_port = int(dst_port_raw) if dst_port_raw is not None else 80
        proto_name = get_protocol_name(proto, dst_port)
        latency_val = round(float(res.get('latency_ms', 0.0)), 2)
        sev = get_severity(attack_score)
        geo_details = get_geoip_details(src_ip)
        intel_key = IOT_CONFIG.get('abuseipdb_api_key') if IOT_CONFIG.get('abuseipdb_enabled') else None
        threat_intel = get_ip_threat_reputation(src_ip, api_key=intel_key)

        out = {
            'ts': ts,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'attack_score': attack_score,
            'label': final_label,
            'reason': reason,
            'shap_explain': res.get('shap_explain'),
            'explanation': res.get('explanation'),
            'features': data,
            'latency_ms': latency_val,
            'threat_intel': threat_intel,
            'abuse_score': threat_intel.get('abuse_score', 0),
            'dst_port': dst_port,
            'protocol': proto_name,
            'severity': sev['level'],
            'severity_class': sev['badge_class'],
            'country': geo_details['country'],
            'city': geo_details['city']
        }

        # GeoIP
        if geoip_reader:
            try:
                response = geoip_reader.city(src_ip)
                out['geo'] = {'lat': response.location.latitude, 'lon': response.location.longitude}
            except:
                out['geo'] = {'lat': np.random.uniform(-60, 70), 'lon': np.random.uniform(-180, 180)}
        else:
            out['geo'] = {'lat': np.random.uniform(-60, 70), 'lon': np.random.uniform(-180, 180)}

        # Cache recent geo markers for map persistence across page changes
        global RECENT_GEO_MARKERS
        RECENT_GEO_MARKERS.append({
            'lat': float(out['geo']['lat']),
            'lon': float(out['geo']['lon']),
            'isAttack': (final_label == 1),
            'src_ip': src_ip,
            'country': geo_details['country']
        })

        if len(RECENT_GEO_MARKERS) > 150:
            RECENT_GEO_MARKERS.pop(0)

        # 4. Log & Alert
        log_prediction({
            'ts': ts,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'features': json.dumps(data),
            'supervised_prob': res.get('supervised_prob'),
            'unsupervised_score': res.get('unsupervised_score'),
            'attack_score': attack_score,
            'label': final_label,
            'true_label': true_label,
            'latency_ms': res.get('latency_ms'),
            'reason': reason
        })

        # Update in-memory session stats
        global SESSION_STATS
        SESSION_STATS['packets'] += 1
        if final_label == 1:
            SESSION_STATS['attacks'] += 1

        out['session_packets'] = SESSION_STATS['packets']
        out['session_attacks'] = SESSION_STATS['attacks']

        socketio.emit('flow_result', out)
        
        if final_label == 1:
            socketio.emit('alarm', out)
            send_alert_email("DDoS / Intrusion", out)

            # Active IPS Auto-Blocking Interception
            if IOT_CONFIG.get('ips_auto_block') and attack_score >= float(IOT_CONFIG.get('ips_block_threshold', 0.90)):
                dur = int(IOT_CONFIG.get('ips_block_duration', 15))
                block_ok, block_msg = block_ip_firewall(
                    ip=src_ip,
                    duration_minutes=dur,
                    reason=f"Auto-IPS Block: {reason or 'High-Severity Intrusion'}",
                    score=attack_score
                )
                if block_ok:
                    out['ips_blocked'] = True
                    out['ips_msg'] = block_msg
                    socketio.emit('ip_blocked', {
                        'ip': src_ip,
                        'score': attack_score,
                        'reason': reason,
                        'duration_minutes': dur
                    })

            # Instant Incident Webhook Push (Discord / Slack)
            if IOT_CONFIG.get('webhook_enabled') and IOT_CONFIG.get('webhook_url'):
                dispatch_webhook_alert_async(out)

    except Exception as e:
        print(f"[ERROR] {e}")
        traceback.print_exc()

LAST_WEBHOOK_TIME = 0.0

def dispatch_webhook_alert_async(details):
    """Dispatches a rich incident card to the configured Discord/Slack webhook in a background thread."""
    url = (IOT_CONFIG.get('webhook_url') or '').strip()
    if not IOT_CONFIG.get('webhook_enabled') or not url:
        return

    global LAST_WEBHOOK_TIME
    now = time.time()
    # 15s cooldown per webhook dispatch
    if now - LAST_WEBHOOK_TIME < 15.0:
        return
    LAST_WEBHOOK_TIME = now

    def _worker():
        ok, msg = send_webhook_alert(details, url)
        if ok:
            print(f"[WEBHOOK] 🚀 Incident card dispatched to webhook.")
            socketio.emit('webhook_alert_sent', {'url': url, 'src_ip': details.get('src_ip')})
        else:
            print(f"[WEBHOOK WARN] Delivery failed: {msg}")

    threading.Thread(target=_worker, daemon=True, name="Webhook-Dispatch-Worker").start()

def auto_expire_firewall_worker():
    """Background daemon to regularly clean up expired temporary IP blocks."""
    while True:
        try:
            time.sleep(30)
            unblocked = cleanup_expired_firewall_blocks()
            for ip in unblocked:
                print(f"[IPS AUTO-EXPIRE] Temporary firewall block expired for: {ip}")
                socketio.emit('ip_unblocked', {'ip': ip, 'reason': 'Auto-lease expired'})
        except Exception:
            time.sleep(10)

# Launch IPS auto-expiry daemon
threading.Thread(target=auto_expire_firewall_worker, daemon=True, name="IPS-Auto-Expire-Daemon").start()

if __name__ == '__main__':
    print("🚀 AI-NIDS (AI-Powered Network Intrusion Detection System) Running on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)