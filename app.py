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

# Local Imports
import threading
from inference import predict_flow, set_detector_params, get_detector_info
from utils import (
    init_db, log_prediction, DB_PATH, get_metrics_data, get_all_logs_csv,
    get_live_stats, add_alert_subscriber, remove_alert_subscriber, get_alert_subscribers
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

@app.context_processor
def inject_branding():
    return {
        'APP_NAME': APP_NAME,
        'APP_FULL_NAME': APP_FULL_NAME,
        'APP_DASHBOARD_TITLE': APP_DASHBOARD_TITLE,
        'APP_MONITOR_TITLE': APP_MONITOR_TITLE,
        'APP_ALERT_PREFIX': APP_ALERT_PREFIX,
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
    'admin_email': 'pamuriravindrareddy4@gmail.com',
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
    return render_template('index.html')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if request.method == 'POST':
        # Update Config
        IOT_CONFIG['device_name'] = request.form.get('device_name')
        IOT_CONFIG['ipv4_enabled'] = 'ipv4' in request.form
        IOT_CONFIG['tcp_enabled'] = 'tcp' in request.form
        IOT_CONFIG['syn_flood_rule'] = 'syn_flood' in request.form
        admin_email = (request.form.get('admin_email') or '').strip().lower()
        if admin_email and is_valid_email(admin_email):
            IOT_CONFIG['admin_email'] = admin_email
        IOT_CONFIG['status'] = 'ON' if 'device_status' in request.form else 'OFF'
        print(f"[ADMIN] Config Updated: {IOT_CONFIG}")
        return redirect(url_for('admin'))
    
    # Refresh IP on load
    IOT_CONFIG['ip_address'] = get_local_ip()
    return render_template('admin.html', config=IOT_CONFIG, user=session.get('user'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        if user and check_password_hash(user[2], password):
            session['user'] = user[1]
            return redirect(url_for('prediction'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed = generate_password_hash(password, method='pbkdf2:sha256')
        try:
            conn = get_db()
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed))
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Username exists"
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

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
@login_required
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
@login_required
def api_settings():
    data = request.get_json(silent=True) or request.form
    alpha = data.get('alpha')
    beta = data.get('beta')
    thresh = data.get('thresh')
    set_detector_params(alpha=alpha, beta=beta, thresh=thresh)
    return jsonify({'status': 'ok', 'detector': get_detector_info()})

@app.route('/api/simulation', methods=['POST'])
@login_required
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
@login_required
def api_reset_stats():
    global SESSION_STATS, RECENT_GEO_MARKERS
    SESSION_STATS['packets'] = 0
    SESSION_STATS['attacks'] = 0
    SESSION_STATS['start_time'] = time.time()
    RECENT_GEO_MARKERS.clear()
    return jsonify({'status': 'ok'})

@app.route('/api/test_email', methods=['POST'])
@login_required
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
@login_required
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
        out = {
            'ts': ts,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'attack_score': attack_score,
            'label': final_label,
            'reason': reason,
            'shap_explain': res.get('shap_explain')
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
            'src_ip': src_ip
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

    except Exception as e:
        print(f"[ERROR] {e}")
        traceback.print_exc()

if __name__ == '__main__':
    print("🚀 AI-NIDS (AI-Powered Network Intrusion Detection System) Running on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)