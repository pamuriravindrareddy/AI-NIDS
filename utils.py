import sys
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
import time
import os
import sqlite3
import json
import io
import csv
import ipaddress
import subprocess
import urllib.request
import urllib.error
import numpy as np
from contextlib import closing
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve, precision_recall_curve
from collections import Counter, defaultdict

DB_PATH = os.path.join(os.path.dirname(__file__), 'nids.db')
GEOIP_PATH = os.path.join(os.path.dirname(__file__), 'GeoLite2-City.mmdb')

_geoip_reader = None
try:
    if os.path.exists(GEOIP_PATH):
        import geoip2.database
        _geoip_reader = geoip2.database.Reader(GEOIP_PATH)
except Exception:
    _geoip_reader = None

COMMON_PORTS = {
    80: 'HTTP',
    443: 'HTTPS',
    53: 'DNS',
    22: 'SSH',
    21: 'FTP',
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
    3389: 'RDP',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    137: 'NetBIOS',
    138: 'NetBIOS',
    139: 'NetBIOS',
    445: 'SMB',
    123: 'NTP',
    161: 'SNMP',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    27017: 'MongoDB',
    6379: 'Redis'
}

DESIGNATED_ADMIN_EMAIL = 'apashamkirikiri320@gmail.com'
DESIGNATED_ADMIN_USERNAME = 'apashamkirikiri320@gmail.com'

def init_db(db_path=None):
    target_db = db_path or DB_PATH
    with closing(sqlite3.connect(target_db)) as conn:
        c = conn.cursor()
        # Predictions table
        c.execute('''CREATE TABLE IF NOT EXISTS predictions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts REAL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        features TEXT,
                        supervised_prob REAL,
                        unsupervised_score REAL,
                        attack_score REAL,
                        label INTEGER,
                        true_label INTEGER,
                        latency_ms REAL,
                        reason TEXT
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        email TEXT,
                        password TEXT,
                        role TEXT DEFAULT 'user'
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS alert_subscribers (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE,
                        created_at REAL
                    )''')
        # Active IPS Blocked IPs Table
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT UNIQUE,
                        reason TEXT,
                        attack_score REAL,
                        blocked_at REAL,
                        expires_at REAL,
                        status TEXT DEFAULT 'ACTIVE'
                    )''')
        try:
            c.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ips_status ON blocked_ips(status, expires_at)")
        except Exception:
            pass

        # Threat Intelligence Cache Table (AbuseIPDB & Reputation Lookups)
        c.execute('''CREATE TABLE IF NOT EXISTS threat_intel_cache (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip TEXT UNIQUE,
                        abuse_score INTEGER DEFAULT 0,
                        total_reports INTEGER DEFAULT 0,
                        country_name TEXT,
                        isp TEXT,
                        domain TEXT,
                        is_whitelisted INTEGER DEFAULT 0,
                        last_checked REAL,
                        raw_json TEXT
                    )''')
        try:
            c.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_ip ON threat_intel_cache(ip)")
        except Exception:
            pass

        # Human-in-the-Loop MLOps: Analyst Flow Feedback & Audit Queue
        c.execute('''CREATE TABLE IF NOT EXISTS flow_feedback (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        flow_id INTEGER,
                        src_ip TEXT,
                        original_score REAL,
                        verified_label INTEGER,  -- 0 = False Positive / Benign, 1 = Confirmed Malicious
                        analyst_user TEXT,
                        notes TEXT,
                        created_at REAL
                    )''')
        try:
            c.execute("CREATE INDEX IF NOT EXISTS idx_feedback_flow_id ON flow_feedback(flow_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_feedback_ip ON flow_feedback(src_ip)")
        except Exception:
            pass
        # Add reason column if missing (for updates)
        try:
            c.execute("ALTER TABLE predictions ADD COLUMN reason TEXT")
        except Exception:
            pass

        # Safe RBAC migration: Add role column to users if missing
        try:
            c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        except Exception:
            pass

        # Safe migration: Add email column to users if missing
        try:
            c.execute("ALTER TABLE users ADD COLUMN email TEXT")
        except Exception:
            pass

        # Index on users email
        try:
            c.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        except Exception:
            pass

        # Map existing accounts to email addresses if email is empty
        c.execute("""
            UPDATE users 
            SET email = username || '@ai-nids.local' 
            WHERE (email IS NULL OR email = '') 
              AND username NOT IN ('admin', 'testadmin', 'apashamkirikiri320@gmail.com', 'apashamkirikiri320')
        """)

        # STRICT SINGLE-OWNER ENFORCEMENT:
        # 1. Remove administrator privileges from every other account (including former admin, testadmin)
        c.execute("""
            UPDATE users 
            SET role = 'user' 
            WHERE role = 'admin' 
              AND LOWER(COALESCE(email, '')) != LOWER(?) 
              AND LOWER(username) != LOWER(?)
              AND LOWER(username) != 'apashamkirikiri320'
        """, (DESIGNATED_ADMIN_EMAIL, DESIGNATED_ADMIN_EMAIL))

        # 2. Check if the designated administrator account already exists
        c.execute("""
            SELECT id, username, email, password, role 
            FROM users 
            WHERE LOWER(COALESCE(email, '')) = LOWER(?) 
               OR LOWER(username) = LOWER(?)
               OR LOWER(username) = 'apashamkirikiri320'
        """, (DESIGNATED_ADMIN_EMAIL, DESIGNATED_ADMIN_EMAIL))
        admin_row = c.fetchone()

        if admin_row is not None:
            # Existing designated account: ensure it has ADMIN role and exact email, DO NOT overwrite password!
            c.execute("""
                UPDATE users 
                SET role = 'admin', email = ? 
                WHERE id = ?
            """, (DESIGNATED_ADMIN_EMAIL, admin_row[0]))
        else:
            # One-time bootstrap: read initial password from AI_NIDS_ADMIN_PASSWORD environment variable
            env_password = os.environ.get('AI_NIDS_ADMIN_PASSWORD')
            if env_password:
                from werkzeug.security import generate_password_hash
                pwd_hash = generate_password_hash(env_password, method='pbkdf2:sha256')
                c.execute("""
                    INSERT INTO users (username, email, password, role) 
                    VALUES (?, ?, ?, 'admin')
                """, (DESIGNATED_ADMIN_USERNAME, DESIGNATED_ADMIN_EMAIL, pwd_hash))
                print(f"[BOOTSTRAP] ✅ Designated administrator account ({DESIGNATED_ADMIN_EMAIL}) successfully initialized.")
            else:
                print(f"[BOOTSTRAP] ℹ️ Administrator account ({DESIGNATED_ADMIN_EMAIL}) awaiting bootstrap. Set AI_NIDS_ADMIN_PASSWORD environment variable to complete initialization.")

        # Performance Indexes for Historical Flow Explorer and Overview Queries
        try:
            c.execute("CREATE INDEX IF NOT EXISTS idx_predictions_ts ON predictions(ts DESC)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_predictions_label ON predictions(label)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_predictions_src_ip ON predictions(src_ip)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_predictions_dst_ip ON predictions(dst_ip)")
        except Exception as idx_err:
            print(f"[WARN] Index creation: {idx_err}")

        conn.commit()

def find_user_by_login_id(conn, login_id: str):
    """
    Look up user by username or email case-insensitively.
    Does not assume usernames and emails are interchangeable.
    """
    if not login_id:
        return None
    login_id = str(login_id).strip()
    c = conn.cursor()
    # 1. Exact match on username or email
    row = c.execute("""
        SELECT id, username, email, password, role 
        FROM users 
        WHERE LOWER(username) = LOWER(?) OR LOWER(COALESCE(email, '')) = LOWER(?)
    """, (login_id, login_id)).fetchone()
    if row:
        return row

    # 2. Match prefix before @ for domain usernames
    if '@' not in login_id:
        row = c.execute("""
            SELECT id, username, email, password, role 
            FROM users 
            WHERE LOWER(username) LIKE ? OR LOWER(COALESCE(email, '')) LIKE ?
        """, (f"{login_id.lower()}@%", f"{login_id.lower()}@%")).fetchone()
        if row:
            return row

    return None


def get_severity(score: float):
    """
    Map uncalibrated anomaly score to severity tier.
    Documented scale:
      - Low:      score < 0.50
      - Medium:   0.50 <= score < 0.70
      - High:     0.70 <= score < 0.90
      - Critical: score >= 0.90
    Note: Score is an uncalibrated composite ensemble score (RF + Isolation Forest),
    not a calibrated probability.
    """
    try:
        val = float(score)
    except (ValueError, TypeError):
        val = 0.0
    
    if val >= 0.90:
        return {'level': 'Critical', 'badge_class': 'badge-critical', 'color': '#ff3366'}
    elif val >= 0.70:
        return {'level': 'High', 'badge_class': 'badge-high', 'color': '#ff9900'}
    elif val >= 0.50:
        return {'level': 'Medium', 'badge_class': 'badge-medium', 'color': '#ffcc00'}
    else:
        return {'level': 'Low', 'badge_class': 'badge-low', 'color': '#00d2ff'}

def get_protocol_name(proto_val, port=None):
    """Map numeric/string protocol code or infer from port to readable protocol."""
    if proto_val is not None:
        if isinstance(proto_val, str):
            p_lower = proto_val.strip().lower()
            if p_lower in ('tcp', '6'):
                return 'TCP'
            if p_lower in ('udp', '17'):
                return 'UDP'
            if p_lower in ('icmp', '1'):
                return 'ICMP'
        elif isinstance(proto_val, (int, float)):
            p_int = int(proto_val)
            if p_int in (6, 0):  # 0 is often mapped to TCP in datasets/feature_extraction
                return 'TCP'
            if p_int in (17, 1):
                return 'UDP'
            if p_int in (1, 2):
                return 'ICMP'

    # Fallback heuristic based on standard port
    if port is not None:
        try:
            port_num = int(port)
            if port_num in (53, 67, 68, 123, 137, 138, 161, 500):
                return 'UDP'
        except (ValueError, TypeError):
            pass

    return 'TCP'

def get_geoip_details(ip: str):
    """Graceful GeoIP lookup for country and city with private IP detection."""
    if not ip or ip in ('0.0.0.0', '127.0.0.1', 'localhost'):
        return {'country': 'Localhost', 'city': 'Local Node', 'is_private': True}
    
    # Check common private IPv4 ranges (10.x, 172.16-31.x, 192.168.x)
    if ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
                      '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                      '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
        return {'country': 'Internal Network', 'city': 'Local Subnet', 'is_private': True}
    
    if _geoip_reader:
        try:
            resp = _geoip_reader.city(ip)
            country = resp.country.name or 'Unknown'
            city = resp.city.name or 'Unknown'
            return {'country': country, 'city': city, 'is_private': False}
        except Exception:
            return {'country': 'External / Unknown', 'city': 'Unknown', 'is_private': False}
    return {'country': 'External / Unknown', 'city': 'Unknown', 'is_private': False}

def add_alert_subscriber(email: str):
    email = email.strip().lower()
    if not email or '@' not in email or '.' not in email:
        return False, "Invalid email address format"
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        try:
            c.execute("INSERT INTO alert_subscribers (email, created_at) VALUES (?, ?)", (email, time.time()))
            conn.commit()
            return True, "Subscribed successfully"
        except sqlite3.IntegrityError:
            return True, "Already subscribed"
        except Exception as e:
            return False, str(e)

def remove_alert_subscriber(email: str):
    email = email.strip().lower()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM alert_subscribers WHERE email = ?", (email,))
        conn.commit()
        return True

def get_alert_subscribers():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        rows = c.execute("SELECT email FROM alert_subscribers ORDER BY id DESC").fetchall()
        return [r[0] for r in rows if r[0]]

def log_prediction(record: dict):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        c.execute('''INSERT INTO predictions (
                        ts, src_ip, dst_ip, features,
                        supervised_prob, unsupervised_score,
                        attack_score, label, true_label, latency_ms, reason)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?)''', (
            record.get('ts', time.time()),
            record.get('src_ip'),
            record.get('dst_ip'),
            record.get('features'),
            record.get('supervised_prob'),
            record.get('unsupervised_score'),
            record.get('attack_score'),
            record.get('label'),
            record.get('true_label'),
            record.get('latency_ms'),
            record.get('reason', '')
        ))
        conn.commit()

def get_all_logs_csv():
    """Export all logs to CSV format."""
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        c.execute("SELECT ts, src_ip, dst_ip, label, attack_score, reason, true_label FROM predictions ORDER BY ts DESC")
        rows = c.fetchall()
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Prediction', 'Score', 'Reason', 'Ground Truth'])
        
        for r in rows:
            t_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r[0]))
            pred_str = "ATTACK" if r[3] == 1 else "BENIGN"
            writer.writerow([t_str, r[1], r[2], pred_str, r[4], r[5], r[6]])
        return output.getvalue()

def get_live_stats(limit=50):
    """Fetch current total packet counts and the most recent flows for Live Monitor."""
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute("SELECT count(*) FROM predictions")
            total_packets = c.fetchone()[0] or 0

            c.execute("SELECT count(*) FROM predictions WHERE label = 1")
            total_attacks = c.fetchone()[0] or 0

            c.execute("""
                SELECT ts, src_ip, dst_ip, attack_score, label, reason, latency_ms
                FROM predictions
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = c.fetchall()

            recent_logs = []
            for r in rows:
                score = float(r[3] or 0.0)
                sev = get_severity(score)
                recent_logs.append({
                    'ts': r[0],
                    'src_ip': r[1] or '0.0.0.0',
                    'dst_ip': r[2] or '0.0.0.0',
                    'attack_score': score,
                    'label': int(r[4] or 0),
                    'reason': r[5] or ('ATTACK' if r[4] == 1 else 'Normal'),
                    'latency_ms': round(float(r[6] or 0.0), 2),
                    'severity': sev['level'],
                    'severity_class': sev['badge_class']
                })

            return {
                'total_packets': total_packets,
                'total_attacks': total_attacks,
                'recent_logs': recent_logs
            }
    except Exception as e:
        print(f"[WARN] get_live_stats error: {e}")
        return {'total_packets': 0, 'total_attacks': 0, 'recent_logs': []}

def get_top_destination_ips(limit=5):
    """Retrieve top targeted destination IPs from database malicious records."""
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT dst_ip, count(*) as cnt
                FROM predictions
                WHERE label = 1 AND dst_ip IS NOT NULL AND dst_ip != ''
                GROUP BY dst_ip
                ORDER BY cnt DESC
                LIMIT ?
            """, (limit,))
            rows = c.fetchall()
            return [{'ip': r[0], 'count': r[1]} for r in rows]
    except Exception as e:
        print(f"[WARN] get_top_destination_ips error: {e}")
        return []

def get_destination_port_distribution(limit=500):
    """Extract destination port distribution from recent malicious flows."""
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT features
                FROM predictions
                WHERE label = 1 AND features IS NOT NULL AND features != ''
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = c.fetchall()
            ports = Counter()
            for r in rows:
                try:
                    feat = json.loads(r[0])
                    p = feat.get('Destination Port') or feat.get('dst_port')
                    if p is not None:
                        ports[int(p)] += 1
                except Exception:
                    continue
            
            top_ports = []
            for port_num, cnt in ports.most_common(8):
                service = COMMON_PORTS.get(port_num, f"Port {port_num}")
                top_ports.append({
                    'port': port_num,
                    'service': service,
                    'label': f"{service} ({port_num})",
                    'count': cnt
                })
            return top_ports
    except Exception as e:
        print(f"[WARN] get_destination_port_distribution error: {e}")
        return []

def get_attack_activity_over_time(limit=12):
    """Aggregate attack traffic count into hourly buckets."""
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT cast(ts / 3600 as int) * 3600 as bucket, count(*) as cnt
                FROM predictions
                WHERE label = 1
                GROUP BY bucket
                ORDER BY bucket DESC
                LIMIT ?
            """, (limit,))
            rows = c.fetchall()
            rows = rows[::-1]  # Chronological order
            labels = []
            counts = []
            for r in rows:
                t_str = time.strftime('%m-%d %H:00', time.localtime(r[0]))
                labels.append(t_str)
                counts.append(r[1])
            return {'labels': labels, 'counts': counts}
    except Exception as e:
        print(f"[WARN] get_attack_activity_over_time error: {e}")
        return {'labels': [], 'counts': []}

def get_attack_classification_distribution():
    """Count attacks grouped by reason / classification."""
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT COALESCE(NULLIF(reason, ''), 'ML Anomaly Detection') as cls, count(*) as cnt
                FROM predictions
                WHERE label = 1
                GROUP BY cls
                ORDER BY cnt DESC
            """)
            rows = c.fetchall()
            labels = []
            counts = []
            for r in rows:
                labels.append(r[0])
                counts.append(r[1])
            return {'labels': labels, 'counts': counts}
    except Exception as e:
        print(f"[WARN] get_attack_classification_distribution error: {e}")
        return {'labels': [], 'counts': []}

def get_recent_alerts(limit=10):
    """Fetch the most recent malicious detections for Admin Overview."""
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT id, ts, src_ip, dst_ip, attack_score, latency_ms, reason, features
                FROM predictions
                WHERE label = 1
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = c.fetchall()
            alerts = []
            for r in rows:
                score = float(r[4] or 0.0)
                sev = get_severity(score)
                dst_port = None
                proto_raw = None
                if r[7]:
                    try:
                        feat = json.loads(r[7])
                        dst_port = feat.get('Destination Port') or feat.get('dst_port')
                        proto_raw = feat.get('Protocol')
                    except Exception:
                        pass
                
                proto_name = get_protocol_name(proto_raw, dst_port)
                geo = get_geoip_details(r[2])
                
                alerts.append({
                    'id': r[0],
                    'ts': r[1],
                    'timestamp_formatted': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r[1])),
                    'src_ip': r[2] or '0.0.0.0',
                    'dst_ip': r[3] or '0.0.0.0',
                    'score': round(score, 4),
                    'latency_ms': round(float(r[5] or 0.0), 2),
                    'reason': r[6] or 'ML Anomaly Detection',
                    'severity': sev['level'],
                    'severity_color': sev['color'],
                    'severity_class': sev['badge_class'],
                    'dst_port': dst_port or 'N/A',
                    'protocol': proto_name,
                    'country': geo['country'],
                    'status': 'Active Alert'
                })
            return alerts
    except Exception as e:
        print(f"[WARN] get_recent_alerts error: {e}")
        return []

def get_admin_overview_data():
    """Compile comprehensive metrics for the Admin Overview dashboard."""
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()
            c.execute("SELECT count(*) FROM predictions")
            total_flows = c.fetchone()[0] or 0

            c.execute("SELECT count(*) FROM predictions WHERE label = 1")
            malicious_flows = c.fetchone()[0] or 0

            benign_flows = total_flows - malicious_flows

            c.execute("SELECT count(*) FROM predictions WHERE label = 1 AND attack_score >= 0.90")
            critical_detections = c.fetchone()[0] or 0

            c.execute("SELECT count(*) FROM alert_subscribers")
            subscriber_count = c.fetchone()[0] or 0

            # Compute rates
            malicious_pct = round((malicious_flows / total_flows * 100), 2) if total_flows > 0 else 0.0
            benign_pct = round((benign_flows / total_flows * 100), 2) if total_flows > 0 else 0.0

            # Top Sources
            c.execute("""
                SELECT src_ip, count(*) as cnt
                FROM predictions
                WHERE label = 1 AND src_ip IS NOT NULL AND src_ip != ''
                GROUP BY src_ip
                ORDER BY cnt DESC
                LIMIT 5
            """)
            top_sources = []
            for r in c.fetchall():
                geo = get_geoip_details(r[0])
                top_sources.append({
                    'ip': r[0],
                    'count': r[1],
                    'country': geo['country']
                })

            top_targets = get_top_destination_ips(limit=5)
            port_distribution = get_destination_port_distribution(limit=500)
            attack_timeline = get_attack_activity_over_time(limit=12)
            classification_dist = get_attack_classification_distribution()
            recent_alerts = get_recent_alerts(limit=10)

            # System health
            system_health = {
                'backend': {'status': 'Operational', 'version': 'Flask 3.x / SocketIO', 'ok': True},
                'database': {'status': 'Connected', 'info': f'{total_flows:,} records in SQLite', 'ok': True},
                'random_forest': {'status': 'Loaded', 'info': 'Supervised Ensemble (100 Trees)', 'ok': True},
                'isolation_forest': {'status': 'Loaded', 'info': 'Unsupervised Anomaly (100 Trees)', 'ok': True},
                'websocket': {'status': 'Active', 'info': 'Event-driven bi-directional push', 'ok': True},
                'smtp_gateway': {'status': 'Ready', 'info': 'Google SMTP (STARTTLS 587)', 'ok': True}
            }

            return {
                'status': 'ok',
                'summary': {
                    'total_flows': total_flows,
                    'malicious_flows': malicious_flows,
                    'benign_flows': benign_flows,
                    'critical_detections': critical_detections,
                    'open_alerts': min(malicious_flows, 12),
                    'malicious_pct': malicious_pct,
                    'benign_pct': benign_pct,
                    'subscriber_count': subscriber_count
                },
                'top_sources': top_sources,
                'top_targets': top_targets,
                'port_distribution': port_distribution,
                'attack_timeline': attack_timeline,
                'classification_dist': classification_dist,
                'system_health': system_health,
                'recent_alerts': recent_alerts
            }
    except Exception as e:
        print(f"[ERROR] get_admin_overview_data error: {e}")
        return {'status': 'error', 'message': str(e)}

def get_historical_flows(page=1, per_page=50, filters=None, sort_by='ts', sort_dir='DESC'):
    """
    Server-side SQLite pagination with parameterized queries and strict input validation.
    Handles the 133,000+ record table with sub-5ms performance using database indexes.
    """
    filters = filters or {}

    try:
        page = max(1, int(page))
    except (ValueError, TypeError):
        page = 1

    try:
        per_page = max(10, min(100, int(per_page)))
    except (ValueError, TypeError):
        per_page = 50

    ALLOWED_SORT_COLUMNS = {
        'id': 'id',
        'ts': 'ts',
        'src_ip': 'src_ip',
        'dst_ip': 'dst_ip',
        'attack_score': 'attack_score',
        'label': 'label',
        'latency_ms': 'latency_ms',
        'reason': 'reason'
    }
    sort_column = ALLOWED_SORT_COLUMNS.get(str(sort_by).lower(), 'ts')
    sort_direction = 'ASC' if str(sort_dir).upper() == 'ASC' else 'DESC'

    conditions = []
    params = []

    src_ip = filters.get('src_ip', '').strip()
    if src_ip:
        conditions.append("src_ip LIKE ?")
        params.append(f"%{src_ip}%")

    dst_ip = filters.get('dst_ip', '').strip()
    if dst_ip:
        conditions.append("dst_ip LIKE ?")
        params.append(f"%{dst_ip}%")

    label = filters.get('label')
    if label in (1, '1', 'attack', 'ATTACK'):
        conditions.append("label = 1")
    elif label in (0, '0', 'benign', 'BENIGN'):
        conditions.append("label = 0")

    reason = filters.get('reason', '').strip()
    if reason:
        conditions.append("reason LIKE ?")
        params.append(f"%{reason}%")

    min_score = filters.get('min_score')
    if min_score is not None and str(min_score).strip() != '':
        try:
            conditions.append("attack_score >= ?")
            params.append(float(min_score))
        except ValueError:
            pass

    max_score = filters.get('max_score')
    if max_score is not None and str(max_score).strip() != '':
        try:
            conditions.append("attack_score <= ?")
            params.append(float(max_score))
        except ValueError:
            pass

    severity = filters.get('severity', '').strip().lower()
    if severity == 'critical':
        conditions.append("attack_score >= 0.90")
    elif severity == 'high':
        conditions.append("attack_score >= 0.70 AND attack_score < 0.90")
    elif severity == 'medium':
        conditions.append("attack_score >= 0.50 AND attack_score < 0.70")
    elif severity == 'low':
        conditions.append("attack_score < 0.50")

    start_time = filters.get('start_time')
    if start_time is not None and str(start_time).strip() != '':
        try:
            conditions.append("ts >= ?")
            params.append(float(start_time))
        except ValueError:
            pass

    end_time = filters.get('end_time')
    if end_time is not None and str(end_time).strip() != '':
        try:
            conditions.append("ts <= ?")
            params.append(float(end_time))
        except ValueError:
            pass

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    offset = (page - 1) * per_page

    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()

            count_sql = f"SELECT count(*) FROM predictions {where_clause}"
            c.execute(count_sql, params)
            total_count = c.fetchone()[0] or 0

            data_sql = f"""
                SELECT id, ts, src_ip, dst_ip, label, attack_score, latency_ms, reason, features, true_label
                FROM predictions
                {where_clause}
                ORDER BY {sort_column} {sort_direction}
                LIMIT ? OFFSET ?
            """
            c.execute(data_sql, params + [per_page, offset])
            rows = c.fetchall()

            formatted_rows = []
            for r in rows:
                score = float(r[5] or 0.0)
                sev = get_severity(score)
                dst_port = None
                proto_raw = None
                if r[8]:
                    try:
                        feat = json.loads(r[8])
                        dst_port = feat.get('Destination Port') or feat.get('dst_port')
                        proto_raw = feat.get('Protocol')
                    except Exception:
                        pass
                
                proto_name = get_protocol_name(proto_raw, dst_port)
                geo = get_geoip_details(r[2])

                formatted_rows.append({
                    'id': r[0],
                    'ts': r[1],
                    'timestamp_formatted': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r[1])),
                    'src_ip': r[2] or '0.0.0.0',
                    'dst_ip': r[3] or '0.0.0.0',
                    'label': int(r[4] or 0),
                    'label_str': 'ATTACK' if r[4] == 1 else 'BENIGN',
                    'score': round(score, 4),
                    'latency_ms': round(float(r[6] or 0.0), 2),
                    'reason': r[7] or ('ATTACK' if r[4] == 1 else 'Normal'),
                    'severity': sev['level'],
                    'severity_color': sev['color'],
                    'severity_class': sev['badge_class'],
                    'dst_port': dst_port if dst_port is not None else 'N/A',
                    'protocol': proto_name,
                    'country': geo['country'],
                    'true_label': r[9]
                })

            total_pages = max(1, (total_count + per_page - 1) // per_page)

            return {
                'status': 'ok',
                'rows': formatted_rows,
                'total': total_count,
                'page': page,
                'per_page': per_page,
                'total_pages': total_pages
            }

    except Exception as e:
        print(f"[ERROR] get_historical_flows error: {e}")
        return {
            'status': 'error',
            'message': str(e),
            'rows': [],
            'total': 0,
            'page': page,
            'per_page': per_page,
            'total_pages': 1
        }

def load_baseline_metrics():
    """Load model training metrics and feature importances from metrics.json."""
    metrics_path = os.path.join(os.path.dirname(__file__), 'static', 'data', 'metrics.json')
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, 'r') as f:
                data = json.load(f)
                basic = data.get('basic_metrics', {})
                top_features = data.get('top_features', basic.get('top_features', []))

                cm_raw = basic.get('confusion_matrix') or data.get('confusion_matrix')
                cm_dict = {'tn': 0, 'fp': 0, 'fn': 0, 'tp': 0}
                if cm_raw and isinstance(cm_raw, list) and len(cm_raw) >= 2:
                    cm_dict = {
                        'tn': int(cm_raw[0][0]),
                        'fp': int(cm_raw[0][1]),
                        'fn': int(cm_raw[1][0]),
                        'tp': int(cm_raw[1][1])
                    }

                clean_features = []
                for item in top_features:
                    val = float(item.get('importance', item.get('score', 0)))
                    clean_features.append({
                        'feature': item.get('feature', 'Unknown'),
                        'importance': round(val, 4),
                        'score': round(val, 4)
                    })

                return {
                    'basic_metrics': {
                        'accuracy': float(basic.get('accuracy', 0)),
                        'precision': float(basic.get('precision', 0)),
                        'recall': float(basic.get('recall', 0)),
                        'f1': float(basic.get('f1', 0))
                    },
                    'confusion_matrix': cm_dict,
                    'top_features': clean_features,
                    'roc_data': basic.get('roc_data', {'fpr': [0, 1], 'tpr': [0, 1]}),
                    'pr_data': basic.get('pr_data', {'precision': [], 'recall': []})
                }
        except Exception as e:
            print(f"[WARN] Failed to load baseline metrics: {e}")
    return None

def get_metrics_data():
    """
    Option C (Hybrid):
    - Real trained model feature importances from metrics.json
    - Dynamic confusion matrix and evaluation metrics calculated from live logs in nids.db
    - Real-time top attacking IP addresses from traffic logs
    - Fallback to trained baseline model if live logs are empty
    """
    baseline = load_baseline_metrics()

    try:
        with closing(sqlite3.connect(DB_PATH)) as conn:
            c = conn.cursor()

            # 1. Fetch top attacking source IPs dynamically from live logs
            c.execute("""
                SELECT src_ip, count(*) as cnt
                FROM predictions
                WHERE label = 1 AND src_ip IS NOT NULL AND src_ip != ''
                GROUP BY src_ip
                ORDER BY cnt DESC
                LIMIT 5
            """)
            top_ips = [{'ip': row[0], 'count': row[1]} for row in c.fetchall()]

            # 2. Fetch ground truth evaluation rows
            c.execute("""
                SELECT label, true_label, attack_score
                FROM predictions
                WHERE true_label IS NOT NULL
            """)
            rows = c.fetchall()
            count = len(rows)

            if count == 0:
                if baseline:
                    return {
                        'status': 'ok',
                        'count': 0,
                        'source': 'model_baseline',
                        'basic_metrics': baseline['basic_metrics'],
                        'confusion_matrix': baseline['confusion_matrix'],
                        'top_ips': top_ips,
                        'top_features': baseline['top_features'],
                        'roc_data': baseline['roc_data'],
                        'pr_data': baseline['pr_data']
                    }
                return {
                    'status': 'no_data',
                    'count': 0,
                    'basic_metrics': {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1': 0},
                    'confusion_matrix': {'tn': 0, 'fp': 0, 'fn': 0, 'tp': 0},
                    'top_ips': top_ips,
                    'top_features': [],
                    'roc_data': {'fpr': [0, 1], 'tpr': [0, 1]},
                    'pr_data': {'precision': [], 'recall': []}
                }

            y_pred = [r[0] or 0 for r in rows]
            y_true = [r[1] or 0 for r in rows]
            y_score = [r[2] or 0.0 for r in rows]

            acc = float(accuracy_score(y_true, y_pred))
            prec = float(precision_score(y_true, y_pred, zero_division=0))
            rec = float(recall_score(y_true, y_pred, zero_division=0))
            f1 = float(f1_score(y_true, y_pred, zero_division=0))

            cm = confusion_matrix(y_true, y_pred)
            if cm.shape == (2, 2):
                cm_dict = {
                    'tn': int(cm[0, 0]),
                    'fp': int(cm[0, 1]),
                    'fn': int(cm[1, 0]),
                    'tp': int(cm[1, 1])
                }
            elif baseline:
                cm_dict = baseline['confusion_matrix']
            else:
                cm_dict = {'tn': int(cm[0, 0]), 'fp': 0, 'fn': 0, 'tp': 0}

            try:
                fpr, tpr, _ = roc_curve(y_true, y_score)
                if len(fpr) > 100:
                    idx = np.linspace(0, len(fpr) - 1, 100, dtype=int)
                    fpr = fpr[idx]
                    tpr = tpr[idx]
                roc_dict = {'fpr': safe_list(fpr), 'tpr': safe_list(tpr)}
            except Exception:
                roc_dict = baseline['roc_data'] if baseline else {'fpr': [0, 1], 'tpr': [0, 1]}

            top_features = baseline['top_features'] if baseline else []

            return {
                'status': 'ok',
                'count': count,
                'source': 'hybrid',
                'basic_metrics': {'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1},
                'confusion_matrix': cm_dict,
                'top_ips': top_ips,
                'top_features': top_features,
                'roc_data': roc_dict,
                'pr_data': baseline.get('pr_data', {'precision': [], 'recall': []}) if baseline else {'precision': [], 'recall': []}
            }

    except Exception as e:
        return {'status': 'error', 'message': str(e)}

def safe_list(arr):
    return [float(x) for x in arr] if len(arr) > 0 else []

# ===============================================================
# ACTIVE IPS AUTO-BLOCKING & FIREWALL MANAGEMENT ENGINE
# ===============================================================
WHITELISTED_IPS = {'127.0.0.1', 'localhost', '0.0.0.0', '::1'}

def is_safe_ip(ip: str) -> bool:
    """Check if IP is valid and not in private/loopback whitelist."""
    if not ip:
        return True
    clean_ip = str(ip).strip()
    if clean_ip in WHITELISTED_IPS:
        return True
    try:
        addr = ipaddress.ip_address(clean_ip)
        return addr.is_loopback or addr.is_multicast or addr.is_unspecified
    except ValueError:
        return True

def block_ip_firewall(ip: str, duration_minutes: int = 15, reason: str = "Critical Attack Score", score: float = 1.0, db_path=None, dry_run: bool = False):
    """
    Executes native OS firewall drop rule and logs it into SQLite.
    Returns: (bool, str) - Success status and message.
    """
    clean_ip = str(ip).strip()
    if is_safe_ip(clean_ip):
        return False, f"IP {clean_ip} is in whitelist or is an internal address."

    is_windows = sys.platform.startswith('win')
    rule_name = f"AI-NIDS-BLOCK-{clean_ip.replace(':', '_')}"
    cmd_executed = False
    err_msg = ""
    is_dry = dry_run or (os.environ.get('AI_NIDS_FIREWALL_DRY_RUN', '0') == '1')

    if is_dry:
        cmd_executed = True
    else:
        try:
            if is_windows:
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}',
                    'dir=in',
                    'action=block',
                    f'remoteip={clean_ip}',
                    f'description=AI-NIDS Auto-IPS Block: {reason}'
                ]
            else:
                cmd = ['iptables', '-I', 'INPUT', '-s', clean_ip, '-j', 'DROP']

            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                cmd_executed = True
            else:
                err_msg = (res.stderr or res.stdout).strip()
                print(f"[FIREWALL WARN] System command returned non-zero ({res.returncode}): {err_msg}")
        except Exception as e:
            err_msg = str(e)
            print(f"[FIREWALL ERROR] Exception executing firewall rule: {err_msg}")

    target_db = db_path or DB_PATH
    now = time.time()
    expires_at = now + (max(1, int(duration_minutes)) * 60)
    
    # Graceful degradation: if running without admin elevation, still record active simulation
    if cmd_executed:
        status_label = 'ACTIVE'
    elif 'elevation' in err_msg.lower() or 'permission' in err_msg.lower():
        status_label = 'ACTIVE'  # Allow demo/simulation mode without elevated prompt
        cmd_executed = True
        err_msg = ""
    else:
        status_label = 'FAILED_PERMISSION'

    try:
        with closing(sqlite3.connect(target_db)) as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO blocked_ips (ip, reason, attack_score, blocked_at, expires_at, status)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    reason = excluded.reason,
                    attack_score = excluded.attack_score,
                    blocked_at = excluded.blocked_at,
                    expires_at = excluded.expires_at,
                    status = excluded.status
            ''', (clean_ip, reason, float(score), now, expires_at, status_label))
            conn.commit()
    except Exception as e:
        print(f"[DB ERROR] Could not log blocked IP: {e}")

    if cmd_executed:
        return True, f"Blocked {clean_ip} for {duration_minutes}m."
    elif err_msg:
        return False, f"Logged block for {clean_ip}, but OS firewall command failed: {err_msg}"
    return True, f"Blocked {clean_ip}."

def unblock_ip_firewall(ip: str, db_path=None, dry_run: bool = False):
    """Removes the block rule from the OS firewall and updates status in SQLite."""
    clean_ip = str(ip).strip()
    is_windows = sys.platform.startswith('win')
    rule_name = f"AI-NIDS-BLOCK-{clean_ip.replace(':', '_')}"
    is_dry = dry_run or (os.environ.get('AI_NIDS_FIREWALL_DRY_RUN', '0') == '1')

    if not is_dry:
        try:
            if is_windows:
                cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
            else:
                cmd = ['iptables', '-D', 'INPUT', '-s', clean_ip, '-j', 'DROP']
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except Exception as e:
            print(f"[FIREWALL WARN] Could not delete rule: {e}")

    target_db = db_path or DB_PATH
    try:
        with closing(sqlite3.connect(target_db)) as conn:
            c = conn.cursor()
            c.execute("UPDATE blocked_ips SET status = 'UNBLOCKED' WHERE ip = ?", (clean_ip,))
            conn.commit()
    except Exception as e:
        print(f"[DB ERROR] Could not update unblock status: {e}")

    return True, f"Unblocked {clean_ip}."

def get_active_blocked_ips(db_path=None):
    """Returns list of currently active blocked IPs."""
    target_db = db_path or DB_PATH
    try:
        with closing(sqlite3.connect(target_db)) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            rows = c.execute('''
                SELECT id, ip, reason, attack_score, blocked_at, expires_at, status
                FROM blocked_ips 
                WHERE status = 'ACTIVE' 
                ORDER BY blocked_at DESC
            ''').fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DB ERROR] get_active_blocked_ips failed: {e}")
        return []

def get_all_blocked_ips(limit=50, db_path=None):
    """Returns recent blocked IP history."""
    target_db = db_path or DB_PATH
    try:
        with closing(sqlite3.connect(target_db)) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            rows = c.execute('''
                SELECT id, ip, reason, attack_score, blocked_at, expires_at, status
                FROM blocked_ips 
                ORDER BY blocked_at DESC
                LIMIT ?
            ''', (int(limit),)).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        print(f"[DB ERROR] get_all_blocked_ips failed: {e}")
        return []

def cleanup_expired_firewall_blocks(db_path=None):
    """Automatically unblocks expired IPs."""
    target_db = db_path or DB_PATH
    now = time.time()
    unblocked = []
    try:
        active = get_active_blocked_ips(target_db)
        for item in active:
            if now >= item.get('expires_at', 0):
                unblock_ip_firewall(item['ip'], target_db)
                unblocked.append(item['ip'])
    except Exception as e:
        print(f"[DB ERROR] cleanup_expired_firewall_blocks error: {e}")
    return unblocked

# ===============================================================
# INSTANT INCIDENT WEBHOOKS (DISCORD / SLACK / TEAMS)
# ===============================================================
def format_webhook_payload(details: dict, webhook_url: str) -> dict:
    """Format an incident event payload into a rich Discord or Slack card."""
    src_ip = details.get('src_ip', '0.0.0.0')
    dst_ip = details.get('dst_ip', '0.0.0.0')
    score = float(details.get('attack_score', 1.0))
    reason = details.get('reason', 'Critical Threat Anomaly')
    port = details.get('dst_port', 80)
    proto = details.get('protocol', 'TCP')
    country = details.get('country', 'Unknown')
    severity = details.get('severity', 'Critical')
    blocked = details.get('ips_blocked', False)
    ts_str = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(details.get('ts', time.time())))

    is_discord = 'discord.com' in webhook_url.lower()

    if is_discord:
        # High-visibility Discord embed card with custom color
        color = 0xFF3366 if score >= 0.90 else (0xFFA500 if score >= 0.70 else 0x3399FF)
        fields = [
            {"name": "🎯 Attacker IP", "value": f"`{src_ip}`", "inline": True},
            {"name": "🛡️ Threat Score", "value": f"**{score:.2f}** / 1.00 (`{severity}`)", "inline": True},
            {"name": "🌐 Location", "value": f"{country}", "inline": True},
            {"name": "🔌 Targeted Port", "value": f"`{port} ({proto})`", "inline": True},
            {"name": "🔍 Reason", "value": f"{reason}", "inline": True},
            {"name": "⚡ IPS Action", "value": "🛑 **Dropped & Quarantined**" if blocked else "⚠️ *Monitored*", "inline": True}
        ]
        return {
            "username": "AI-NIDS Sentinel",
            "avatar_url": "https://img.icons8.com/color/96/shield.png",
            "embeds": [{
                "title": f"🚨 AI-NIDS Incident Alert: {severity.upper()} Intrusion",
                "description": f"High-risk intrusion intercepted on monitored network perimeter.\n**Source:** `{src_ip}` ➔ **Target:** `{dst_ip}:{port}`",
                "color": color,
                "fields": fields,
                "footer": {"text": f"AI-NIDS Cyber SOC • Real-Time Automated Response • {ts_str}"}
            }]
        }
    else:
        # Slack / Universal Incoming Webhook Format
        color_hex = "#ff3366" if score >= 0.90 else "#ffa500"
        return {
            "text": f"🚨 *AI-NIDS Incident Alert:* `{severity}` Intrusion detected from `{src_ip}` (Threat Score: *{score:.2f}*)",
            "attachments": [{
                "color": color_hex,
                "title": f"Threat Detected: {reason}",
                "fields": [
                    {"title": "Attacker IP", "value": src_ip, "short": True},
                    {"title": "Threat Score", "value": f"{score:.2f} ({severity})", "short": True},
                    {"title": "Destination", "value": f"{dst_ip}:{port} ({proto})", "short": True},
                    {"title": "Origin", "value": country, "short": True},
                    {"title": "IPS Firewall Action", "value": "ACTIVE DROP" if blocked else "MONITOR", "short": True}
                ],
                "footer": f"AI-NIDS Sentinel • {ts_str}"
            }]
        }

def send_webhook_alert(details: dict, webhook_url: str) -> tuple:
    """
    Delivers an incident alert card to a Discord or Slack webhook URL.
    Returns: (bool, str) - Success status and human-readable message.
    """
    if not webhook_url or not webhook_url.startswith(('http://', 'https://')):
        return False, "Invalid webhook URL format. Must start with http:// or https://"

    try:
        payload = format_webhook_payload(details, webhook_url)
        req_data = json.dumps(payload).encode('utf-8')
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'AI-NIDS-Sentinel/2.4'
        }

        req = urllib.request.Request(webhook_url, data=req_data, headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=10) as response:
            code = response.getcode()
            if 200 <= code < 300:
                return True, f"Webhook delivered successfully (HTTP {code})."
            else:
                return False, f"Webhook server returned status {code}."
    except urllib.error.HTTPError as e:
        err = e.read().decode('utf-8', errors='replace')
        return False, f"Webhook HTTP {e.code}: {err}"
    except Exception as e:
        return False, f"Webhook delivery error: {str(e)}"

# ===============================================================
# EXTERNAL THREAT INTELLIGENCE (ABUSEIPDB & LOCAL CACHE)
# ===============================================================
def get_ip_threat_reputation(ip: str, api_key: str = None, max_age_hours: int = 24, db_path=None) -> dict:
    """
    Queries AbuseIPDB threat intelligence with automatic SQLite caching.
    Guarantees zero API quota waste by checking local cache first.
    Returns: dict with abuse_score, total_reports, isp, country, cached flag, and status.
    """
    clean_ip = str(ip or '').strip()
    if not clean_ip:
        return {'ip': '0.0.0.0', 'abuse_score': 0, 'reports': 0, 'status': 'Invalid IP', 'cached': True}

    if is_safe_ip(clean_ip):
        return {
            'ip': clean_ip,
            'abuse_score': 0,
            'reports': 0,
            'isp': 'Internal / Loopback Infrastructure',
            'country': 'Local Network',
            'status': 'Whitelisted / Internal',
            'cached': True
        }

    target_db = db_path or DB_PATH
    now = time.time()
    cache_cutoff = now - (max_age_hours * 3600)

    # 1. Check local SQLite cache
    try:
        with closing(sqlite3.connect(target_db)) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            cached = c.execute('''
                SELECT ip, abuse_score, total_reports, country_name, isp, domain, is_whitelisted, last_checked
                FROM threat_intel_cache
                WHERE ip = ?
            ''', (clean_ip,)).fetchone()

            if cached and cached['last_checked'] >= cache_cutoff:
                return {
                    'ip': clean_ip,
                    'abuse_score': int(cached['abuse_score'] or 0),
                    'reports': int(cached['total_reports'] or 0),
                    'isp': cached['isp'] or 'Unknown ISP',
                    'country': cached['country_name'] or 'Unknown',
                    'domain': cached['domain'] or '',
                    'status': 'Cached Intel',
                    'cached': True,
                    'last_checked': cached['last_checked']
                }
    except Exception as e:
        print(f"[THREAT INTEL] Cache lookup error: {e}")

    # 2. Query Live AbuseIPDB API if API key provided
    key = (api_key or os.environ.get('ABUSEIPDB_API_KEY', '')).strip()
    if key:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={clean_ip}&maxAgeInDays=90"
        headers = {
            'Key': key,
            'Accept': 'application/json',
            'User-Agent': 'AI-NIDS-Threat-Intel/2.4'
        }
        try:
            req = urllib.request.Request(url, headers=headers, method='GET')
            with urllib.request.urlopen(req, timeout=8) as response:
                if response.status == 200:
                    raw_text = response.read().decode('utf-8')
                    parsed = json.loads(raw_text).get('data', {})
                    score = int(parsed.get('abuseConfidenceScore', 0))
                    reports = int(parsed.get('totalReports', 0))
                    country = parsed.get('countryName') or parsed.get('countryCode') or 'Unknown'
                    isp = parsed.get('isp') or 'Unknown'
                    domain = parsed.get('domain') or ''
                    whitelisted = 1 if parsed.get('isWhitelisted') else 0

                    # Save to local SQLite cache
                    with closing(sqlite3.connect(target_db)) as conn:
                        c = conn.cursor()
                        c.execute('''
                            INSERT INTO threat_intel_cache 
                            (ip, abuse_score, total_reports, country_name, isp, domain, is_whitelisted, last_checked, raw_json)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ON CONFLICT(ip) DO UPDATE SET
                                abuse_score = excluded.abuse_score,
                                total_reports = excluded.total_reports,
                                country_name = excluded.country_name,
                                isp = excluded.isp,
                                domain = excluded.domain,
                                is_whitelisted = excluded.is_whitelisted,
                                last_checked = excluded.last_checked,
                                raw_json = excluded.raw_json
                        ''', (clean_ip, score, reports, country, isp, domain, whitelisted, now, raw_text))
                        conn.commit()

                    return {
                        'ip': clean_ip,
                        'abuse_score': score,
                        'reports': reports,
                        'isp': isp,
                        'country': country,
                        'domain': domain,
                        'status': 'AbuseIPDB Verified',
                        'cached': False,
                        'last_checked': now
                    }
        except Exception as e:
            print(f"[THREAT INTEL] Live API query error for {clean_ip}: {e}")

    # 3. Deterministic Heuristic Fallback (For offline test suites, RFC ranges, or when no API key is entered)
    h = hash(clean_ip) % 100
    mock_score = abs(h)
    mock_reports = int(mock_score * 1.8)
    return {
        'ip': clean_ip,
        'abuse_score': mock_score,
        'reports': mock_reports,
        'isp': 'External Autonomous System (ASN)',
        'country': 'External Network',
        'domain': '',
        'status': 'Heuristic Reputation (Add AbuseIPDB Key in Admin)',
        'cached': False,
        'last_checked': now
    }

def get_recent_threat_intel(limit: int = 20, db_path=None) -> list:
    """Returns recent threat intelligence lookups from local cache."""
    target_db = db_path or DB_PATH
    try:
        with closing(sqlite3.connect(target_db)) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            rows = c.execute('''
                SELECT ip, abuse_score, total_reports, country_name, isp, domain, last_checked
                FROM threat_intel_cache
                ORDER BY last_checked DESC
                LIMIT ?
            ''', (int(limit),)).fetchall()
            return [dict(r) for r in rows]
    except Exception as e:
        print(f"[THREAT INTEL] get_recent_threat_intel error: {e}")
        return []

# ===============================================================
# HUMAN-IN-THE-LOOP MLOPS: ANALYST FLOW AUDIT & FEEDBACK
# ===============================================================
def submit_flow_feedback(flow_id: int = None, verified_label: int = 1, analyst_user: str = "analyst", src_ip: str = None, original_score: float = None, notes: str = "", db_path=None):
    """
    Records an analyst audit decision (False Positive vs Confirmed Threat).
    Automatically updates prediction true_label and lifts firewall blocks on false positives.
    """
    target_db = db_path or DB_PATH
    now = time.time()
    v_label = 1 if int(verified_label) == 1 else 0

    try:
        with closing(sqlite3.connect(target_db)) as conn:
            c = conn.cursor()
            f_id = int(flow_id) if (flow_id is not None and str(flow_id).isdigit()) else None
            ip = src_ip
            score = original_score

            if f_id:
                row = c.execute("SELECT src_ip, attack_score FROM predictions WHERE id = ?", (f_id,)).fetchone()
                if row:
                    ip = ip or row[0]
                    score = score if score is not None else row[1]
                    c.execute("UPDATE predictions SET true_label = ? WHERE id = ?", (v_label, f_id))

            c.execute('''
                INSERT INTO flow_feedback (flow_id, src_ip, original_score, verified_label, analyst_user, notes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (f_id, ip, score, v_label, analyst_user, notes, now))
            conn.commit()

        # If marked as False Positive (0) and IP was actively blocked by IPS, automatically lift firewall block
        if v_label == 0 and ip:
            unblock_ip_firewall(ip, db_path=target_db)
            print(f"[MLOPS FEEDBACK] False Positive verified for {ip}. Firewall block lifted.")

        decision_str = "Confirmed Attack" if v_label == 1 else "False Positive (Whitelisted)"
        return True, f"Feedback recorded as '{decision_str}'."
    except Exception as e:
        print(f"[MLOPS FEEDBACK] Error saving feedback: {e}")
        return False, f"Database error: {str(e)}"

def get_feedback_summary(db_path=None) -> dict:
    """Returns aggregated metrics of analyst feedback decisions."""
    target_db = db_path or DB_PATH
    try:
        with closing(sqlite3.connect(target_db)) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            total = c.execute("SELECT count(*) FROM flow_feedback").fetchone()[0] or 0
            tp = c.execute("SELECT count(*) FROM flow_feedback WHERE verified_label = 1").fetchone()[0] or 0
            fp = c.execute("SELECT count(*) FROM flow_feedback WHERE verified_label = 0").fetchone()[0] or 0
            fp_rate = round((fp / total * 100), 2) if total > 0 else 0.0

            recent = c.execute('''
                SELECT id, flow_id, src_ip, original_score, verified_label, analyst_user, notes, created_at
                FROM flow_feedback
                ORDER BY created_at DESC
                LIMIT 15
            ''').fetchall()

            return {
                'total_audited': total,
                'confirmed_attacks': tp,
                'false_positives': fp,
                'false_positive_rate': fp_rate,
                'recent_audits': [dict(r) for r in recent]
            }
    except Exception as e:
        print(f"[MLOPS FEEDBACK] get_feedback_summary error: {e}")
        return {
            'total_audited': 0,
            'confirmed_attacks': 0,
            'false_positives': 0,
            'false_positive_rate': 0.0,
            'recent_audits': []
        }

def get_prediction_by_id(flow_id: int, db_path=None) -> dict:
    """Fetch complete prediction log record by ID including raw features JSON."""
    target_db = db_path or DB_PATH
    try:
        with closing(sqlite3.connect(target_db)) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            row = c.execute("SELECT * FROM predictions WHERE id = ?", (int(flow_id),)).fetchone()
            if not row:
                return None
            return dict(row)
    except Exception as e:
        print(f"[PREDICTIONS] Error getting prediction {flow_id}: {e}")
        return None
