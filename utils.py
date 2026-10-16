import time
import os
import sqlite3
import json
import io
import csv
import numpy as np
from contextlib import closing
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve, precision_recall_curve
from collections import Counter, defaultdict

DB_PATH = os.path.join(os.path.dirname(__file__), 'nids.db')

def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()
        # Added 'reason' column
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
                        password TEXT
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS alert_subscribers (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE,
                        created_at REAL
                    )''')
        # Add reason column if missing (for updates)
        try:
            c.execute("ALTER TABLE predictions ADD COLUMN reason TEXT")
        except:
            pass

        # Provision default admin user if not present
        c.execute("SELECT count(*) FROM users WHERE username = 'admin'")
        if c.fetchone()[0] == 0:
            from werkzeug.security import generate_password_hash
            default_pwd_hash = generate_password_hash('admin', method='pbkdf2:sha256')
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', default_pwd_hash))

        conn.commit()

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
            # Convert TS to readable
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
                SELECT ts, src_ip, dst_ip, attack_score, label, reason
                FROM predictions
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = c.fetchall()

            recent_logs = []
            for r in rows:
                recent_logs.append({
                    'ts': r[0],
                    'src_ip': r[1] or '0.0.0.0',
                    'dst_ip': r[2] or '0.0.0.0',
                    'attack_score': float(r[3] or 0.0),
                    'label': int(r[4] or 0),
                    'reason': r[5] or ('ATTACK' if r[4] == 1 else 'Normal')
                })

            return {
                'total_packets': total_packets,
                'total_attacks': total_attacks,
                'recent_logs': recent_logs
            }
    except Exception as e:
        print(f"[WARN] get_live_stats error: {e}")
        return {'total_packets': 0, 'total_attacks': 0, 'recent_logs': []}

def load_baseline_metrics():
    """Load model training metrics and feature importances from metrics.json."""
    metrics_path = os.path.join(os.path.dirname(__file__), 'static', 'data', 'metrics.json')
    if os.path.exists(metrics_path):
        try:
            with open(metrics_path, 'r') as f:
                data = json.load(f)
                basic = data.get('basic_metrics', {})
                top_features = data.get('top_features', basic.get('top_features', []))

                # Format confusion matrix if available
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

            # 2. Fetch ground truth evaluation rows (without heavy JSON features payload)
            c.execute("""
                SELECT label, true_label, attack_score
                FROM predictions
                WHERE true_label IS NOT NULL
            """)
            rows = c.fetchall()
            count = len(rows)

            # If no live labeled data, fall back to baseline model metrics
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

            # 3. Compute live performance metrics from traffic stream
            y_pred = [r[0] or 0 for r in rows]
            y_true = [r[1] or 0 for r in rows]
            y_score = [r[2] or 0.0 for r in rows]

            acc = float(accuracy_score(y_true, y_pred))
            prec = float(precision_score(y_true, y_pred, zero_division=0))
            rec = float(recall_score(y_true, y_pred, zero_division=0))
            f1 = float(f1_score(y_true, y_pred, zero_division=0))

            # 4. Compute live confusion matrix
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

            # 5. Compute live ROC Curve (downsampled for smooth frontend rendering)
            try:
                fpr, tpr, _ = roc_curve(y_true, y_score)
                if len(fpr) > 100:
                    idx = np.linspace(0, len(fpr) - 1, 100, dtype=int)
                    fpr = fpr[idx]
                    tpr = tpr[idx]
                roc_dict = {'fpr': safe_list(fpr), 'tpr': safe_list(tpr)}
            except Exception:
                roc_dict = baseline['roc_data'] if baseline else {'fpr': [0, 1], 'tpr': [0, 1]}

            # 6. Feature importances (Hybrid: uses trained model feature weights)
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