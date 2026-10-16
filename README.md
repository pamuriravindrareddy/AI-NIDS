# AI-NIDS: AI-Powered Network Intrusion Detection System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%20%7C%20Flask--SocketIO-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Machine Learning](https://img.shields.io/badge/ML-Random%20Forest%20%7C%20Isolation%20Forest-orange.svg)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**AI-NIDS** is an intelligent, real-time Network Intrusion Detection System designed to protect network infrastructure from volumetric threats, port scans, SYN floods, and zero-day anomalies. It combines supervised machine learning (`RandomForestClassifier`) with unsupervised anomaly detection (`IsolationForest`) and an ensemble scoring pipeline to deliver high-precision threat classification.

---

## 🌟 Key Features

- **Hybrid AI Detection Engine**:
  - **Supervised Random Forest**: Trained on 15 core statistical network flow features from the benchmark CIC-IDS2017 dataset.
  - **Unsupervised Isolation Forest**: Identifies zero-day anomalies and unexpected traffic spikes.
  - **Ensemble Scorer**: Combines supervised attack probabilities ($\alpha$) with unsupervised anomaly scores ($\beta$) against an adjustable classification threshold ($T$).
- **Live Interactive Dashboard**:
  - Real-time GeoIP threat mapping using Leaflet.js and MaxMind GeoLite2.
  - WebSocket-powered live flow telemetry table and traffic intensity stream charts.
  - Dynamic simulation controls to adjust playback speed and threshold parameters on the fly.
- **Automated Incident Alerting**:
  - Instant SMTP security warning emails dispatched to system administrators.
  - User self-subscription portal allowing incident warnings to be delivered directly to interested stakeholders.
- **Node & Security Policy Control**:
  - Remote node identity configuration and auto-detected IP tracking.
  - Protocol firewall policies (IPv4 traffic switch, TCP toggle, SYN flood detection rules).
  - Main system power toggle to control packet processing.
- **Forensic Analytics & Reporting**:
  - Real-time confusion matrix, precision-recall curve, and ROC curve visualization.
  - Feature importance breakdown across flow metrics.
  - One-click attack log export (`ai_nids_attack_logs.csv`).

---

## 🏗️ System Architecture

```
                      +-----------------------------+
                      |   Network Flow Telemetry    |
                      |  (Simulation / Live Flows)  |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |  Feature Extraction (15)    |
                      |  & StandardScaler Transform |
                      +--------------+--------------+
                                     |
                    +----------------+----------------+
                    |                                 |
                    v                                 v
        +-----------------------+         +-----------------------+
        |   Random Forest (RF)  |         | Isolation Forest (IF) |
        |   Supervised Scoring  |         |  Unsupervised Anomaly |
        +-----------+-----------+         +-----------+-----------+
                    |                                 |
                    +----------------+----------------+
                                     |
                                     v
                      +-----------------------------+
                      |      Ensemble Scorer        |
                      |  S = α·P(RF) + β·S(IF)      |
                      +--------------+--------------+
                                     |
                     [ S >= Threshold or Signature ]
                                     |
                    +----------------+----------------+
                    |                                 |
              [ATTACK DETECTED]                    [BENIGN]
                    |                                 |
        +-----------+-----------+                     v
        | - WebSocket Broadcast |               Logged to nids.db
        | - Leaflet Map Marker  |
        | - SMTP Alert Email    |
        | - nids.db Audit Log   |
        +-----------------------+
```

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- Git

### 2. Clone the Repository
```bash
git clone https://github.com/pamuriravindrareddy/AI-NIDS.git
cd AI-NIDS
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```
*(Or install packages: `pip install flask flask-socketio scikit-learn pandas numpy geoip2 joblib`)*

### 4. Run the Application
```bash
python app.py
```
Access the application at [http://localhost:5000](http://localhost:5000).

---

## 🔑 Default Credentials

- **Username**: `admin`
- **Password**: `admin`

---

## 📡 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Home page & system capability overview |
| `GET` | `/prediction` | Live threat monitor & interactive attack map |
| `GET` | `/analysis` | Model evaluation & forensic analysis dashboard |
| `GET/POST`| `/admin` | Administration & network node security policies |
| `POST` | `/api/test_email` | Test SMTP alert delivery to specified recipient |
| `GET/POST`| `/api/subscribers` | View or subscribe email addresses to alert pipeline |
| `POST` | `/api/subscribers/delete` | Remove an email from alert subscriptions |
| `POST` | `/api/settings` | Update $\alpha$, $\beta$, and classification threshold |
| `GET` | `/api/live_stats` | Live packet counts, session telemetry, and GeoIP markers |
| `GET` | `/api/metrics_data` | Confusion matrix, ROC, PR curve data for forensic view |
| `GET` | `/download_logs` | Export full incident logs as CSV (`ai_nids_attack_logs.csv`) |

---

## 🛡️ License

This project is licensed under the MIT License.
