"""
Comprehensive test suite verifying all 6 decisions for AI-NIDS dashboard redesign.
Tests RBAC, Class B enhancements, Historical Flow Explorer, Admin Overview APIs,
and model inference preservation.
"""

import sys
import unittest
import json
import time
import sqlite3
from app import app, IOT_CONFIG, get_local_ip
from utils import (
    DB_PATH, init_db, get_admin_overview_data, get_historical_flows,
    get_severity, get_protocol_name, get_geoip_details, get_top_destination_ips,
    get_destination_port_distribution, get_attack_activity_over_time,
    get_attack_classification_distribution, get_recent_alerts, get_metrics_data
)
from inference import predict_flow, get_detector_info, get_model_health


class TestDashboardRedesign(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        app.config['TESTING'] = True
        cls.client = app.test_client()

    def test_01_rbac_database_roles(self):
        """Verify role column exists and single designated admin / user roles are correctly mapped."""
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            cols = [d[1] for d in c.execute("PRAGMA table_info(users)").fetchall()]
            self.assertIn('role', cols, "users table must contain 'role' column")

            # Designated single-owner administrator must have 'admin' role
            owner_user = c.execute("SELECT role FROM users WHERE LOWER(email) = 'apashamkirikiri320@gmail.com'").fetchone()
            self.assertIsNotNone(owner_user)
            self.assertEqual(owner_user[0], 'admin', "Designated owner must have 'admin' role")

            # Former admins must be demoted to 'user' role
            admin_user = c.execute("SELECT role FROM users WHERE username = 'admin'").fetchone()
            if admin_user:
                self.assertEqual(admin_user[0], 'user', "Former admin must be demoted to 'user' role")

            normal_user = c.execute("SELECT role FROM users WHERE username = 'madhan'").fetchone()
            if normal_user:
                self.assertEqual(normal_user[0], 'user', "regular user must have 'user' role")

    def test_02_rbac_endpoint_protection(self):
        """Verify @admin_required protects admin endpoints from unauthorized access."""
        # 1. Unauthenticated request to /admin -> 302 to login
        res = self.client.get('/admin')
        self.assertEqual(res.status_code, 302)

        # 2. Regular user session accessing /admin -> 403 Forbidden
        with self.client.session_transaction() as sess:
            sess['user'] = 'madhan'
            sess['role'] = 'user'
        res = self.client.get('/admin')
        self.assertEqual(res.status_code, 403)

        # 3. Regular user accessing /api/admin/overview -> 403 Forbidden
        res = self.client.get('/api/admin/overview')
        self.assertEqual(res.status_code, 403)

        # 4. Designated single-owner admin session accessing /admin -> 200 OK
        with self.client.session_transaction() as sess:
            sess['user'] = 'apashamkirikiri320@gmail.com'
            sess['email'] = 'apashamkirikiri320@gmail.com'
            sess['role'] = 'admin'
        res = self.client.get('/admin')
        self.assertEqual(res.status_code, 200)

        # 5. Admin accessing /api/admin/overview -> 200 OK
        res = self.client.get('/api/admin/overview')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get('status'), 'ok')

    def test_03_class_b_severity_scale(self):
        """Verify documented Low/Medium/High/Critical severity mapping."""
        sev_low = get_severity(0.25)
        self.assertEqual(sev_low['level'], 'Low')

        sev_med = get_severity(0.55)
        self.assertEqual(sev_med['level'], 'Medium')

        sev_high = get_severity(0.78)
        self.assertEqual(sev_high['level'], 'High')

        sev_crit = get_severity(0.95)
        self.assertEqual(sev_crit['level'], 'Critical')

    def test_04_class_b_protocols_and_ports(self):
        """Verify readable protocol labels and port heuristics."""
        self.assertEqual(get_protocol_name('tcp'), 'TCP')
        self.assertEqual(get_protocol_name(6), 'TCP')
        self.assertEqual(get_protocol_name('udp'), 'UDP')
        self.assertEqual(get_protocol_name(17), 'UDP')
        self.assertEqual(get_protocol_name('icmp'), 'ICMP')
        self.assertEqual(get_protocol_name(None, port=53), 'UDP')
        self.assertEqual(get_protocol_name(None, port=443), 'TCP')

    def test_05_class_b_geoip_enrichment(self):
        """Verify GeoIP country lookup and private IP fallback."""
        geo_local = get_geoip_details('127.0.0.1')
        self.assertTrue(geo_local['is_private'])
        self.assertEqual(geo_local['country'], 'Localhost')

        geo_priv = get_geoip_details('192.168.1.50')
        self.assertTrue(geo_priv['is_private'])
        self.assertEqual(geo_priv['country'], 'Internal Network')

        geo_ext = get_geoip_details('8.8.8.8')
        self.assertFalse(geo_ext['is_private'])
        self.assertIn(geo_ext['country'], ['United States', 'External / Unknown'])

    def test_06_top_targeted_destination_ips(self):
        """Verify top destination IPs calculation from real database records."""
        top_targets = get_top_destination_ips(limit=5)
        self.assertIsInstance(top_targets, list)
        self.assertGreater(len(top_targets), 0)
        self.assertIn('ip', top_targets[0])
        self.assertIn('count', top_targets[0])
        self.assertGreater(top_targets[0]['count'], 0)

    def test_07_destination_port_distribution(self):
        """Verify port distribution extraction from malicious flow JSON features."""
        ports = get_destination_port_distribution(limit=500)
        self.assertIsInstance(ports, list)
        self.assertGreater(len(ports), 0)
        self.assertIn('port', ports[0])
        self.assertIn('count', ports[0])
        self.assertIn('service', ports[0])

    def test_08_attack_timeline_and_classification(self):
        """Verify attack activity over time and threat classification distribution."""
        timeline = get_attack_activity_over_time(limit=12)
        self.assertIn('labels', timeline)
        self.assertIn('counts', timeline)
        self.assertGreater(len(timeline['labels']), 0)

        cls_dist = get_attack_classification_distribution()
        self.assertIn('labels', cls_dist)
        self.assertIn('counts', cls_dist)
        self.assertGreater(len(cls_dist['labels']), 0)

    def test_09_historical_flow_explorer_pagination(self):
        """Verify server-side SQLite pagination across 133k+ rows with parameterized queries."""
        t0 = time.time()
        res = get_historical_flows(page=1, per_page=50)
        elapsed_ms = (time.time() - t0) * 1000

        self.assertEqual(res['status'], 'ok')
        self.assertGreaterEqual(res['total'], 133000, "Should reflect actual 133,000+ records")
        self.assertEqual(len(res['rows']), 50, "Default per_page must be 50 records")
        self.assertLess(elapsed_ms, 200, f"Query must be sub-200ms using indexes (was {elapsed_ms:.1f}ms)")

        # Verify enriched fields on rows
        first_row = res['rows'][0]
        self.assertIn('severity', first_row)
        self.assertIn('protocol', first_row)
        self.assertIn('dst_port', first_row)
        self.assertIn('latency_ms', first_row)
        self.assertIn('country', first_row)
        self.assertIn('score', first_row)

        # Verify filtered query
        filtered = get_historical_flows(page=1, per_page=25, filters={'label': 'attack', 'severity': 'critical'})
        self.assertEqual(filtered['status'], 'ok')
        self.assertLessEqual(len(filtered['rows']), 25)
        for r in filtered['rows']:
            self.assertEqual(r['label'], 1)
            self.assertGreaterEqual(r['score'], 0.90)

    def test_10_admin_overview_data_structure(self):
        """Verify complete Admin Overview data structure matches Decision 4 specifications."""
        data = get_admin_overview_data()
        self.assertEqual(data['status'], 'ok')

        summary = data['summary']
        self.assertGreater(summary['total_flows'], 130000)
        self.assertGreater(summary['malicious_flows'], 0)
        self.assertGreater(summary['benign_flows'], 0)
        self.assertEqual(summary['total_flows'], summary['malicious_flows'] + summary['benign_flows'])
        self.assertGreater(summary['critical_detections'], 0)

        # Health
        health = data['system_health']
        self.assertTrue(health['backend']['ok'])
        self.assertTrue(health['database']['ok'])
        self.assertTrue(health['random_forest']['ok'])
        self.assertTrue(health['isolation_forest']['ok'])
        self.assertTrue(health['websocket']['ok'])
        self.assertTrue(health['smtp_gateway']['ok'])

        # Recent alerts
        alerts = data['recent_alerts']
        self.assertLessEqual(len(alerts), 10)
        if len(alerts) > 0:
            self.assertIn('severity', alerts[0])
            self.assertIn('src_ip', alerts[0])
            self.assertIn('dst_ip', alerts[0])

    def test_11_ml_pipeline_preservation(self):
        """Verify Random Forest, Isolation Forest, and hybrid forensic metrics are preserved."""
        # Test sample flow inference
        sample_flow = {
            'Destination Port': 443,
            'Flow Duration': 50000,
            'Total Fwd Packets': 10,
            'Total Backward Packets': 8,
            'Total Length of Fwd Packets': 500,
            'Total Length of Bwd Packets': 1200,
            'Protocol': 6
        }
        res = predict_flow(sample_flow)
        self.assertIn('supervised_prob', res)
        self.assertIn('unsupervised_score', res)
        self.assertIn('attack_score', res)
        self.assertIn('label', res)
        self.assertIn('latency_ms', res)
        self.assertGreater(res['latency_ms'], 0.0)

        # Test model health
        health = get_model_health()
        self.assertTrue(health['rf_loaded'])
        self.assertTrue(health['iso_loaded'])
        self.assertTrue(health['scaler_loaded'])

        # Test forensic metrics from utils
        metrics = get_metrics_data()
        self.assertEqual(metrics.get('status'), 'ok')
        self.assertIn('basic_metrics', metrics)
        self.assertIn('confusion_matrix', metrics)
        self.assertIn('top_features', metrics)


if __name__ == '__main__':
    unittest.main()
