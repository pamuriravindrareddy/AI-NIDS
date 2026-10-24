# -*- coding: utf-8 -*-
"""
test_analyst_feedback.py - Unit and Integration Tests for Human-in-the-Loop MLOps Feedback
"""

import os
import sys
import time
import sqlite3
import unittest
import tempfile
from contextlib import closing

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils import init_db, block_ip_firewall, get_active_blocked_ips, submit_flow_feedback, get_feedback_summary
from app import app


class AnalystFeedbackTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db = os.path.join(cls.temp_dir.name, 'test_nids.db')
        init_db(cls.test_db)
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_01_submit_confirmed_threat(self):
        """Verify submitting confirmed threat records to feedback table."""
        test_ip = '198.51.100.33'
        ok, msg = submit_flow_feedback(
            flow_id=101,
            verified_label=1,
            analyst_user='sec_analyst_1',
            src_ip=test_ip,
            original_score=0.92,
            notes='Confirmed true DoS flood',
            db_path=self.test_db
        )
        self.assertTrue(ok)
        self.assertIn('confirmed', msg.lower())

        summary = get_feedback_summary(db_path=self.test_db)
        self.assertGreaterEqual(summary['total_audited'], 1)
        self.assertGreaterEqual(summary['confirmed_attacks'], 1)

    def test_02_false_positive_auto_lifts_firewall(self):
        """Verify marking a flow as False Positive lifts any active firewall block."""
        target_ip = '198.51.100.44'
        # First, block the IP via firewall
        block_ip_firewall(target_ip, duration_minutes=15, db_path=self.test_db, dry_run=True)
        active = get_active_blocked_ips(db_path=self.test_db)
        self.assertIn(target_ip, [r['ip'] for r in active])

        # Now analyst marks this flow as False Positive (0)
        ok, msg = submit_flow_feedback(
            flow_id=102,
            verified_label=0,
            analyst_user='sec_analyst_1',
            src_ip=target_ip,
            original_score=0.88,
            notes='Benign developer load test',
            db_path=self.test_db
        )
        self.assertTrue(ok)
        self.assertIn('false positive', msg.lower())

        # Verify the IP is no longer in active blocked list
        active_after = get_active_blocked_ips(db_path=self.test_db)
        self.assertNotIn(target_ip, [r['ip'] for r in active_after])

    def test_03_feedback_summary_calculation(self):
        """Verify false positive rate calculation in summary."""
        summary = get_feedback_summary(db_path=self.test_db)
        self.assertGreaterEqual(summary['total_audited'], 2)
        self.assertGreaterEqual(summary['false_positives'], 1)
        self.assertGreater(summary['false_positive_rate'], 0.0)

    def test_04_api_endpoint_rbac(self):
        """Verify /api/flows/feedback requires authenticated session."""
        # Unauthenticated request should fail
        res = self.client.post('/api/flows/feedback', json={'src_ip': '1.2.3.4', 'verified_label': 1})
        self.assertIn(res.status_code, [302, 401, 403])

        # Authenticated user request
        with self.client.session_transaction() as sess:
            sess['user'] = 'analyst_alice'
            sess['role'] = 'user'

        res_auth = self.client.post('/api/flows/feedback', json={
            'src_ip': '203.0.113.99',
            'verified_label': 1,
            'original_score': 0.95,
            'notes': 'Verified exploit'
        })
        self.assertEqual(res_auth.status_code, 200)
        data = res_auth.get_json()
        self.assertEqual(data.get('status'), 'ok')
        self.assertIn('summary', data)


if __name__ == '__main__':
    unittest.main()
