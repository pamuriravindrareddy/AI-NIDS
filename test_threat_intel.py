# -*- coding: utf-8 -*-
"""
test_threat_intel.py - Unit and Integration Tests for AbuseIPDB Threat Intelligence & Cache
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

from utils import init_db, get_ip_threat_reputation, get_recent_threat_intel
from app import app, IOT_CONFIG


class ThreatIntelligenceTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db = os.path.join(cls.temp_dir.name, 'test_nids.db')
        init_db(cls.test_db)
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_01_safe_ip_returns_whitelisted(self):
        """Verify loopback and local IPs return zero abuse risk without calling external APIs."""
        res_loopback = get_ip_threat_reputation('127.0.0.1', db_path=self.test_db)
        self.assertEqual(res_loopback['abuse_score'], 0)
        self.assertEqual(res_loopback['reports'], 0)
        self.assertTrue(res_loopback['cached'])
        self.assertIn('whitelisted', res_loopback['status'].lower())

    def test_02_heuristic_fallback_for_public_ips(self):
        """Verify offline heuristic provides valid threat metrics without crashing."""
        test_ip = '198.51.100.55'
        res = get_ip_threat_reputation(test_ip, api_key=None, db_path=self.test_db)
        self.assertEqual(res['ip'], test_ip)
        self.assertIsInstance(res['abuse_score'], int)
        self.assertGreaterEqual(res['abuse_score'], 0)
        self.assertLessEqual(res['abuse_score'], 100)
        self.assertIn('isp', res)
        self.assertIn('country', res)

    def test_03_sqlite_caching_layer(self):
        """Verify that cached entries are read from SQLite without redundant lookups."""
        cached_ip = '203.0.113.77'
        now = time.time()
        # Insert known threat intel record directly into SQLite cache
        with closing(sqlite3.connect(self.test_db)) as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO threat_intel_cache 
                (ip, abuse_score, total_reports, country_name, isp, domain, is_whitelisted, last_checked, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (cached_ip, 88, 142, 'Netherlands', 'Hosting Provider NV', 'example.nl', 0, now, '{}'))
            conn.commit()

        # Query the reputation function
        intel = get_ip_threat_reputation(cached_ip, db_path=self.test_db)
        self.assertEqual(intel['ip'], cached_ip)
        self.assertEqual(intel['abuse_score'], 88)
        self.assertEqual(intel['reports'], 142)
        self.assertEqual(intel['country'], 'Netherlands')
        self.assertEqual(intel['isp'], 'Hosting Provider NV')
        self.assertTrue(intel['cached'])

    def test_04_api_endpoint_rbac(self):
        """Verify /api/threat_intel/check requires authentication and returns structured JSON."""
        # Unauthenticated request should redirect or fail
        res = self.client.get('/api/threat_intel/check?ip=198.51.100.99')
        self.assertIn(res.status_code, [302, 401, 403])

        # Authenticated user request
        with self.client.session_transaction() as sess:
            sess['user'] = 'analyst'
            sess['role'] = 'user'

        res_auth = self.client.get('/api/threat_intel/check?ip=198.51.100.99')
        self.assertEqual(res_auth.status_code, 200)
        data = res_auth.get_json()
        self.assertEqual(data.get('status'), 'ok')
        self.assertIn('threat_intel', data)
        self.assertEqual(data['threat_intel']['ip'], '198.51.100.99')

    def test_05_iot_config_contains_abuse_keys(self):
        """Verify IOT_CONFIG contains abuseipdb settings."""
        self.assertIn('abuseipdb_enabled', IOT_CONFIG)
        self.assertIn('abuseipdb_api_key', IOT_CONFIG)


if __name__ == '__main__':
    unittest.main()
