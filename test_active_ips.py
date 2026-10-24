# -*- coding: utf-8 -*-
"""
test_active_ips.py - Unit and Integration Tests for AI-NIDS Active IPS Auto-Blocking
"""

import os
import sys
import time
import sqlite3
import unittest
import tempfile
from contextlib import closing

# Ensure parent directory is in path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import utils
from utils import (
    init_db, is_safe_ip, block_ip_firewall, unblock_ip_firewall,
    get_active_blocked_ips, get_all_blocked_ips, cleanup_expired_firewall_blocks
)
import app as app_module
from app import app, IOT_CONFIG


class ActiveIPSTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a temporary database for test isolation
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db = os.path.join(cls.temp_dir.name, 'test_nids.db')
        init_db(cls.test_db)
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_01_safe_ip_whitelisting(self):
        """Verify that loopback, localhost, and invalid IPs are never blocked."""
        self.assertTrue(is_safe_ip('127.0.0.1'))
        self.assertTrue(is_safe_ip('localhost'))
        self.assertTrue(is_safe_ip('0.0.0.0'))
        self.assertTrue(is_safe_ip('::1'))
        self.assertTrue(is_safe_ip(''))
        self.assertTrue(is_safe_ip(None))
        # An external public IP should NOT be whitelisted
        self.assertFalse(is_safe_ip('203.0.113.195'))
        self.assertFalse(is_safe_ip('198.51.100.42'))

    def test_02_block_whitelisted_ip_rejected(self):
        """Verify block_ip_firewall rejects whitelisted IPs safely."""
        success, msg = block_ip_firewall('127.0.0.1', db_path=self.test_db)
        self.assertFalse(success)
        self.assertIn('whitelist', msg.lower())

    def test_03_block_and_query_active_ips(self):
        """Verify blocking an IP records it into the database with active status."""
        test_ip = '198.51.100.88'
        success, msg = block_ip_firewall(
            ip=test_ip,
            duration_minutes=15,
            reason='DDoS SYN Flood Attack',
            score=0.98,
            db_path=self.test_db
        )
        self.assertTrue(success)

        # Check in active list
        active = get_active_blocked_ips(db_path=self.test_db)
        ips = [r['ip'] for r in active]
        self.assertIn(test_ip, ips)

        # Verify record attributes
        rec = next(r for r in active if r['ip'] == test_ip)
        self.assertEqual(rec['reason'], 'DDoS SYN Flood Attack')
        self.assertAlmostEqual(rec['attack_score'], 0.98)
        self.assertGreater(rec['expires_at'], rec['blocked_at'])

    def test_04_unblock_ip(self):
        """Verify unblocking an IP updates its status in the database."""
        test_ip = '198.51.100.88'
        success, msg = unblock_ip_firewall(test_ip, db_path=self.test_db)
        self.assertTrue(success)

        # Active list should no longer include it
        active = get_active_blocked_ips(db_path=self.test_db)
        ips = [r['ip'] for r in active]
        self.assertNotIn(test_ip, ips)

        # All history should still have it as UNBLOCKED
        all_blocks = get_all_blocked_ips(limit=10, db_path=self.test_db)
        rec = next((r for r in all_blocks if r['ip'] == test_ip), None)
        self.assertIsNotNone(rec)
        self.assertEqual(rec['status'], 'UNBLOCKED')

    def test_05_cleanup_expired_blocks(self):
        """Verify that expired bans are automatically unblocked by the cleanup function."""
        expired_ip = '198.51.100.99'
        now = time.time()
        # Manually insert an already expired block into the test db
        with closing(sqlite3.connect(self.test_db)) as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO blocked_ips (ip, reason, attack_score, blocked_at, expires_at, status)
                VALUES (?, ?, ?, ?, ?, 'ACTIVE')
            ''', (expired_ip, 'Old Attack', 0.95, now - 3600, now - 60))
            conn.commit()

        unblocked = cleanup_expired_firewall_blocks(db_path=self.test_db)
        self.assertIn(expired_ip, unblocked)

        # Ensure it is marked UNBLOCKED
        active = get_active_blocked_ips(db_path=self.test_db)
        self.assertNotIn(expired_ip, [r['ip'] for r in active])

    def test_06_api_endpoints_rbac(self):
        """Verify API endpoints require authentication and proper admin role."""
        # Unauthenticated request to /api/ips/blocked should redirect or fail
        res = self.client.get('/api/ips/blocked')
        self.assertIn(res.status_code, [302, 401, 403])

        # Test authenticated admin session
        with self.client.session_transaction() as sess:
            sess['user'] = 'admin'
            sess['role'] = 'admin'

        res = self.client.get('/api/ips/blocked')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get('status'), 'ok')
        self.assertIn('records', data)

    def test_07_iot_config_ips_settings(self):
        """Verify IOT_CONFIG contains IPS keys."""
        self.assertIn('ips_auto_block', IOT_CONFIG)
        self.assertIn('ips_block_threshold', IOT_CONFIG)
        self.assertIn('ips_block_duration', IOT_CONFIG)


if __name__ == '__main__':
    unittest.main()
