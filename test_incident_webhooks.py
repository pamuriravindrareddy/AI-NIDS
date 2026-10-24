# -*- coding: utf-8 -*-
"""
test_incident_webhooks.py - Unit and Integration Tests for Discord & Slack Incident Webhooks
"""

import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from utils import format_webhook_payload, send_webhook_alert
from app import app, IOT_CONFIG


class IncidentWebhookTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()

    def test_01_discord_payload_formatting(self):
        """Verify format_webhook_payload formats a valid Discord embed card."""
        discord_url = "https://discord.com/api/webhooks/123456789/abcdef"
        flow = {
            'src_ip': '203.0.113.88',
            'dst_ip': '192.168.1.1',
            'attack_score': 0.98,
            'severity': 'Critical',
            'reason': 'Volumetric SYN Flood',
            'dst_port': 443,
            'protocol': 'HTTPS',
            'country': 'United States',
            'ips_blocked': True
        }
        payload = format_webhook_payload(flow, discord_url)

        self.assertIn('embeds', payload)
        self.assertEqual(len(payload['embeds']), 1)
        embed = payload['embeds'][0]
        self.assertIn('CRITICAL', embed['title'])
        self.assertEqual(embed['color'], 0xFF3366)  # Critical Red
        
        # Verify fields
        field_names = [f['name'] for f in embed['fields']]
        self.assertTrue(any('Attacker IP' in name for name in field_names))
        self.assertTrue(any('Threat Score' in name for name in field_names))
        self.assertTrue(any('IPS Action' in name for name in field_names))

    def test_02_slack_payload_formatting(self):
        """Verify format_webhook_payload formats a valid Slack card."""
        slack_url = "https://hooks.slack.com/services/T00/B00/XXXX"
        flow = {
            'src_ip': '198.51.100.42',
            'dst_ip': '10.0.0.1',
            'attack_score': 0.85,
            'severity': 'High',
            'reason': 'Port Scan Probe',
            'dst_port': 22,
            'protocol': 'SSH',
            'country': 'Germany',
            'ips_blocked': False
        }
        payload = format_webhook_payload(flow, slack_url)

        self.assertIn('attachments', payload)
        self.assertEqual(len(payload['attachments']), 1)
        att = payload['attachments'][0]
        self.assertEqual(att['color'], '#ffa500')  # High Orange

    def test_03_invalid_webhook_url(self):
        """Verify send_webhook_alert rejects malformed URLs."""
        flow = {'src_ip': '1.2.3.4', 'attack_score': 0.9}
        ok, msg = send_webhook_alert(flow, "not_a_valid_url")
        self.assertFalse(ok)
        self.assertIn("invalid", msg.lower())

    def test_04_test_webhook_endpoint_rbac(self):
        """Verify /api/test_webhook requires administrator authentication."""
        # Unauthenticated request should be redirected or forbidden
        res = self.client.post('/api/test_webhook', json={'webhook_url': 'https://discord.com/api/webhooks/test'})
        self.assertIn(res.status_code, [302, 401, 403])

        # Authenticated admin request with empty URL should return 400
        with self.client.session_transaction() as sess:
            sess['user'] = 'apashamkirikiri320@gmail.com'
            sess['email'] = 'apashamkirikiri320@gmail.com'
            sess['role'] = 'admin'

        res2 = self.client.post('/api/test_webhook', json={'webhook_url': ''})
        self.assertEqual(res2.status_code, 400)

    def test_05_iot_config_contains_webhook_keys(self):
        """Verify IOT_CONFIG has webhook settings."""
        self.assertIn('webhook_enabled', IOT_CONFIG)
        self.assertIn('webhook_url', IOT_CONFIG)


if __name__ == '__main__':
    unittest.main()
