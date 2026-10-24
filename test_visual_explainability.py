import unittest
import json
import os
import sqlite3
import numpy as np

from inference import explain_flow, predict_flow, _detector
from app import app
from utils import DB_PATH, log_prediction, get_prediction_by_id


class TestVisualExplainability(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

        # Seed test flow in SQLite
        self.test_flow_features = {
            'Destination Port': 80,
            'Flow Duration': 45000,
            'Total Fwd Packets': 120,
            'Total Backward Packets': 2,
            'Total Length of Fwd Packets': 65000,
            'Total Length of Bwd Packets': 100,
            'Fwd Packet Length Max': 1460,
            'Fwd Packet Length Min': 40,
            'Fwd Packet Length Mean': 540,
            'Fwd Packet Length Std': 110,
            'Bwd Packet Length Max': 50,
            'Bwd Packet Length Min': 50,
            'Bwd Packet Length Mean': 50,
            'Bwd Packet Length Std': 0
        }

        # Log prediction to get an ID
        self.flow_id = 999999
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("DELETE FROM predictions WHERE id = ?", (self.flow_id,))
            c.execute('''
                INSERT INTO predictions (id, ts, src_ip, dst_ip, features, supervised_prob, unsupervised_score, attack_score, label, true_label, latency_ms, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.flow_id,
                1700000000.0,
                '198.51.100.99',
                '192.168.1.50',
                json.dumps(self.test_flow_features),
                0.95,
                0.88,
                0.92,
                1,
                None,
                15.2,
                'Simulated High-Volume Attack'
            ))
            conn.commit()

    def tearDown(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.cursor().execute("DELETE FROM predictions WHERE id = ?", (self.flow_id,))
            conn.commit()

    def test_explain_flow_structure(self):
        """Verify explain_flow returns valid SHAP decomposition structure."""
        explanation = explain_flow(self.test_flow_features, top_k=5)
        self.assertIn('method', explanation)
        self.assertIn(explanation['method'], ['shap', 'tree_feature_importance_deviation'])
        self.assertIn('top_features', explanation)
        self.assertIn('summary', explanation)
        self.assertIn('all_features', explanation)
        self.assertIn('flow_prediction', explanation)

        top_feats = explanation['top_features']
        self.assertGreater(len(top_feats), 0)
        self.assertLessEqual(len(top_feats), 5)

        for feat in top_feats:
            self.assertIn('feature', feat)
            self.assertIn('shap_value', feat)
            self.assertIn('direction', feat)
            self.assertIn(feat['direction'], ['attack', 'benign'])
            self.assertIn('magnitude', feat)
            self.assertIn('percentage', feat)
            self.assertIsInstance(feat['shap_value'], float)

    def test_get_prediction_by_id(self):
        """Verify database helper correctly retrieves prediction record and features."""
        rec = get_prediction_by_id(self.flow_id)
        self.assertIsNotNone(rec)
        self.assertEqual(rec['src_ip'], '198.51.100.99')
        features = json.loads(rec['features'])
        self.assertEqual(features['Destination Port'], 80)

    def test_api_explain_flow_by_id(self):
        """Verify GET /api/flows/<id>/explain endpoint returns 200 with attribution."""
        with self.client.session_transaction() as sess:
            sess['user'] = 'apashamkirikiri320@gmail.com'
            sess['role'] = 'admin'

        res = self.client.get(f'/api/flows/{self.flow_id}/explain')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['status'], 'ok')
        self.assertEqual(data['flow_id'], self.flow_id)
        self.assertEqual(data['src_ip'], '198.51.100.99')
        self.assertIn('explanation', data)
        self.assertGreater(len(data['explanation']['top_features']), 0)

    def test_api_explain_custom_features(self):
        """Verify POST /api/flows/explain accepts custom flow feature payload."""
        with self.client.session_transaction() as sess:
            sess['user'] = 'analyst'
            sess['role'] = 'user'

        res = self.client.post('/api/flows/explain', json={
            'features': self.test_flow_features,
            'top_k': 3
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['status'], 'ok')
        self.assertEqual(len(data['explanation']['top_features']), 3)

    def test_explain_nonexistent_flow(self):
        """Verify proper 404 error returned for unknown flow ID."""
        with self.client.session_transaction() as sess:
            sess['user'] = 'analyst'
            sess['role'] = 'user'

        res = self.client.get('/api/flows/88888888/explain')
        self.assertEqual(res.status_code, 404)
        data = res.get_json()
        self.assertEqual(data['status'], 'error')


if __name__ == '__main__':
    unittest.main()
