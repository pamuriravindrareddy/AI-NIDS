# -*- coding: utf-8 -*-
"""
test_feature_schema.py - Automated Unit & Integration Tests for Feature Schema Verification

Verifies:
1. Training and inference canonical feature lists match exactly.
2. Feature order is preserved across feature_extraction, inference, and scaler.
3. Missing required features are handled safely (strict rejection vs non-strict defaults).
4. Incorrect input dimensions cannot silently produce predictions (no positional shifting/padding).
5. Scaler receives correctly named and ordered features.
"""

import unittest
import numpy as np
import pandas as pd
import joblib

from feature_extraction import CANONICAL_FEATURES, FEATURE_KEYS, validate_flow_dict, row_to_vector, row_to_dataframe
from inference import EnsembleDetector, predict_flow, get_detector_info, reload_detector


class FeatureSchemaTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reload detector using v2 models
        reload_detector(use_v2=True)
        cls.detector = EnsembleDetector(use_v2=True)

    def test_01_feature_list_exact_match(self):
        """Verify that training and inference feature lists match exactly."""
        self.assertEqual(len(CANONICAL_FEATURES), 14)
        self.assertEqual(CANONICAL_FEATURES, FEATURE_KEYS)

        # Check against v2 scaler
        scaler_v2 = joblib.load('models/scaler_v2.joblib')
        self.assertEqual(scaler_v2.n_features_in_, 14)
        self.assertEqual(list(scaler_v2.feature_names_in_), CANONICAL_FEATURES)

    def test_02_feature_order_preserved(self):
        """Verify feature ordering is preserved strictly from index 0 to 13."""
        expected_order = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
            'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
            'Flow IAT Mean', 'Fwd IAT Mean', 'Bwd IAT Mean',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags'
        ]
        self.assertEqual(CANONICAL_FEATURES, expected_order)

        # DataFrame conversion preserves exact order
        dummy_row = {k: float(i + 1) for i, k in enumerate(reversed(expected_order))}
        df_out = row_to_dataframe(dummy_row)
        self.assertEqual(list(df_out.columns), expected_order)
        # Verify values mapped to correct column names rather than positional order
        self.assertEqual(df_out['Flow Duration'].iloc[0], dummy_row['Flow Duration'])
        self.assertEqual(df_out['Bwd URG Flags'].iloc[0], dummy_row['Bwd URG Flags'])

    def test_03_missing_required_features_strict_rejection(self):
        """Verify missing required features raise descriptive ValueError in strict mode."""
        incomplete_flow = {
            'Flow Duration': 50000,
            'Total Fwd Packets': 10
            # Missing remaining 12 canonical features
        }
        with self.assertRaises(ValueError) as ctx:
            validate_flow_dict(incomplete_flow, strict=True)
        self.assertIn("Missing required canonical flow features", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            row_to_vector(incomplete_flow, strict=True)
        self.assertIn("Missing required canonical flow features", str(ctx.exception))

    def test_04_missing_features_non_strict_defaults_safely(self):
        """Verify missing features default to 0.0 without crash when strict=False."""
        incomplete_flow = {
            'Flow Duration': 50000,
            'Total Fwd Packets': 10
        }
        cleaned = validate_flow_dict(incomplete_flow, strict=False)
        self.assertEqual(len(cleaned), 14)
        self.assertEqual(cleaned['Flow Duration'], 50000.0)
        self.assertEqual(cleaned['Total Fwd Packets'], 10.0)
        self.assertEqual(cleaned['Total Backward Packets'], 0.0)
        self.assertEqual(cleaned['Bwd URG Flags'], 0.0)

        vec = row_to_vector(incomplete_flow, strict=False)
        self.assertEqual(vec.shape, (1, 14))

    def test_05_incorrect_dimensions_rejected_no_silent_padding(self):
        """Verify incorrect input dimensions cannot silently produce predictions."""
        # 5-element array (expected 14)
        wrong_short = np.array([1.0, 2.0, 3.0, 4.0, 5.0])
        with self.assertRaises(ValueError) as ctx:
            self.detector._prepare_dataframe(wrong_short)
        self.assertIn("Incorrect input dimensions: expected 14", str(ctx.exception))

        # 20-element array (expected 14)
        wrong_long = np.ones((1, 20))
        with self.assertRaises(ValueError) as ctx:
            self.detector._prepare_dataframe(wrong_long)
        self.assertIn("Incorrect input dimensions: expected 14", str(ctx.exception))

    def test_06_non_numeric_and_nan_values_handled(self):
        """Verify non-numeric or NaN/Inf values are handled strictly or sanitized."""
        corrupted_row = {k: 1.0 for k in CANONICAL_FEATURES}
        corrupted_row['Flow Duration'] = float('nan')
        corrupted_row['Total Fwd Packets'] = "invalid_string"

        # Strict mode raises ValueError
        with self.assertRaises(ValueError):
            validate_flow_dict(corrupted_row, strict=True)

        # Non-strict mode sanitizes to 0.0
        cleaned = validate_flow_dict(corrupted_row, strict=False)
        self.assertEqual(cleaned['Flow Duration'], 0.0)
        self.assertEqual(cleaned['Total Fwd Packets'], 0.0)
        self.assertEqual(cleaned['Total Backward Packets'], 1.0)

    def test_07_scaler_receives_correct_schema(self):
        """Verify the scaler receives correctly named and ordered features in inference."""
        sample_flow = {k: float(i * 10) for i, k in enumerate(CANONICAL_FEATURES)}
        res = self.detector.predict(sample_flow)
        self.assertNotIn('error', res)
        self.assertIn('supervised_prob', res)
        self.assertIn('unsupervised_score', res)
        self.assertIn('attack_score', res)
        self.assertIn('label', res)
        self.assertGreaterEqual(res['attack_score'], 0.0)
        self.assertLessEqual(res['attack_score'], 1.0)
        self.assertGreater(res['latency_ms'], 0.0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
