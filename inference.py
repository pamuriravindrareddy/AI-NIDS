# -*- coding: utf-8 -*-
"""
inference.py - Robust Inference Engine for AI-NIDS

- Strictly validates canonical 14-feature schema by name.
- Prevents silent positional truncation or zero-padding.
- Dynamically aligns Random Forest attack class index via model.classes_.
- Correctly normalizes Isolation Forest anomaly scores using benign calibration.
- Combines models using configurable weighted ensemble (default: alpha=0.6, beta=0.4, threshold=0.5).
- Handles SHAP explainability safely with graceful fallback if dependencies are absent.
"""

import os
import time
import joblib
import numpy as np
import pandas as pd
import traceback
import warnings

from feature_extraction import CANONICAL_FEATURES, FEATURE_KEYS, validate_flow_dict, row_to_dataframe

# Suppress SHAP inner_full warnings if shap is loaded
warnings.filterwarnings("ignore", message="Please use inner_full rather than model_output")

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')


class EnsembleDetector:
    def __init__(self, alpha=0.6, beta=0.4, thresh=0.5, use_v2=False):
        self.alpha = float(alpha)
        self.beta = float(beta)
        self.thresh = float(thresh)
        self.use_v2 = use_v2
        self.scaler = None
        self.rf = None
        self.iso = None
        self.explainer = None
        self.expected_features = 14
        self.canonical_features = list(CANONICAL_FEATURES)
        self.attack_idx = 1
        self.calib_min = -0.6849
        self.calib_max = -0.3229
        self._load()

    def _load(self):
        """Load scaler, models, calibration metrics, and SHAP explainer."""
        # Determine artifact filenames based on v2 flag or presence
        scaler_name = 'scaler_v2.joblib' if self.use_v2 and os.path.exists(os.path.join(MODELS_DIR, 'scaler_v2.joblib')) else 'scaler.joblib'
        rf_name = 'supervised_rf_v2.joblib' if self.use_v2 and os.path.exists(os.path.join(MODELS_DIR, 'supervised_rf_v2.joblib')) else 'supervised_rf.joblib'
        iso_name = 'unsupervised_iso_v2.joblib' if self.use_v2 and os.path.exists(os.path.join(MODELS_DIR, 'unsupervised_iso_v2.joblib')) else 'unsupervised_iso.joblib'
        summary_name = 'eval_summary_v2.joblib' if self.use_v2 and os.path.exists(os.path.join(MODELS_DIR, 'eval_summary_v2.joblib')) else 'eval_summary.joblib'

        try:
            self.scaler = joblib.load(os.path.join(MODELS_DIR, scaler_name))
            self.rf = joblib.load(os.path.join(MODELS_DIR, rf_name))
            self.iso = joblib.load(os.path.join(MODELS_DIR, iso_name))
            print(f"[INFO] Models loaded successfully ({scaler_name}, {rf_name}, {iso_name}).")
        except Exception as e:
            print(f"[ERROR] Failed to load essential model artifacts: {e}")
            raise

        # Determine expected features and canonical list from scaler
        if hasattr(self.scaler, 'n_features_in_'):
            self.expected_features = int(self.scaler.n_features_in_)
        else:
            self.expected_features = len(CANONICAL_FEATURES)

        if hasattr(self.scaler, 'feature_names_in_'):
            self.canonical_features = list(self.scaler.feature_names_in_)
        else:
            self.canonical_features = list(CANONICAL_FEATURES)

        # Dynamic attack class index lookup
        if hasattr(self.rf, 'classes_'):
            classes = list(self.rf.classes_)
            if 1 in classes:
                self.attack_idx = classes.index(1)
            elif '1' in classes:
                self.attack_idx = classes.index('1')
            else:
                self.attack_idx = 1
        else:
            self.attack_idx = 1

        # Load Isolation Forest Calibration Metrics if available
        summary_path = os.path.join(MODELS_DIR, summary_name)
        if os.path.exists(summary_path):
            try:
                summary_data = joblib.load(summary_path)
                if isinstance(summary_data, dict) and 'isolation_forest_calibration' in summary_data:
                    calib = summary_data['isolation_forest_calibration']
                    self.calib_min = float(calib.get('min_score', -0.6849))
                    self.calib_max = float(calib.get('max_score', -0.3229))
                    print(f"[INFO] Loaded IF calibration: min={self.calib_min:.4f}, max={self.calib_max:.4f}")
            except Exception as e:
                print(f"[WARN] Could not parse IF calibration from summary: {e}")

        # Optional SHAP Explainer
        try:
            import shap
            explainer_path = os.path.join(MODELS_DIR, 'shap_explainer.joblib')
            if os.path.exists(explainer_path):
                try:
                    self.explainer = joblib.load(explainer_path)
                    print("[INFO] SHAP explainer loaded successfully.")
                except Exception as load_err:
                    print(f"[WARN] Failed loading precomputed explainer ({load_err}), initializing dynamic TreeExplainer.")
                    self.explainer = shap.TreeExplainer(self.rf) if self.rf is not None else None
            elif self.rf is not None:
                self.explainer = shap.TreeExplainer(self.rf)
                print("[INFO] Dynamic SHAP TreeExplainer initialized.")
            else:
                self.explainer = None
        except Exception as e:
            print(f"[WARN] SHAP explainer disabled ({e}).")
            self.explainer = None

        print(f"[INFO] Detector initialized. Expected features: {self.expected_features}. Attack index: {self.attack_idx}.")

    def _prepare_dataframe(self, flow_input, strict=False):
        """
        Convert input dictionary or array to an explicitly named DataFrame.
        Rejects positional shifting and handles missing/invalid values.
        """
        if isinstance(flow_input, dict):
            # Check for missing required features if strict mode is requested
            missing = [k for k in self.canonical_features if k not in flow_input]
            if missing and strict:
                raise ValueError(f"Missing required canonical feature(s): {missing}")

            cleaned = {}
            for key in self.canonical_features:
                val = flow_input.get(key, 0.0)
                try:
                    num = float(val)
                    if np.isnan(num) or np.isinf(num):
                        if strict:
                            raise ValueError(f"Feature '{key}' contains non-finite value: {val}")
                        num = 0.0
                except (ValueError, TypeError):
                    if strict:
                        raise ValueError(f"Feature '{key}' has invalid non-numeric value: {val}")
                    num = 0.0
                cleaned[key] = num

            return pd.DataFrame([cleaned], columns=self.canonical_features)

        elif isinstance(flow_input, (list, np.ndarray)):
            arr = np.array(flow_input).reshape(1, -1)
            if arr.shape[1] != self.expected_features:
                raise ValueError(
                    f"Incorrect input dimensions: expected {self.expected_features} features, got {arr.shape[1]}. "
                    "Positional truncation and silent zero-padding are disabled."
                )
            return pd.DataFrame(arr, columns=self.canonical_features)

        else:
            raise TypeError(f"Unsupported flow input type: {type(flow_input).__name__}. Expected dict or ndarray.")

    def predict(self, flow_row, strict=False):
        """
        Execute dual-engine inference for a single network flow.

        Args:
            flow_row (dict or array): Incoming network flow data.
            strict (bool): If True, strictly validates all required feature keys.

        Returns:
            dict: Structured prediction results including probabilities, scores, latency, and severity.
        """
        start_time = time.time()

        try:
            # Explicit named DataFrame conversion
            df_in = self._prepare_dataframe(flow_row, strict=strict)

            # Feature Scaling
            scaled_arr = self.scaler.transform(df_in)
            scaled_df = pd.DataFrame(scaled_arr, columns=self.canonical_features)

            # Supervised Random Forest Probability
            rf_probs = self.rf.predict_proba(scaled_df)[0]
            supervised_prob = float(rf_probs[self.attack_idx])

            # Unsupervised Isolation Forest Anomaly Score
            unsupervised_raw = float(self.iso.score_samples(scaled_df)[0])

            # Calibrate Isolation Forest score to [0, 1] threat index
            if self.calib_max != self.calib_min:
                unsupervised_prob = float(np.clip(
                    (self.calib_max - unsupervised_raw) / (self.calib_max - self.calib_min),
                    0.0, 1.0
                ))
            else:
                unsupervised_prob = float(np.interp(unsupervised_raw, [-1.0, 0.0], [1.0, 0.0]))

            # Hybrid Ensemble Threat Index
            attack_score = float((self.alpha * supervised_prob) + (self.beta * unsupervised_prob))
            label = 1 if attack_score >= self.thresh else 0

            latency_ms = float((time.time() - start_time) * 1000)

            result = {
                'supervised_prob': supervised_prob,
                'unsupervised_score': unsupervised_prob,
                'raw_iso_score': unsupervised_raw,
                'attack_score': attack_score,
                'label': int(label),
                'latency_ms': latency_ms,
                'shap_explain': {}
            }

            # Explainability: Compute local feature contributions (SHAP / analytical)
            explain_res = self.explain_scaled_vector(scaled_arr, flow_input=df_in.iloc[0].to_dict(), top_k=5)
            result['shap_explain'] = {f['feature']: f['shap_value'] for f in explain_res.get('top_features', [])[:3]}
            result['explanation'] = explain_res

            return result

        except Exception as e:
            latency_ms = float((time.time() - start_time) * 1000)
            return {
                'error': str(e),
                'traceback': traceback.format_exc(),
                'latency_ms': latency_ms,
                'shap_explain': {},
                'explanation': {
                    'method': 'error',
                    'base_value': 0.5,
                    'top_features': [],
                    'all_features': {},
                    'summary': f'Explainability error: {str(e)}'
                }
            }

    def explain_scaled_vector(self, scaled_vec, flow_input=None, top_k=5):
        """
        Calculates local feature contribution attribution for a scaled feature vector.
        Uses SHAP TreeExplainer when available, with a normalized tree importance fallback.
        """
        vals = None
        base_val = 0.5
        method = 'shap'

        if self.explainer is not None:
            try:
                shap_raw = self.explainer.shap_values(scaled_vec)
                if hasattr(self.explainer, 'expected_value'):
                    exp_val = self.explainer.expected_value
                    if isinstance(exp_val, (list, np.ndarray)):
                        base_val = float(exp_val[self.attack_idx] if len(exp_val) > self.attack_idx else exp_val[-1])
                    else:
                        base_val = float(exp_val)

                if isinstance(shap_raw, list):
                    vals = shap_raw[self.attack_idx] if len(shap_raw) > self.attack_idx else shap_raw[-1]
                    if vals.ndim > 1:
                        vals = vals[0]
                elif isinstance(shap_raw, np.ndarray):
                    if shap_raw.ndim == 3:
                        idx = self.attack_idx if shap_raw.shape[2] > self.attack_idx else 0
                        vals = shap_raw[0, :, idx]
                    elif shap_raw.ndim == 2:
                        vals = shap_raw[0]
                    else:
                        vals = shap_raw
                else:
                    vals = np.array(shap_raw).flatten()[:len(self.canonical_features)]
            except Exception as e:
                vals = None

        if vals is None:
            method = 'tree_feature_importance_deviation'
            if self.rf is not None and hasattr(self.rf, 'feature_importances_'):
                importances = self.rf.feature_importances_
                s = scaled_vec[0] if getattr(scaled_vec, 'ndim', 1) > 1 else scaled_vec
                clipped_s = np.clip(s, -5.0, 5.0)
                vals = importances * clipped_s
            else:
                vals = np.zeros(len(self.canonical_features))

        vals = np.array(vals, dtype=float)
        total_mag = float(np.sum(np.abs(vals)))
        if total_mag == 0:
            total_mag = 1.0

        all_features = {}
        feature_list = []
        raw_vals = flow_input if isinstance(flow_input, dict) else {}

        for i, feat in enumerate(self.canonical_features):
            val_f = float(vals[i]) if i < len(vals) else 0.0
            all_features[feat] = round(val_f, 4)
            feature_list.append({
                'feature': feat,
                'shap_value': round(val_f, 4),
                'direction': 'attack' if val_f > 0 else 'benign',
                'magnitude': round(abs(val_f), 4),
                'percentage': round(float((abs(val_f) / total_mag) * 100), 1),
                'raw_value': raw_vals.get(feat, None)
            })

        feature_list.sort(key=lambda x: x['magnitude'], reverse=True)
        top_features = feature_list[:top_k]

        attack_factors = [f"{f['feature']} (+{f['percentage']}%)" for f in top_features if f['direction'] == 'attack']
        benign_factors = [f"{f['feature']} (-{f['percentage']}%)" for f in top_features if f['direction'] == 'benign']

        if attack_factors:
            summary = "Primary attack drivers: " + ", ".join(attack_factors)
        else:
            summary = "Traffic characteristics align closely with baseline benign flows (" + ", ".join(benign_factors[:2]) + ")"

        return {
            'method': method,
            'base_value': round(base_val, 4),
            'top_features': top_features,
            'all_features': all_features,
            'summary': summary
        }

    def explain(self, flow_input, top_k=5, strict=False):
        """
        Public explanation method for any raw or pre-structured flow.
        """
        df = self._prepare_dataframe(flow_input, strict=strict)
        scaled_vec = self.scaler.transform(df)
        raw_dict = df.iloc[0].to_dict()
        pred_res = self.predict(flow_input, strict=strict)
        explain_res = self.explain_scaled_vector(scaled_vec, flow_input=raw_dict, top_k=top_k)
        explain_res['flow_prediction'] = {
            'label': pred_res.get('label'),
            'attack_score': pred_res.get('attack_score'),
            'supervised_prob': pred_res.get('supervised_prob'),
            'unsupervised_score': pred_res.get('unsupervised_score'),
            'reason': pred_res.get('reason'),
            'latency_ms': pred_res.get('latency_ms')
        }
        return explain_res

    def set_params(self, alpha=None, beta=None, thresh=None):
        """Dynamically adjust ensemble blending weights and decision threshold."""
        if alpha is not None:
            self.alpha = float(alpha)
        if beta is not None:
            self.beta = float(beta)
        if thresh is not None:
            self.thresh = float(thresh)
        print(f"[INFO] Detector parameters updated: alpha={self.alpha}, beta={self.beta}, T={self.thresh}")


# ===============================================================
# PUBLIC API MODULE INTERFACE
# ===============================================================
_detector = EnsembleDetector()


def predict_flow(flow_row, strict=False):
    return _detector.predict(flow_row, strict=strict)


def explain_flow(flow_row, top_k=5, strict=False):
    return _detector.explain(flow_row, top_k=top_k, strict=strict)


def set_detector_params(alpha=None, beta=None, thresh=None):
    _detector.set_params(alpha, beta, thresh)


def get_detector_info():
    return {
        'alpha': _detector.alpha,
        'beta': _detector.beta,
        'thresh': _detector.thresh,
        'expected_features': _detector.expected_features,
        'canonical_features': _detector.canonical_features,
        'attack_class_index': _detector.attack_idx
    }


def get_model_health():
    return {
        'rf_loaded': _detector.rf is not None,
        'rf_estimators': getattr(_detector.rf, 'n_estimators', 100) if _detector.rf else 0,
        'iso_loaded': _detector.iso is not None,
        'iso_estimators': getattr(_detector.iso, 'n_estimators', 100) if _detector.iso else 0,
        'scaler_loaded': _detector.scaler is not None,
        'expected_features': _detector.expected_features,
        'explainer_loaded': _detector.explainer is not None,
        'alpha': _detector.alpha,
        'beta': _detector.beta,
        'thresh': _detector.thresh
    }


def reload_detector(use_v2=False):
    """Reload detector with latest models or switch between versioned artifacts."""
    global _detector
    _detector = EnsembleDetector(use_v2=use_v2)
    return get_model_health()
