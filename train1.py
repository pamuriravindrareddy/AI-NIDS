# -*- coding: utf-8 -*-
"""
train1.py - NIDS Training & Metrics Generation Script for AI-NIDS

Trains Random Forest and Isolation Forest on clean deduplicated data,
evaluates both models independently and as a hybrid ensemble,
and exports metrics.json for the SOC dashboard.
"""

import os
import argparse
import json
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_curve,
    precision_recall_curve,
    roc_auc_score
)
import joblib

# Canonical 14-feature schema
FEATURE_KEYS = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Mean',
    'Flow IAT Mean',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'Fwd PSH Flags',
    'Bwd PSH Flags',
    'Fwd URG Flags',
    'Bwd URG Flags'
]

LABEL_COL = 'Label'


def preprocess_dataframe(df):
    print(f"[INFO] Raw rows: {len(df):,}, columns: {len(df.columns)}")
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    missing_cols = [col for col in FEATURE_KEYS if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required feature columns: {missing_cols}")

    if LABEL_COL not in df.columns:
        raise ValueError(f"Label column '{LABEL_COL}' not found in CSV.")

    df[FEATURE_KEYS] = df[FEATURE_KEYS].fillna(0.0)

    # Label encoding: BENIGN -> 0, Attack -> 1
    y = df[LABEL_COL].apply(lambda x: 0 if str(x).strip().upper() in ('BENIGN', 'NORMAL', '0') else 1)
    df['target'] = y

    # Deduplication
    before = len(df)
    df = df.drop_duplicates(subset=FEATURE_KEYS + ['target']).copy()
    print(f"[INFO] Removed {before - len(df):,} exact duplicate rows.")

    # Remove conflicting label tuples
    conflicts = df.duplicated(subset=FEATURE_KEYS, keep=False)
    if conflicts.sum() > 0:
        print(f"[INFO] Removed {conflicts.sum()} contradictory feature rows.")
        df = df[~conflicts].copy()

    X = df[FEATURE_KEYS].astype(np.float64)
    y = df['target'].values
    print(f"[INFO] Clean dataset size: {len(y):,} samples.")
    return X, y


def main(csv_path):
    print(f"[INFO] Loading CSV: {csv_path}")
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"[ERROR] Could not read CSV: {e}")
        return

    X, y = preprocess_dataframe(df)

    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.15, random_state=42, stratify=y_train_val
    )
    print(f"[INFO] Split: Train={len(y_train):,}, Val={len(y_val):,}, Test={len(y_test):,}")

    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=FEATURE_KEYS)
    X_val_scaled = pd.DataFrame(scaler.transform(X_val), columns=FEATURE_KEYS)
    X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=FEATURE_KEYS)

    # 1. Train Random Forest
    print("[INFO] Training RandomForestClassifier (100 trees)...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)

    # 2. Train Isolation Forest (Benign-only)
    X_train_benign = X_train_scaled[y_train == 0]
    print(f"[INFO] Training Isolation Forest on {len(X_train_benign):,} clean BENIGN training flows...")
    iso = IsolationForest(n_estimators=100, contamination=0.03, random_state=42, n_jobs=-1)
    iso.fit(X_train_benign)

    # Calibration
    benign_scores = iso.score_samples(X_train_benign)
    min_b = float(np.percentile(benign_scores, 1))
    max_b = float(np.percentile(benign_scores, 99))

    # Test Predictions
    rf_prob = rf.predict_proba(X_test_scaled)[:, 1]
    rf_pred = (rf_prob >= 0.5).astype(int)

    iso_raw = iso.score_samples(X_test_scaled)
    iso_prob = np.clip((max_b - iso_raw) / (max_b - min_b), 0.0, 1.0)
    iso_pred = (iso_prob >= 0.5).astype(int)

    ens_score = 0.6 * rf_prob + 0.4 * iso_prob
    ens_pred = (ens_score >= 0.5).astype(int)

    def get_metrics_dict(y_t, y_p, y_s):
        cm = confusion_matrix(y_t, y_p).tolist()
        return {
            "accuracy": float(accuracy_score(y_t, y_p)),
            "precision": float(precision_score(y_t, y_p, zero_division=0)),
            "recall": float(recall_score(y_t, y_p, zero_division=0)),
            "f1": float(f1_score(y_t, y_p, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_t, y_s)),
            "confusion_matrix": cm
        }

    rf_metrics = get_metrics_dict(y_test, rf_pred, rf_prob)
    iso_metrics = get_metrics_dict(y_test, iso_pred, iso_prob)
    ens_metrics = get_metrics_dict(y_test, ens_pred, ens_score)

    print("\n[RESULT] Random Forest Alone:")
    print(f"  Acc: {rf_metrics['accuracy']*100:.2f}%, Prec: {rf_metrics['precision']:.4f}, Rec: {rf_metrics['recall']:.4f}, F1: {rf_metrics['f1']:.4f}")
    print("\n[RESULT] Hybrid Ensemble (0.6 RF + 0.4 IF):")
    print(f"  Acc: {ens_metrics['accuracy']*100:.2f}%, Prec: {ens_metrics['precision']:.4f}, Rec: {ens_metrics['recall']:.4f}, F1: {ens_metrics['f1']:.4f}")

    # Curve Data
    fpr, tpr, _ = roc_curve(y_test, ens_score)
    precision_curve, recall_curve, _ = precision_recall_curve(y_test, ens_score)

    if len(fpr) > 100:
        idx_r = np.linspace(0, len(fpr) - 1, 100, dtype=int)
        roc_data = {"fpr": fpr[idx_r].tolist(), "tpr": tpr[idx_r].tolist()}
    else:
        roc_data = {"fpr": fpr.tolist(), "tpr": tpr.tolist()}

    if len(precision_curve) > 100:
        idx_p = np.linspace(0, len(precision_curve) - 1, 100, dtype=int)
        pr_data = {"precision": precision_curve[idx_p].tolist(), "recall": recall_curve[idx_p].tolist()}
    else:
        pr_data = {"precision": precision_curve.tolist(), "recall": recall_curve.tolist()}

    # Top Features
    importances = rf.feature_importances_
    feat_imp = sorted(zip(FEATURE_KEYS, importances), key=lambda x: x[1], reverse=True)
    top_features = [{"feature": f, "importance": float(imp)} for f, imp in feat_imp[:10]]

    # Save Models
    os.makedirs("models", exist_ok=True)
    joblib.dump(scaler, "models/scaler.joblib")
    joblib.dump(rf, "models/supervised_rf.joblib")
    joblib.dump(iso, "models/unsupervised_iso.joblib")

    # Metrics JSON
    metrics = {
        "basic_metrics": ens_metrics,
        "accuracy": ens_metrics["accuracy"],
        "precision": ens_metrics["precision"],
        "recall": ens_metrics["recall"],
        "f1": ens_metrics["f1"],
        "confusion_matrix": ens_metrics["confusion_matrix"],
        "roc_data": roc_data,
        "pr_data": pr_data,
        "top_features": top_features,
        "rf_alone_metrics": rf_metrics,
        "iso_alone_metrics": iso_metrics,
        "canonical_features": FEATURE_KEYS
    }

    out_dir = os.path.join("static", "data")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "metrics.json")
    with open(out_path, "w") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"[INFO] Metrics written to {out_path}")
    print("[INFO] Training & evaluation successfully complete.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Train IDS models and save metrics.')
    parser.add_argument('--csv', default='data/CICIDS2017_subset.csv', help='Path to dataset CSV')
    args = parser.parse_args()
    main(args.csv)
