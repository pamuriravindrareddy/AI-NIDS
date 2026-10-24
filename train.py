# -*- coding: utf-8 -*-
"""
train.py - NIDS Model Training Script for AI-NIDS

Trains Random Forest (supervised) and Isolation Forest (unsupervised, benign-only)
using the canonical 14-feature schema on deduplicated, leakage-resistant data.
"""

import os
import argparse
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score
import joblib

# Canonical 14-feature schema (without non-existent Protocol)
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
    """Clean, deduplicate, and prepare dataframe for training."""
    print(f"[INFO] Raw rows: {len(df):,}, columns: {len(df.columns)}")
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    missing_cols = [col for col in FEATURE_KEYS if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required feature columns in CSV: {missing_cols}")

    if LABEL_COL not in df.columns:
        raise ValueError(f"Label column '{LABEL_COL}' not found in CSV.")

    df[FEATURE_KEYS] = df[FEATURE_KEYS].fillna(0.0)

    # Encode Label: BENIGN -> 0, Attack -> 1
    y = df[LABEL_COL].apply(lambda x: 0 if str(x).strip().upper() in ('BENIGN', 'NORMAL', '0') else 1)
    df['target'] = y

    # Deduplicate on features + label to prevent train-test leakage
    before_dedup = len(df)
    df = df.drop_duplicates(subset=FEATURE_KEYS + ['target']).copy()
    print(f"[INFO] Deduplication: removed {before_dedup - len(df):,} exact duplicate rows.")

    # Remove ambiguous conflicting feature tuples
    conflicts = df.duplicated(subset=FEATURE_KEYS, keep=False)
    if conflicts.sum() > 0:
        print(f"[INFO] Removing {conflicts.sum()} contradictory feature rows with conflicting labels.")
        df = df[~conflicts].copy()

    X = df[FEATURE_KEYS].astype(np.float64)
    y = df['target'].values
    print(f"[INFO] Clean dataset size: {len(y):,} samples (Benign: {np.sum(y==0):,}, Attack: {np.sum(y==1):,})")
    return X, y


def main(csv_path):
    print(f"[INFO] Loading CSV: {csv_path}")
    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"[ERROR] Could not read CSV: {e}")
        return

    X, y = preprocess_dataframe(df)

    # 70% Train+Val / 30% Test split (stratified)
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.15, random_state=42, stratify=y_train_val
    )
    print(f"[INFO] Data split: Train={len(y_train):,}, Val={len(y_val):,}, Test={len(y_test):,}")

    # Scale data (fit ONLY on X_train)
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=FEATURE_KEYS)
    X_val_scaled = pd.DataFrame(scaler.transform(X_val), columns=FEATURE_KEYS)
    X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=FEATURE_KEYS)

    # 1. Train Random Forest (Supervised)
    print("[INFO] Training RandomForestClassifier (100 estimators)...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)

    # 2. Train Isolation Forest (Unsupervised, BENIGN-only)
    X_train_benign = X_train_scaled[y_train == 0]
    print(f"[INFO] Training Isolation Forest on {len(X_train_benign):,} clean BENIGN training flows...")
    iso = IsolationForest(n_estimators=100, contamination=0.03, random_state=42, n_jobs=-1)
    iso.fit(X_train_benign)

    # Calibrate Isolation Forest score
    benign_scores = iso.score_samples(X_train_benign)
    min_b = float(np.percentile(benign_scores, 1))
    max_b = float(np.percentile(benign_scores, 99))

    # Evaluate RF alone
    y_pred_rf = rf.predict(X_test_scaled)
    acc_rf = accuracy_score(y_test, y_pred_rf)
    print(f"\n[EVALUATION - RANDOM FOREST ALONE]")
    print(f"Accuracy: {acc_rf * 100:.4f}%")
    print(classification_report(y_test, y_pred_rf, zero_division=0))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred_rf))

    # Evaluate Ensemble
    rf_prob = rf.predict_proba(X_test_scaled)[:, 1]
    iso_raw = iso.score_samples(X_test_scaled)
    iso_prob = np.clip((max_b - iso_raw) / (max_b - min_b), 0.0, 1.0)
    ensemble_score = 0.6 * rf_prob + 0.4 * iso_prob
    ensemble_pred = (ensemble_score >= 0.5).astype(int)

    acc_ens = accuracy_score(y_test, ensemble_pred)
    print(f"\n[EVALUATION - HYBRID ENSEMBLE (0.6 RF + 0.4 IF, T=0.5)]")
    print(f"Accuracy: {acc_ens * 100:.4f}%")
    print(classification_report(y_test, ensemble_pred, zero_division=0))
    print("Confusion Matrix:\n", confusion_matrix(y_test, ensemble_pred))

    # Save models
    os.makedirs("models", exist_ok=True)
    joblib.dump(scaler, "models/scaler.joblib")
    joblib.dump(rf, "models/supervised_rf.joblib")
    joblib.dump(iso, "models/unsupervised_iso.joblib")

    # Optional SHAP
    try:
        import shap
        explainer = shap.TreeExplainer(rf)
        joblib.dump(explainer, "models/shap_explainer.joblib")
        print("[INFO] SHAP explainer saved.")
    except Exception as e:
        print(f"[INFO] Skipping SHAP explainer ({e}).")

    print(f"\n[INFO] Models successfully saved to ./models/")
    print(f"[INFO] Scaler and models trained on {len(FEATURE_KEYS)} canonical features.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='NIDS Corrected Model Trainer')
    parser.add_argument('--csv', default='data/CICIDS2017_subset.csv', help='Path to dataset CSV')
    args = parser.parse_args()
    main(args.csv)
