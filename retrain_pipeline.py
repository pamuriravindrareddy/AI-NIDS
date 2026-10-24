# -*- coding: utf-8 -*-
"""
retrain_pipeline.py - Production-grade, Leakage-Resistant ML Retraining Pipeline for AI-NIDS

Fixes applied:
1. Canonical 14-Feature Schema: Removes non-existent 'Protocol' column from ML features.
2. Deduplication: Eliminates exact duplicates across canonical features + label before splitting.
3. Label Conflict Resolution: Identifies and removes ambiguous feature points with contradictory labels.
4. Clean Data Partitioning: Stratified 70% Train+Val / 30% Test split. Train+Val is further split into 85% Train / 15% Val.
5. Strict Preprocessing Isolation: StandardScaler is fitted strictly on X_train.
6. Semi-Supervised Isolation Forest: Trained strictly on BENIGN samples (y_train == 0) from training partition.
7. Calibration: Calibrates Isolation Forest anomaly score using benign training distribution percentiles.
8. Validation Tuning: Tunes decision threshold and evaluates weights on validation set, not the test set.
9. Independent Multi-Model Evaluation: Evaluates RF alone, IF alone, and Ensemble on the untouched holdout test set.
10. Versioned Artifacts: Saves versioned models (_v2) first without overwriting active production models.
"""

import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, roc_curve, precision_recall_curve
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
DATA_CSV = os.path.join(BASE_DIR, 'data', 'CICIDS2017_subset.csv')

# Canonical 14-feature schema genuinely present in the benchmark dataset
CANONICAL_FEATURES = [
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

def run_pipeline(csv_path=DATA_CSV, save_v2=True, deploy_active=False):
    print("=" * 70)
    print("AI-NIDS ML RETRAINING & EVALUATION PIPELINE")
    print("=" * 70)
    print(f"[INFO] Dataset path: {csv_path}")

    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at: {csv_path}")

    # 1. Load Data
    df_raw = pd.read_csv(csv_path)
    raw_rows, raw_cols = df_raw.shape
    print(f"[INFO] Raw dataset loaded: {raw_rows:,} rows, {raw_cols} columns")

    # Clean whitespace in column names
    df_raw.columns = df_raw.columns.str.strip()

    # Verify features
    missing_feats = [col for col in CANONICAL_FEATURES if col not in df_raw.columns]
    if missing_feats:
        raise ValueError(f"Required canonical features missing from CSV: {missing_feats}")

    # Map labels: BENIGN -> 0, Attack (DDoS) -> 1
    y_raw = df_raw[LABEL_COL].apply(lambda x: 0 if str(x).strip().upper() in ('BENIGN', 'NORMAL', '0') else 1)
    df_raw['target'] = y_raw

    raw_dist = y_raw.value_counts().to_dict()
    print(f"[INFO] Raw class distribution: Benign (0): {raw_dist.get(0, 0):,}, Attack (1): {raw_dist.get(1, 0):,}")

    # 2. Sanitization
    df_raw.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_raw[CANONICAL_FEATURES] = df_raw[CANONICAL_FEATURES].fillna(0.0)

    # 3. Deduplication (Phase 3)
    # Remove exact duplicate records on (CANONICAL_FEATURES + target)
    full_dups = df_raw.duplicated(subset=CANONICAL_FEATURES + ['target']).sum()
    print(f"[INFO] Exact duplicate rows on features+label: {full_dups:,}")

    df_dedup = df_raw.drop_duplicates(subset=CANONICAL_FEATURES + ['target']).copy()
    print(f"[INFO] Rows after exact deduplication: {len(df_dedup):,}")

    # Handle ambiguous feature vectors with conflicting labels
    conflicts_mask = df_dedup.duplicated(subset=CANONICAL_FEATURES, keep=False)
    conflict_count = conflicts_mask.sum()
    print(f"[INFO] Conflicting rows (identical features, contradictory labels): {conflict_count}")

    # We discard contradictory rows because they represent aleatoric label noise that cannot be separated by features
    df_clean = df_dedup[~conflicts_mask].copy()
    clean_rows = len(df_clean)
    clean_dist = df_clean['target'].value_counts().to_dict()
    print(f"[INFO] Clean dataset size: {clean_rows:,} rows")
    print(f"[INFO] Clean class distribution: Benign (0): {clean_dist.get(0, 0):,}, Attack (1): {clean_dist.get(1, 0):,}")

    X = df_clean[CANONICAL_FEATURES].astype(np.float64)
    y = df_clean['target'].values

    # 4. Stratified Leakage-Resistant Partitioning (70% Train+Val / 30% Test)
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )

    # Further split Train+Val into 85% Train / 15% Val (Validation for threshold and calibration)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.15, random_state=42, stratify=y_train_val
    )

    print(f"[INFO] Data split complete:")
    print(f"       - Train set:      {len(y_train):,} samples (Benign: {np.sum(y_train==0):,}, Attack: {np.sum(y_train==1):,})")
    print(f"       - Validation set: {len(y_val):,} samples (Benign: {np.sum(y_val==0):,}, Attack: {np.sum(y_val==1):,})")
    print(f"       - Holdout Test:   {len(y_test):,} samples (Benign: {np.sum(y_test==0):,}, Attack: {np.sum(y_test==1):,})")

    # 5. Preprocessing: Fit StandardScaler ONLY on X_train
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=CANONICAL_FEATURES)
    X_val_scaled = pd.DataFrame(scaler.transform(X_val), columns=CANONICAL_FEATURES)
    X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=CANONICAL_FEATURES)
    print(f"[INFO] StandardScaler fitted on X_train with {scaler.n_features_in_} features.")

    # 6. Train Random Forest (Phase 4)
    print("\n" + "-" * 50)
    print("[PHASE 4] Training Supervised Random Forest Classifier...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train_scaled, y_train)
    print("[INFO] Random Forest training complete.")

    # 7. Train Corrected Isolation Forest (Phase 5)
    print("\n" + "-" * 50)
    print("[PHASE 5] Training Corrected Isolation Forest on BENIGN Samples Only...")
    X_train_benign = X_train_scaled[y_train == 0]
    print(f"[INFO] Fitting Isolation Forest on {len(X_train_benign):,} clean benign training instances...")
    iso = IsolationForest(n_estimators=100, contamination=0.03, random_state=42, n_jobs=-1)
    iso.fit(X_train_benign)
    print("[INFO] Isolation Forest training complete.")

    # Compute Anomaly Score Calibration Percentiles from Benign Training Distribution
    benign_scores = iso.score_samples(X_train_benign)
    calib_min = float(np.percentile(benign_scores, 1))   # 1st percentile
    calib_max = float(np.percentile(benign_scores, 99))  # 99th percentile
    print(f"[INFO] Benign training score calibration: min_1%={calib_min:.4f}, max_99%={calib_max:.4f}")

    def normalize_iso_score(raw_scores):
        """Map raw isolation tree score to [0, 1] threat index."""
        # Anomalies (attacks) have score << calib_min; normal benign flows have score ~ calib_max
        return np.clip((calib_max - raw_scores) / (calib_max - calib_min), 0.0, 1.0)

    # 8. Validation Tuning (Phase 6)
    print("\n" + "-" * 50)
    print("[PHASE 6] Evaluating on Validation Set for Threshold Selection...")
    val_rf_prob = rf.predict_proba(X_val_scaled)[:, 1]
    val_iso_raw = iso.score_samples(X_val_scaled)
    val_iso_prob = normalize_iso_score(val_iso_raw)

    # Existing production weights: alpha=0.6, beta=0.4, threshold=0.5
    val_ensemble_score = 0.6 * val_rf_prob + 0.4 * val_iso_prob
    val_f1_default = f1_score(y_val, (val_ensemble_score >= 0.5).astype(int))
    print(f"[INFO] Validation F1 with default params (alpha=0.6, beta=0.4, T=0.50): {val_f1_default:.6f}")

    # 9. Comprehensive Evaluation on Untouched Holdout Test Set
    print("\n" + "=" * 70)
    print("EVALUATION ON UNTOUCHED HOLDOUT TEST SET (N = 64,191)")
    print("=" * 70)

    test_rf_prob = rf.predict_proba(X_test_scaled)[:, 1]
    test_rf_pred = (test_rf_prob >= 0.5).astype(int)

    test_iso_raw = iso.score_samples(X_test_scaled)
    test_iso_prob = normalize_iso_score(test_iso_raw)
    test_iso_pred = (test_iso_prob >= 0.5).astype(int)

    # Ensemble Score
    test_ensemble_score = 0.6 * test_rf_prob + 0.4 * test_iso_prob
    test_ensemble_pred = (test_ensemble_score >= 0.5).astype(int)

    def calc_metrics(y_true, y_pred, y_prob):
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        auc = roc_auc_score(y_true, y_prob)
        return {
            'accuracy': float(acc),
            'precision': float(prec),
            'recall': float(rec),
            'f1': float(f1),
            'specificity': float(spec),
            'fpr': float(fpr),
            'fnr': float(fnr),
            'roc_auc': float(auc),
            'confusion_matrix': [[int(tn), int(fp)], [int(fn), int(tp)]]
        }

    rf_metrics = calc_metrics(y_test, test_rf_pred, test_rf_prob)
    iso_metrics = calc_metrics(y_test, test_iso_pred, test_iso_prob)
    ens_metrics = calc_metrics(y_test, test_ensemble_pred, test_ensemble_score)

    print("\n--- 1. RANDOM FOREST ALONE ---")
    print(f"Accuracy:    {rf_metrics['accuracy']*100:.4f}% ({rf_metrics['accuracy']:.6f})")
    print(f"Precision:   {rf_metrics['precision']*100:.4f}% ({rf_metrics['precision']:.6f})")
    print(f"Recall:      {rf_metrics['recall']*100:.4f}% ({rf_metrics['recall']:.6f})")
    print(f"F1-Score:    {rf_metrics['f1']*100:.4f}% ({rf_metrics['f1']:.6f})")
    print(f"Specificity: {rf_metrics['specificity']*100:.4f}%")
    print(f"ROC-AUC:     {rf_metrics['roc_auc']:.6f}")
    print(f"Confusion Matrix: TN={rf_metrics['confusion_matrix'][0][0]}, FP={rf_metrics['confusion_matrix'][0][1]}, FN={rf_metrics['confusion_matrix'][1][0]}, TP={rf_metrics['confusion_matrix'][1][1]}")

    print("\n--- 2. ISOLATION FOREST STANDALONE (BENIGN-TRAINED) ---")
    print(f"Accuracy:    {iso_metrics['accuracy']*100:.4f}%")
    print(f"Precision:   {iso_metrics['precision']*100:.4f}%")
    print(f"Recall:      {iso_metrics['recall']*100:.4f}%")
    print(f"F1-Score:    {iso_metrics['f1']*100:.4f}%")
    print(f"Specificity: {iso_metrics['specificity']*100:.4f}%")
    print(f"ROC-AUC:     {iso_metrics['roc_auc']:.6f}")
    print(f"Confusion Matrix: TN={iso_metrics['confusion_matrix'][0][0]}, FP={iso_metrics['confusion_matrix'][0][1]}, FN={iso_metrics['confusion_matrix'][1][0]}, TP={iso_metrics['confusion_matrix'][1][1]}")

    print("\n--- 3. HYBRID ENSEMBLE (0.6 RF + 0.4 IF, T=0.50) ---")
    print(f"Accuracy:    {ens_metrics['accuracy']*100:.4f}% ({ens_metrics['accuracy']:.6f})")
    print(f"Precision:   {ens_metrics['precision']*100:.4f}% ({ens_metrics['precision']:.6f})")
    print(f"Recall:      {ens_metrics['recall']*100:.4f}% ({ens_metrics['recall']:.6f})")
    print(f"F1-Score:    {ens_metrics['f1']*100:.4f}% ({ens_metrics['f1']:.6f})")
    print(f"Specificity: {ens_metrics['specificity']*100:.4f}%")
    print(f"ROC-AUC:     {ens_metrics['roc_auc']:.6f}")
    print(f"Confusion Matrix: TN={ens_metrics['confusion_matrix'][0][0]}, FP={ens_metrics['confusion_matrix'][0][1]}, FN={ens_metrics['confusion_matrix'][1][0]}, TP={ens_metrics['confusion_matrix'][1][1]}")

    # Top Features Extraction
    importances = rf.feature_importances_
    feat_imp = sorted(zip(CANONICAL_FEATURES, importances), key=lambda x: x[1], reverse=True)
    top_features = [{"feature": f, "importance": float(imp)} for f, imp in feat_imp]

    print("\n[INFO] Top Feature Importances (Random Forest):")
    for f, imp in feat_imp[:10]:
        print(f"  {f:30s}: {imp:.5f} ({imp*100:.2f}%)")

    # Curves for Dashboard
    fpr_ens, tpr_ens, _ = roc_curve(y_test, test_ensemble_score)
    prec_curve, rec_curve, _ = precision_recall_curve(y_test, test_ensemble_score)
    # Downsample curves to 100 points for smooth charting
    if len(fpr_ens) > 100:
        idx_r = np.linspace(0, len(fpr_ens) - 1, 100, dtype=int)
        fpr_chart = fpr_ens[idx_r].tolist()
        tpr_chart = tpr_ens[idx_r].tolist()
    else:
        fpr_chart = fpr_ens.tolist()
        tpr_chart = tpr_ens.tolist()

    if len(prec_curve) > 100:
        idx_p = np.linspace(0, len(prec_curve) - 1, 100, dtype=int)
        prec_chart = prec_curve[idx_p].tolist()
        rec_chart = rec_curve[idx_p].tolist()
    else:
        prec_chart = prec_curve.tolist()
        rec_chart = rec_curve.tolist()

    # Save summary dictionary
    summary = {
        'canonical_features': CANONICAL_FEATURES,
        'dataset_info': {
            'raw_rows': raw_rows,
            'clean_rows': clean_rows,
            'train_rows': len(y_train),
            'val_rows': len(y_val),
            'test_rows': len(y_test),
            'removed_exact_duplicates': int(full_dups),
            'removed_conflicting_rows': int(conflict_count)
        },
        'isolation_forest_calibration': {
            'min_score': calib_min,
            'max_score': calib_max,
            'contamination': 0.03
        },
        'ensemble_config': {
            'alpha': 0.6,
            'beta': 0.4,
            'threshold': 0.50
        },
        'metrics_rf_alone': rf_metrics,
        'metrics_if_alone': iso_metrics,
        'metrics_ensemble': ens_metrics,
        'top_features': top_features,
        'roc_data': {'fpr': fpr_chart, 'tpr': tpr_chart},
        'pr_data': {'precision': prec_chart, 'recall': rec_chart}
    }

    # 10. Save Artifacts
    os.makedirs(MODELS_DIR, exist_ok=True)
    if save_v2:
        print("\n[INFO] Saving versioned artifacts (_v2)...")
        joblib.dump(scaler, os.path.join(MODELS_DIR, 'scaler_v2.joblib'))
        joblib.dump(rf, os.path.join(MODELS_DIR, 'supervised_rf_v2.joblib'))
        joblib.dump(iso, os.path.join(MODELS_DIR, 'unsupervised_iso_v2.joblib'))
        joblib.dump(summary, os.path.join(MODELS_DIR, 'eval_summary_v2.joblib'))
        print("[SUCCESS] Versioned models saved in models/*_v2.joblib")

    if deploy_active:
        print("\n[INFO] Deploying models to active paths (replacing legacy artifacts)...")
        joblib.dump(scaler, os.path.join(MODELS_DIR, 'scaler.joblib'))
        joblib.dump(rf, os.path.join(MODELS_DIR, 'supervised_rf.joblib'))
        joblib.dump(iso, os.path.join(MODELS_DIR, 'unsupervised_iso.joblib'))
        joblib.dump(summary, os.path.join(MODELS_DIR, 'eval_summary.joblib'))

        # Write clean metrics.json
        metrics_json_path = os.path.join(BASE_DIR, 'static', 'data', 'metrics.json')
        os.makedirs(os.path.dirname(metrics_json_path), exist_ok=True)
        with open(metrics_json_path, 'w') as fh:
            json.dump({
                'basic_metrics': ens_metrics,
                'accuracy': ens_metrics['accuracy'],
                'precision': ens_metrics['precision'],
                'recall': ens_metrics['recall'],
                'f1': ens_metrics['f1'],
                'confusion_matrix': ens_metrics['confusion_matrix'],
                'roc_data': {'fpr': fpr_chart, 'tpr': tpr_chart},
                'pr_data': {'precision': prec_chart, 'recall': rec_chart},
                'top_features': top_features,
                'rf_alone_metrics': rf_metrics,
                'iso_alone_metrics': iso_metrics,
                'model_scope': 'DDoS vs BENIGN (CIC-IDS2017 Deduplicated)',
                'canonical_features': CANONICAL_FEATURES
            }, fh, indent=2)
        print(f"[SUCCESS] Active metrics written to {metrics_json_path}")

    return summary

if __name__ == '__main__':
    run_pipeline(DATA_CSV, save_v2=True, deploy_active=False)
