# -*- coding: utf-8 -*-
"""
feature_extraction.py - Canonical Feature Extraction Module for AI-NIDS

Converts raw flow telemetry dictionaries or packets into numerical feature vectors
aligned strictly with the trained machine learning models.
"""

import math
import numpy as np
import pandas as pd

# -------------------------------------------------------------------
# CANONICAL 14-FEATURE SCHEMA
# -------------------------------------------------------------------
# Strictly defines the 14 genuine flow statistical features present in the dataset.
# The non-existent 'Protocol' column has been removed from ML features.
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

# Backward compatibility alias
FEATURE_KEYS = CANONICAL_FEATURES

# Protocol map for network/UI display purposes only (not fed into the 14-feature ML model)
PROTO_MAP = {'tcp': 0, 'udp': 1, 'icmp': 2, 'others': 3}


def validate_flow_dict(row: dict, strict: bool = False):
    """
    Validate an incoming flow dictionary against the canonical feature schema.

    Args:
        row (dict): Raw network flow data.
        strict (bool): If True, missing or non-finite features raise ValueError.

    Returns:
        dict: Cleaned and validated feature dictionary.
    """
    if not isinstance(row, dict):
        raise TypeError(f"Expected flow record to be a dictionary, got {type(row).__name__}")

    missing_keys = [k for k in CANONICAL_FEATURES if k not in row]
    if missing_keys and strict:
        raise ValueError(f"Missing required canonical flow features: {missing_keys}")

    cleaned = {}
    for key in CANONICAL_FEATURES:
        val = row.get(key, 0.0)
        try:
            num = float(val)
            if math.isnan(num) or math.isinf(num):
                if strict:
                    raise ValueError(f"Feature '{key}' contains non-finite value: {val}")
                num = 0.0
        except (ValueError, TypeError):
            if strict:
                raise ValueError(f"Feature '{key}' has non-numeric value: {val}")
            num = 0.0
        cleaned[key] = num

    return cleaned


def row_to_vector(row: dict, strict: bool = False):
    """
    Convert a flow dictionary to a numpy vector for model prediction.

    Args:
        row (dict): Flow data containing canonical feature keys.
        strict (bool): If True, strictly raises errors on missing or invalid features.

    Returns:
        np.ndarray: Feature vector of shape (1, 14) in canonical order.
    """
    cleaned_dict = validate_flow_dict(row, strict=strict)
    vec = [cleaned_dict[k] for k in CANONICAL_FEATURES]
    return np.array(vec, dtype=np.float64).reshape(1, -1)


def row_to_dataframe(row: dict, strict: bool = False):
    """
    Convert a flow dictionary directly to an explicitly named DataFrame.

    Args:
        row (dict): Flow data containing canonical feature keys.
        strict (bool): If True, strictly raises errors on missing or invalid features.

    Returns:
        pd.DataFrame: 1-row DataFrame with columns matching CANONICAL_FEATURES.
    """
    cleaned_dict = validate_flow_dict(row, strict=strict)
    return pd.DataFrame([cleaned_dict], columns=CANONICAL_FEATURES)
