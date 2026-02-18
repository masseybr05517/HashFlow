#!/usr/bin/env python3
"""
Combine bidirectional flows from CSV rows and train a binary classifier.

Row format (per unidirectional flow):
[label, src_ip, src_port, dst_ip, dst_port, proto, ts1, ts2, ..., "", ps1, ps2, ...]
- The "" is a blank separator column between timestamps and packet sizes.

Goal:
Using the first 5 packets across BOTH directions (global time order),
predict whether the bidirectional flow will reach >= 40 packets total.
"""

import argparse
import glob
import os
import ipaddress
import math
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple
import csv

import numpy as np
import pandas as pd

from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    average_precision_score,
    roc_auc_score,
    precision_recall_fscore_support,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
import joblib

# -----------------------------
# Helpers: canonical key & parsing
# -----------------------------

Endpoint = Tuple[str, int]
FlowKey = Tuple[str, int, str, int, str]  # (A_ip, A_port, B_ip, B_port, proto)


def canonical_flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str) -> FlowKey:
    a: Endpoint = (src_ip, int(src_port))
    b: Endpoint = (dst_ip, int(dst_port))
    if a <= b:
        A, B = a, b
    else:
        A, B = b, a
    return (A[0], A[1], B[0], B[1], str(proto))

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(str(s).strip())
        return True
    except Exception:
        return False


def _to_float(x) -> Optional[float]:
    """Convert CSV cell to float, returning None if blank/NaN/unparseable."""
    if x is None:
        return None
    if isinstance(x, float) and math.isnan(x):
        return None
    s = str(x).strip()
    if s == "" or s.lower() == "nan":
        return None
    try:
        return float(s)
    except ValueError:
        return None


def parse_row_to_events(row: List, ts_start_guess: int = 6):
    if len(row) < 10:
        return None

    # Find where the src_ip actually starts (handles 1-label or 2-label files)
    ip_idx = None
    for i in range(min(10, len(row))):  # IP should be early; scan first 10 cells
        if is_ip(row[i]):
            ip_idx = i
            break
    if ip_idx is None:
        return None

    # Now parse 5-tuple relative to that position
    src_ip = str(row[ip_idx]).strip()
    src_port = row[ip_idx + 1]
    dst_ip = str(row[ip_idx + 2]).strip()
    dst_port = row[ip_idx + 3]
    proto = str(row[ip_idx + 4]).strip()

    # validate ports
    try:
        src_port = int(str(src_port).strip())
        dst_port = int(str(dst_port).strip())
    except ValueError:
        return None

    key = canonical_flow_key(src_ip, src_port, dst_ip, dst_port, proto)

    # timestamps start right after proto
    ts_start_idx = ip_idx + 5

    # Find blank separator column between timestamps and sizes.
    # We scan from ts_start_idx onward for the first truly blank cell.
    blank_idx = None
    for i in range(ts_start_idx, len(row)):
        v = row[i]
        # treat "", None, NaN as blank separator
        if v is None:
            blank_idx = i
            break
        if isinstance(v, float) and math.isnan(v):
            blank_idx = i
            break
        if isinstance(v, str) and v.strip() == "":
            blank_idx = i
            break

    if blank_idx is None:
        # No blank separator found -> cannot split
        return None

    ts_cells = row[ts_start_idx:blank_idx]
    ps_cells = row[blank_idx + 1 :]

    timestamps = [t for t in (_to_float(x) for x in ts_cells) if t is not None]
    sizes = [s for s in (_to_float(x) for x in ps_cells) if s is not None]

    # Must be same length or at least alignable
    n = min(len(timestamps), len(sizes))
    if n == 0:
        return None

    timestamps = timestamps[:n]
    sizes = sizes[:n]

    events = list(zip(timestamps, sizes))
    return key, events


# -----------------------------
# Feature extraction
# -----------------------------

def features_from_firstN(events_sorted, N):
    if len(events_sorted) < N:
        return None

    firstN = events_sorted[:N]
    t = np.array([x[0] for x in firstN], dtype=float)
    s = np.array([x[1] for x in firstN], dtype=float)

    dt = np.diff(t)
    span = t[-1] - t[0]

    feats = {}

    # raw sizes
    for i in range(N):
        feats[f"s{i+1}"] = float(s[i])

    # interarrival times
    for i in range(N - 1):
        feats[f"dt{i+2}"] = float(dt[i])

    # aggregate size stats
    feats["mean_size"] = float(np.mean(s))
    feats["std_size"] = float(np.std(s))
    feats["min_size"] = float(np.min(s))
    feats["max_size"] = float(np.max(s))
    feats["sum_size"] = float(np.sum(s))

    # aggregate timing stats
    feats["mean_dt"] = float(np.mean(dt))
    feats["std_dt"] = float(np.std(dt))
    feats["min_dt"] = float(np.min(dt))
    feats["max_dt"] = float(np.max(dt))
    feats[f"span_{N}"] = float(span)

    eps = 1e-9
    feats[f"pps_{N}"] = float(N / (span + eps))
    feats[f"bps_{N}"] = float(np.sum(s) / (span + eps))

    return feats



# -----------------------------
# Dataset builder
# -----------------------------

@dataclass
class Example:
    feats: Dict[str, float]
    y: int
    group: str  # e.g., filename


import csv
import os

def build_examples_from_csv(csv_path: str, first_n: int, target_packets: int) -> List[Example]:
    by_key: Dict[FlowKey, List[Tuple[float, float]]] = {}

    with open(csv_path, "r", newline="") as f:
        reader = csv.reader(f)
        for line_no, row in enumerate(reader, start=1):
            try:
                parsed = parse_row_to_events(row)
            except Exception as e:
                print(f"\nERROR in file: {csv_path}")
                print(f"Line number: {line_no}")
                print(f"Exception: {type(e).__name__}: {e}")
                print(f"Row head: {row[:10]}")
                raise  # re-raise so the traceback still happens

            if parsed is None:
                continue

            key, events = parsed
            by_key.setdefault(key, []).extend(events)

    examples: List[Example] = []
    group = os.path.basename(csv_path)

    for key, events in by_key.items():
        events_sorted = sorted(events, key=lambda x: x[0])
        y = 1 if len(events_sorted) >= target_packets else 0

        feats = features_from_firstN(events_sorted, first_n)
        if feats is None:
            continue

        examples.append(Example(feats=feats, y=y, group=group))

    return examples



def build_dataset(csv_glob: str, first_n: int, target_packets: int) -> Tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    """
    Returns:
      X_df: dataframe of features
      y: labels
      groups: group ids (e.g., file) for splitting
    """
    all_paths = sorted(glob.glob(csv_glob, recursive=True))

    paths = [
        p for p in all_paths
        if not (
            p.endswith("labeled.csv") or
            p.endswith("with_domain_name.csv")
        )
    ]
    if not paths:
        raise FileNotFoundError(f"No CSVs matched: {csv_glob}")

    all_examples: List[Example] = []
    for p in paths:
        all_examples.extend(build_examples_from_csv(p, first_n, target_packets))

    if not all_examples:
        raise RuntimeError("No examples built. Check parsing or CSV format.")

    X_df = pd.DataFrame([ex.feats for ex in all_examples]).fillna(0.0)
    y = np.array([ex.y for ex in all_examples], dtype=int)
    groups = np.array([ex.group for ex in all_examples], dtype=object)
    return X_df, y, groups


# -----------------------------
# Train / evaluate
# -----------------------------

def evaluate_model(name: str, model, X_train, y_train, X_test, y_test) -> None:
    model.fit(X_train, y_train)

    # probabilities for AUC metrics
    if hasattr(model, "predict_proba"):
        p = model.predict_proba(X_test)[:, 1]
    else:
        # fall back to decision_function if needed
        p = model.decision_function(X_test)
        # normalize to 0..1-ish (not perfect, but keeps code robust)
        p = (p - p.min()) / (p.max() - p.min() + 1e-12)

    y_pred = (p >= 0.5).astype(int)

    pr_auc = average_precision_score(y_test, p)
    roc_auc = roc_auc_score(y_test, p) if len(np.unique(y_test)) > 1 else float("nan")
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="binary", zero_division=0
    )

    pos_rate = float(np.mean(y_test))

    print(f"\n=== {name} ===")
    print(f"Test positive rate: {pos_rate:.4f}")
    print(f"PR-AUC:  {pr_auc:.4f}")
    print(f"ROC-AUC: {roc_auc:.4f}")
    print(f"Precision@0.5: {precision:.4f}")
    print(f"Recall@0.5:    {recall:.4f}")
    print(f"F1@0.5:        {f1:.4f}")
    return model

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv_glob", required=True, help='e.g. "data/*labeled*.csv"')
    ap.add_argument("--test_size", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--first_n", type=int, default=5)
    ap.add_argument("--target_packets", type=int, default=40,
                help="Label threshold: positive if total packets in bidirectional flow >= this value (default: 40)")


    args = ap.parse_args()
    FIRST_N_PACKETS = args.first_n
    X_df, y, groups = build_dataset(args.csv_glob, args.first_n, args.target_packets)

    # --- ADD THIS: save feature order ---
    feature_names = list(X_df.columns)
    joblib.dump(feature_names, "feature_names.joblib")
    print("Saved feature names to feature_names.joblib")
    # -----------------------------------

    splitter = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=args.seed)
    train_idx, test_idx = next(splitter.split(X_df, y, groups=groups))
    train_files = sorted(set(groups[train_idx]))
    test_files = sorted(set(groups[test_idx]))

    print("\n=== Files in TRAIN set ===")
    for f in train_files:
        print(f)

    print("\n=== Files in TEST set ===")
    for f in test_files:
        print(f)
    import shutil

    dest_dir = "test_split_data"
    os.makedirs(dest_dir, exist_ok=True)

    for csv_name in test_files:
        base = os.path.splitext(csv_name)[0]

        # Search for matching PCAP under training_data
        for root, _, files in os.walk("training_data"):
            pcap_name = base + ".pcap"
            if pcap_name in files:
                src_path = os.path.join(root, pcap_name)
                shutil.copy2(src_path, dest_dir)
                print(f"Copied {src_path}")
                break
        else:
            print(f"Missing PCAP for {csv_name}")


    X_train = X_df.iloc[train_idx].values
    y_train = y[train_idx]
    X_test = X_df.iloc[test_idx].values
    y_test = y[test_idx]

    lr = Pipeline([
        ("scaler", StandardScaler(with_mean=True, with_std=True)),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced"))
    ])

    rf = RandomForestClassifier(
        n_estimators=400,
        max_depth=None,
        min_samples_leaf=2,
        n_jobs=-1,
        class_weight="balanced_subsample",
        random_state=args.seed,
    )

    print(f"Built dataset: {len(X_df)} examples, {X_df.shape[1]} features")
    print(f"Train: {len(train_idx)}  Test: {len(test_idx)}")

    lr_trained = evaluate_model("LogisticRegression(balanced)", lr, X_train, y_train, X_test, y_test)
    rf_trained = evaluate_model("RandomForest(balanced_subsample)", rf, X_train, y_train, X_test, y_test)

    # --- SAVE MODEL WITH N IN FILENAME ---
    rf_model_path = f"randforest_first{FIRST_N_PACKETS}_predicting{args.target_packets}packets.joblib"

    joblib.dump(rf_trained, rf_model_path)
    print(f"Saved model to {rf_model_path}")

    # --- SAVE METADATA ---
    metadata = {
        "first_N_packets": FIRST_N_PACKETS,
        "target_packets": args.target_packets
    }

    joblib.dump(metadata, f"metadata_first{FIRST_N_PACKETS}.joblib")
    print(f"Saved metadata to metadata_first{FIRST_N_PACKETS}.joblib")


if __name__ == "__main__":
    main()