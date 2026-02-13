#!/usr/bin/env python3
"""
predict_flows_from_pcap_first8_27_eval.py

PCAP -> flow aggregation (canonical 5-tuple) -> first-8 feature vector (27 dims)
-> sklearn/joblib model predict_proba -> precision/recall/F1 + confusion matrix
-> optional threshold sweep + print top-k flows by p(class=1)

Feature extraction matches your C code build_feature_entries_first8():
  - s[0..7]  = abs(ip_len) for first 8 packets in arrival order
  - dt[0..6] = t[i+1]-t[i] for first 8 packets
  - stats over s (n=8): mean, std(pop), min, max, sum
  - stats over dt (n=7): mean, std(pop), min, max, span
  - pps_8 = 8/span, bps_8 = sum_size/span (with eps)

Ground truth label (class 1):
  pkts >= FLOW_TARGET (default 40)

Usage:
  python3 predict_flows_from_pcap_first8_27_eval.py <pcap> <model.joblib> [max_flows] [topk] [threshold]

Examples:
  python3 predict_flows_from_pcap_first8_27_eval.py newtrace.pcap randforest_first8_predicting40packets.joblib
  python3 predict_flows_from_pcap_first8_27_eval.py newtrace.pcap randforest_first8_predicting40packets.joblib 0 50 0.5
"""

import sys
import socket
from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Optional

import dpkt
import numpy as np
import joblib


# ----------------------------
# Config (matches your C intent)
# ----------------------------
FIRST_N = 8
FLOW_TARGET = 40  # class 1 means "reaches 40 packets"


FlowKey = Tuple[str, str, int, int, int]  # (ip1, ip2, port1, port2, proto)


def ip_to_str(ip_bytes: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET, ip_bytes)


def canonicalize_flow(src_ip: str, dst_ip: str, sport: int, dport: int, proto: int) -> FlowKey:
    """Canonical key so both directions map to same flow."""
    a = (src_ip, dst_ip, sport, dport, proto)
    b = (dst_ip, src_ip, dport, sport, proto)
    return a if a <= b else b


@dataclass
class FlowState:
    t_first: float
    t_last: float
    first_ts: List[float] = field(default_factory=list)     # first 8 packet timestamps (absolute seconds)
    first_size: List[float] = field(default_factory=list)   # first 8 abs(ip_len)
    pkts: int = 0
    bytes: int = 0


def stats_1d_pop(a: List[float]) -> Tuple[float, float, float, float, float]:
    """
    Returns (mean, std(population), min, max, sum) exactly like your C stats_1d:
      var = sum((x-mean)^2)/n  (population variance)
    """
    n = len(a)
    sm = float(sum(a))
    mn = float(min(a))
    mx = float(max(a))
    mean = sm / float(n)

    var = 0.0
    for x in a:
        d = float(x) - mean
        var += d * d
    var /= float(n)

    std = float(np.sqrt(var)) if var > 0.0 else 0.0
    return mean, std, mn, mx, sm


def extract_features_first8_27(state: FlowState) -> Optional[np.ndarray]:
    """
    Produce the exact 27-dim feature vector used by your tl2cgen model.
    Returns None if the flow has fewer than 8 packets observed.
    """
    if len(state.first_ts) < FIRST_N or len(state.first_size) < FIRST_N:
        return None

    t = state.first_ts[:FIRST_N]
    s = state.first_size[:FIRST_N]

    dt = [t[i + 1] - t[i] for i in range(FIRST_N - 1)]  # 7 values
    span = t[FIRST_N - 1] - t[0]
    eps = 1e-9

    mean_size, std_size, min_size, max_size, sum_size = stats_1d_pop(s)
    mean_dt, std_dt, min_dt, max_dt, _sum_dt = stats_1d_pop(dt)

    pps_8 = float(FIRST_N) / (span + eps)
    bps_8 = sum_size / (span + eps)

    feats: List[float] = []
    feats.extend([float(x) for x in s])                 # 8
    feats.extend([float(x) for x in dt])                # 7
    feats.extend([mean_size, std_size, min_size, max_size, sum_size])  # 5
    feats.extend([mean_dt, std_dt, min_dt, max_dt, span])              # 5
    feats.extend([pps_8, bps_8])                        # 2

    if len(feats) != 27:
        raise RuntimeError(f"Internal error: expected 27 features, got {len(feats)}")
    return np.array(feats, dtype=np.float32)


def load_model(model_path: str):
    return joblib.load(model_path)


def safe_div(n: float, d: float) -> float:
    return n / d if d != 0 else 0.0


def precision_recall_f1(y_true: np.ndarray, y_pred: np.ndarray) -> Tuple[float, float, float, int, int, int, int]:
    """
    Compute precision/recall/F1 + confusion counts without requiring sklearn.metrics.
    Returns: (precision, recall, f1, tn, fp, fn, tp)
    """
    y_true = y_true.astype(int)
    y_pred = y_pred.astype(int)

    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1, tn, fp, fn, tp


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <pcap_file> <model.joblib> [max_flows] [topk] [threshold]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    model_path = sys.argv[2]
    max_flows = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    topk = int(sys.argv[4]) if len(sys.argv) > 4 else 50
    threshold = float(sys.argv[5]) if len(sys.argv) > 5 else 0.50

    model = load_model(model_path)

    flows: Dict[FlowKey, FlowState] = {}

    # ----------------------------
    # Parse PCAP and build flows
    # ----------------------------
    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                proto = ip.p

                if proto not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                    continue

                src_ip = ip_to_str(ip.src)
                dst_ip = ip_to_str(ip.dst)

                if proto == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    sport, dport = int(tcp.sport), int(tcp.dport)
                else:
                    udp = ip.data
                    sport, dport = int(udp.sport), int(udp.dport)

                key = canonicalize_flow(src_ip, dst_ip, sport, dport, int(proto))

                st = flows.get(key)
                if st is None:
                    if max_flows and len(flows) >= max_flows:
                        continue
                    st = FlowState(t_first=float(ts), t_last=float(ts))
                    flows[key] = st

                st.t_last = float(ts)

                # Match C: ip_len = ntohs(ip->ip_len)
                # dpkt's ip.len is already an int from the header
                ip_len = int(ip.len) if int(ip.len) > 0 else int(len(ip))

                st.pkts += 1
                st.bytes += ip_len

                # Collect only first 8 packets in arrival order (direction ignored for ML)
                if len(st.first_ts) < FIRST_N:
                    st.first_ts.append(float(ts))
                    st.first_size.append(float(abs(ip_len)))

            except Exception:
                continue

    # ----------------------------
    # Build X for flows with >= 8 packets
    # ----------------------------
    row_keys: List[FlowKey] = []
    rows: List[np.ndarray] = []

    for k, st in flows.items():
        fv = extract_features_first8_27(st)
        if fv is None:
            continue
        rows.append(fv)
        row_keys.append(k)

    if not rows:
        print("No flows with >= 8 packets found; nothing to score.")
        sys.exit(0)

    X = np.stack(rows, axis=0)

    # Sanity check with sklearn model's expected dimension (if present)
    n_expected = getattr(model, "n_features_in_", None)
    if n_expected is not None and X.shape[1] != int(n_expected):
        raise ValueError(f"Feature mismatch: X has {X.shape[1]} features, model expects {n_expected}")

    if not hasattr(model, "predict_proba"):
        raise TypeError("Loaded model does not support predict_proba().")

    proba = model.predict_proba(X)
    if proba.ndim != 2 or proba.shape[1] < 2:
        raise ValueError(f"Unexpected predict_proba shape: {proba.shape}")

    p1 = proba[:, 1]

    # ----------------------------
    # Evaluation: precision/recall/F1 at chosen threshold
    # ----------------------------
    y_true = np.array([1 if flows[k].pkts >= FLOW_TARGET else 0 for k in row_keys], dtype=int)
    y_pred = (p1 >= threshold).astype(int)

    precision, recall, f1, tn, fp, fn, tp = precision_recall_f1(y_true, y_pred)

    print("\n=== Evaluation (flow-level) ===")
    print(f"PCAP: {pcap_path}")
    print(f"Model: {model_path}")
    print(f"Class-1 ground truth: pkts >= {FLOW_TARGET}")
    print(f"Num scored flows (>= {FIRST_N} pkts): {len(row_keys)}")
    print(f"Threshold: {threshold:.3f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1-score : {f1:.4f}")
    print("Confusion matrix counts:")
    print(f"  TN={tn}  FP={fp}")
    print(f"  FN={fn}  TP={tp}")

    # Optional: threshold sweep
    print("\n=== Threshold sweep ===")
    print("thr    prec    rec     f1     TP   FP   FN   TN")
    for thr in [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]:
        yp = (p1 >= thr).astype(int)
        pr, rc, f1s, tn_, fp_, fn_, tp_ = precision_recall_f1(y_true, yp)
        print(f"{thr:0.2f}  {pr:0.3f}  {rc:0.3f}  {f1s:0.3f}  {tp_:4d} {fp_:4d} {fn_:4d} {tn_:4d}")

    # ----------------------------
    # Print top-k flows by probability (for inspection)
    # ----------------------------
    scored = sorted(zip(row_keys, p1), key=lambda x: x[1], reverse=True)[:topk]

    print(f"\n=== Top {topk} flows by p(class=1) ===")
    for (ip1, ip2, port1, port2, proto), p in scored:
        st = flows[(ip1, ip2, port1, port2, proto)]
        print(
            f"{ip1}:{port1} -> {ip2}:{port2} proto={proto}  "
            f"p(class=1)={p:.4f}  pkts={st.pkts} bytes={st.bytes}"
        )


if __name__ == "__main__":
    main()
