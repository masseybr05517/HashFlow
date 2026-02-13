#!/usr/bin/env python3
"""
predict_flows_from_pcap_first8_27.py

PCAP -> flow aggregation (bidirectional, canonical 5-tuple) -> first-8 feature vector (27 dims)
-> sklearn/joblib model predict_proba -> print top results.

This matches the feature extraction in:
  build_feature_entries_first8() from your C file:
    - s[0..7]  = abs(ip_len) for first 8 packets in arrival order
    - dt[0..6] = t[i+1]-t[i] for first 8 packets
    - stats over s (n=8): mean, std(pop), min, max, sum
    - stats over dt (n=7): mean, std(pop), min, max, span
    - pps_8 = 8/span, bps_8 = sum_size/span (with eps)

Usage:
  python3 predict_flows_from_pcap_first8_27.py <pcap> <model.joblib> [max_flows] [topk]

Example:
  python3 predict_flows_from_pcap_first8_27.py newtrace.pcap randforest_first8_predicting40packets.joblib 0 50
"""

import sys
import socket
from dataclasses import dataclass, field
from typing import Dict, Tuple, List, Optional

import dpkt
import numpy as np
import joblib

FlowKey = Tuple[str, str, int, int, int]  # (ip1, ip2, port1, port2, proto)


def ip_to_str(ip_bytes: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET, ip_bytes)


def canonicalize_flow(src_ip: str, dst_ip: str, sport: int, dport: int, proto: int) -> FlowKey:
    """
    Canonical key so both directions map to the same flow.
    This mirrors your C make_key logic conceptually: order by (ip, then port).
    """
    a = (src_ip, dst_ip, sport, dport, proto)
    b = (dst_ip, src_ip, dport, sport, proto)
    return a if a <= b else b


@dataclass
class FlowState:
    t_first: float
    t_last: float
    first_ts: List[float] = field(default_factory=list)     # store first 8 packet timestamps (absolute seconds)
    first_size: List[float] = field(default_factory=list)   # store first 8 abs(ip_len)
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
    Produce the exact 27-dim feature vector used by your C tl2cgen model.
    Returns None if the flow has fewer than 8 packets observed.
    """
    if len(state.first_ts) < 8 or len(state.first_size) < 8:
        return None

    t = state.first_ts[:8]
    s = state.first_size[:8]

    dt = [t[i + 1] - t[i] for i in range(7)]
    span = t[7] - t[0]
    eps = 1e-9

    mean_size, std_size, min_size, max_size, sum_size = stats_1d_pop(s)
    mean_dt, std_dt, min_dt, max_dt, _sum_dt = stats_1d_pop(dt)

    pps_8 = 8.0 / (span + eps)
    bps_8 = sum_size / (span + eps)

    feats: List[float] = []
    feats.extend([float(x) for x in s])   # 8
    feats.extend([float(x) for x in dt])  # 7

    feats.extend([mean_size, std_size, min_size, max_size, sum_size])  # 5
    feats.extend([mean_dt, std_dt, min_dt, max_dt, span])              # 5
    feats.extend([pps_8, bps_8])                                       # 2

    if len(feats) != 27:
        raise RuntimeError(f"Internal error: expected 27 features, got {len(feats)}")
    return np.array(feats, dtype=np.float32)


def load_model(model_path: str):
    return joblib.load(model_path)


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <pcap_file> <model.joblib> [max_flows] [topk]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    model_path = sys.argv[2]
    max_flows = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    topk = int(sys.argv[4]) if len(sys.argv) > 4 else 50

    model = load_model(model_path)

    flows: Dict[FlowKey, FlowState] = {}

    with open(pcap_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                proto = ip.p

                # Only TCP/UDP
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
                        # ignore NEW flows after cap
                        continue
                    st = FlowState(t_first=ts, t_last=ts)
                    flows[key] = st

                st.t_last = ts

                # Match C: ip_len = ntohs(ip->ip_len)
                # dpkt sets ip.len from header (already host order int)
                ip_len = int(ip.len) if int(ip.len) > 0 else int(len(ip))

                st.pkts += 1
                st.bytes += ip_len

                # Collect only first 8 packets in arrival order
                if len(st.first_ts) < 8:
                    st.first_ts.append(float(ts))
                    st.first_size.append(float(abs(ip_len)))

            except Exception:
                continue

    # Build feature matrix for flows with >= 8 packets
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

    # Sanity check
    n_expected = getattr(model, "n_features_in_", None)
    if n_expected is not None and X.shape[1] != int(n_expected):
        raise ValueError(f"Feature mismatch: X has {X.shape[1]} features, model expects {n_expected}")

    # Predict probability of positive class
    if not hasattr(model, "predict_proba"):
        raise TypeError("Loaded model does not support predict_proba().")

    proba = model.predict_proba(X)
    if proba.ndim != 2 or proba.shape[1] < 2:
        raise ValueError(f"Unexpected predict_proba shape: {proba.shape}")

    # Print top-k by P(class=1)
    scored = sorted(zip(row_keys, proba[:, 1]), key=lambda x: x[1], reverse=True)[:topk]
    for (ip1, ip2, port1, port2, proto), p in scored:
        st = flows[(ip1, ip2, port1, port2, proto)]
        print(
            f"{ip1}:{port1} -> {ip2}:{port2} proto={proto}  "
            f"p(class=1)={p:.4f}  pkts={st.pkts} bytes={st.bytes}"
        )


if __name__ == "__main__":
    main()
