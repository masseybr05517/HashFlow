#!/usr/bin/env python3
import sys
import socket
import dpkt
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, List
import joblib

FlowKey = Tuple[str, str, int, int, int]  # (src_ip, dst_ip, src_port, dst_port, proto)

def ip_to_str(ip_bytes: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET, ip_bytes)

@dataclass
class FlowState:
    t_first: float
    t_last: float
    pkt_lens_fwd: List[int] = field(default_factory=list)
    pkt_lens_rev: List[int] = field(default_factory=list)
    ipt_fwd: List[float] = field(default_factory=list)
    ipt_rev: List[float] = field(default_factory=list)
    bytes_fwd: int = 0
    bytes_rev: int = 0
    pkts_fwd: int = 0
    pkts_rev: int = 0
    last_ts_fwd: Optional[float] = None
    last_ts_rev: Optional[float] = None

def canonicalize_flow(src_ip, dst_ip, sport, dport, proto) -> Tuple[FlowKey, bool]:
    """
    Return (canonical_key, is_fwd)
    Canonical key is ordered so that both directions map to same key.
    is_fwd tells you whether this packet is in the canonical forward direction.
    """
    a = (src_ip, dst_ip, sport, dport, proto)
    b = (dst_ip, src_ip, dport, sport, proto)
    if a <= b:
        return a, True
    else:
        return b, False

def extract_features(state: FlowState, max_pkts: int = 8) -> np.ndarray:
    """
    EXAMPLE features. Replace with YOUR exact training feature order.
    Here we build:
      - duration
      - total bytes, total pkts
      - fwd bytes/pkts, rev bytes/pkts
      - first N fwd lens, first N rev lens (padded)
      - first N fwd ipt,  first N rev ipt  (padded)
    """
    duration = max(0.0, state.t_last - state.t_first)
    total_bytes = state.bytes_fwd + state.bytes_rev
    total_pkts = state.pkts_fwd + state.pkts_rev

    def pad_int(xs):
        xs = xs[:max_pkts]
        return xs + [0] * (max_pkts - len(xs))

    def pad_float(xs):
        xs = xs[:max_pkts]
        return xs + [0.0] * (max_pkts - len(xs))

    feats = []
    feats += [duration, float(total_bytes), float(total_pkts)]
    feats += [float(state.bytes_fwd), float(state.pkts_fwd), float(state.bytes_rev), float(state.pkts_rev)]
    feats += list(map(float, pad_int(state.pkt_lens_fwd)))
    feats += list(map(float, pad_int(state.pkt_lens_rev)))
    feats += pad_float(state.ipt_fwd)
    feats += pad_float(state.ipt_rev)
    return np.array(feats, dtype=np.float32)

def load_model(model_path: str):
    return joblib.load(model_path)

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <pcap_file> <model_path_or_dummy> [max_flows] [max_pkts_per_flow]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    model_path = sys.argv[2]
    max_flows = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    max_pkts_per_flow = int(sys.argv[4]) if len(sys.argv) > 4 else 200

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
                # Only TCP/UDP in this example
                if proto not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                    continue

                src_ip = ip_to_str(ip.src)
                dst_ip = ip_to_str(ip.dst)

                if proto == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    sport, dport = tcp.sport, tcp.dport
                else:
                    udp = ip.data
                    sport, dport = udp.sport, udp.dport

                key, is_fwd = canonicalize_flow(src_ip, dst_ip, sport, dport, proto)

                st = flows.get(key)
                if st is None:
                    if max_flows and len(flows) >= max_flows:
                        continue
                    st = FlowState(t_first=ts, t_last=ts)
                    flows[key] = st

                st.t_last = ts
                plen = len(ip)  # bytes at IP layer; change if you used wire length

                if is_fwd:
                    st.pkts_fwd += 1
                    st.bytes_fwd += plen
                    st.pkt_lens_fwd.append(plen)
                    if st.last_ts_fwd is not None:
                        st.ipt_fwd.append(ts - st.last_ts_fwd)
                    st.last_ts_fwd = ts
                else:
                    st.pkts_rev += 1
                    st.bytes_rev += plen
                    st.pkt_lens_rev.append(plen)
                    if st.last_ts_rev is not None:
                        st.ipt_rev.append(ts - st.last_ts_rev)
                    st.last_ts_rev = ts

                # optional cap
                if (st.pkts_fwd + st.pkts_rev) >= max_pkts_per_flow:
                    pass

            except Exception:
                continue

    # Build feature matrix
    keys = list(flows.keys())
    X = np.stack([extract_features(flows[k]) for k in keys], axis=0)

    # Predict
    proba = model.predict_proba(X)
    # print top results
    for k, p in sorted(zip(keys, proba[:, 1]), key=lambda x: x[1], reverse=True)[:50]:
        src, dst, sport, dport, proto = k
        print(f"{src}:{sport} -> {dst}:{dport} proto={proto}  p(class=1)={p:.4f}  "
              f"pkts={flows[k].pkts_fwd+flows[k].pkts_rev} bytes={flows[k].bytes_fwd+flows[k].bytes_rev}")

if __name__ == "__main__":
    main()