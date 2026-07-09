#!/usr/bin/env python3
"""
Convert CESNET-style flow CSV rows into synthetic PCAPs.

Supports:
- IPv4
- IPv6
- TCP
- UDP

Important assumptions:
- This creates synthetic PCAPs, not original traffic reconstruction.
- PPI layout is assumed to be:
    PPI[0] = inter-packet times in milliseconds
    PPI[1] = directions, where +1 is SRC -> DST and -1 is DST -> SRC
    PPI[2] = transport payload sizes
    PPI[3] = TCP PSH flags, if present
- SRC_PORT is not present in the CESNET row, so this script generates one.
- The generated SRC port is constant within a flow.
- The generated SRC port is made as unique as possible within each output PCAP.
- For TCP:
    first packet from SRC direction is SYN
    first packet from DST direction is SYN+ACK
    final packet from SRC direction is FIN+ACK
    final packet from DST direction is FIN+ACK
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, PcapWriter


EPHEMERAL_MIN = 49152
EPHEMERAL_MAX = 65535
EPHEMERAL_COUNT = EPHEMERAL_MAX - EPHEMERAL_MIN + 1


@dataclass
class FlowState:
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    ip_version: int

    client_seq: int
    server_seq: int
    client_mac: str
    server_mac: str
    ip_id: int = 1


class SourcePortAllocator:
    def __init__(self) -> None:
        self.used_ports: set[int] = set()
        self.flow_to_port: Dict[str, int] = {}

    def allocate(self, flow_key: str) -> int:
        if flow_key in self.flow_to_port:
            return self.flow_to_port[flow_key]

        start = EPHEMERAL_MIN + (stable_int(flow_key) % EPHEMERAL_COUNT)

        for offset in range(EPHEMERAL_COUNT):
            port = EPHEMERAL_MIN + ((start - EPHEMERAL_MIN + offset) % EPHEMERAL_COUNT)
            if port not in self.used_ports:
                self.used_ports.add(port)
                self.flow_to_port[flow_key] = port
                return port

        port = start
        self.flow_to_port[flow_key] = port
        return port


def stable_int(text: str, nbytes: int = 8) -> int:
    digest = hashlib.blake2b(text.encode("utf-8"), digest_size=nbytes).digest()
    return int.from_bytes(digest, byteorder="big", signed=False)


def stable_u32(text: str) -> int:
    return stable_int(text, nbytes=4) & 0xFFFFFFFF


def mac_from_text(text: str) -> str:
    """
    Make a deterministic locally-administered unicast MAC address.
    """
    h = hashlib.blake2b(text.encode("utf-8"), digest_size=5).digest()
    return "02:" + ":".join(f"{b:02x}" for b in h)


def parse_time(value: str) -> float:
    value = value.strip()
    dt = datetime.fromisoformat(value)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.timestamp()


def sniff_delimiter(path: Path) -> str:
    with path.open("r", errors="replace") as f:
        sample = f.read(8192)

    try:
        dialect = csv.Sniffer().sniff(sample, delimiters="\t,;")
        return dialect.delimiter
    except csv.Error:
        return ","


def parse_boolish(value) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "t", "yes", "y"}


def parse_int(value, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except Exception:
        return default


def parse_ppi(value: str) -> Tuple[List[float], List[int], List[int], List[int]]:
    ppi = ast.literal_eval(value)

    if not isinstance(ppi, list) or len(ppi) < 3:
        raise ValueError(f"Bad PPI value: {value[:120]}")

    ipt_ms = [float(x) for x in ppi[0]]
    directions = [int(x) for x in ppi[1]]
    payload_sizes = [max(0, int(x)) for x in ppi[2]]

    if len(ppi) >= 4:
        push_flags = [int(x) for x in ppi[3]]
    else:
        push_flags = [0] * len(payload_sizes)

    n = min(len(ipt_ms), len(directions), len(payload_sizes), len(push_flags))

    return ipt_ms[:n], directions[:n], payload_sizes[:n], push_flags[:n]


def make_flow_key(row: Dict[str, str]) -> str:
    return "|".join(
        [
            str(row.get("ID", "")).strip(),
            str(row.get("SRC_IP", "")).strip(),
            str(row.get("DST_IP", "")).strip(),
            str(row.get("DST_PORT", "")).strip(),
            str(row.get("PROTOCOL", "")).strip(),
            str(row.get("TIME_FIRST", "")).strip(),
        ]
    )


def get_ip_version(src_ip: str, dst_ip: str) -> int:
    """
    Return 4 or 6.

    Reject mixed IPv4/IPv6 rows.
    """
    src_obj = ipaddress.ip_address(src_ip)
    dst_obj = ipaddress.ip_address(dst_ip)

    if src_obj.version != dst_obj.version:
        raise ValueError(f"Mixed IP versions are not supported: {src_ip} -> {dst_ip}")

    return src_obj.version


def build_flow_state(row: Dict[str, str], port_allocator: SourcePortAllocator) -> FlowState:
    flow_key = make_flow_key(row)

    src_ip = row["SRC_IP"].strip()
    dst_ip = row["DST_IP"].strip()

    ip_version = get_ip_version(src_ip, dst_ip)

    protocol = parse_int(row.get("PROTOCOL", "0"))
    dst_port = parse_int(row.get("DST_PORT", "0"))

    if not (0 < dst_port <= 65535):
        if protocol == 6:
            dst_port = 443
        elif protocol == 17:
            dst_port = 53
        else:
            dst_port = 0

    src_port = port_allocator.allocate(flow_key)

    return FlowState(
        flow_key=flow_key,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        ip_version=ip_version,
        client_seq=stable_u32(flow_key + "|client_seq"),
        server_seq=stable_u32(flow_key + "|server_seq"),
        client_mac=mac_from_text(flow_key + "|client_mac"),
        server_mac=mac_from_text(flow_key + "|server_mac"),
        ip_id=1 + (stable_u32(flow_key + "|ip_id") % 60000),
    )


def payload_bytes(flow_key: str, direction: int, size: int) -> bytes:
    if size <= 0:
        return b""

    seed = hashlib.blake2b(
        f"{flow_key}|{direction}|payload".encode("utf-8"),
        digest_size=32,
    ).digest()

    repeats = (size // len(seed)) + 1
    return (seed * repeats)[:size]


def make_network_layer(state: FlowState, direction: int):
    """
    Create either an IPv4 or IPv6 layer depending on the flow.

    direction:
        +1 means SRC -> DST
        -1 means DST -> SRC
    """
    if direction == 1:
        src = state.src_ip
        dst = state.dst_ip
    else:
        src = state.dst_ip
        dst = state.src_ip

    if state.ip_version == 4:
        layer = IP(src=src, dst=dst, id=state.ip_id, ttl=64)
        state.ip_id = (state.ip_id + 1) % 65536
        return layer

    if state.ip_version == 6:
        return IPv6(src=src, dst=dst, hlim=64)

    raise ValueError(f"Unsupported IP version: {state.ip_version}")


def make_ether_layer(state: FlowState, direction: int) -> Ether:
    if direction == 1:
        return Ether(src=state.client_mac, dst=state.server_mac)
    return Ether(src=state.server_mac, dst=state.client_mac)


def make_tcp_packet(
    state: FlowState,
    direction: int,
    flags: str,
    payload_len: int,
    timestamp: float,
):
    if direction == 1:
        sport = state.src_port
        dport = state.dst_port
        seq = state.client_seq
        ack = state.server_seq
    else:
        sport = state.dst_port
        dport = state.src_port
        seq = state.server_seq
        ack = state.client_seq

    tcp = TCP(
        sport=sport,
        dport=dport,
        flags=flags,
        seq=seq,
        ack=ack,
        window=8192,
    )

    pkt = make_ether_layer(state, direction) / make_network_layer(state, direction) / tcp

    if payload_len > 0:
        pkt = pkt / Raw(load=payload_bytes(state.flow_key, direction, payload_len))

    pkt.time = timestamp

    seq_advance = payload_len

    if "S" in flags:
        seq_advance += 1

    if "F" in flags:
        seq_advance += 1

    if direction == 1:
        state.client_seq = (state.client_seq + seq_advance) & 0xFFFFFFFF
    else:
        state.server_seq = (state.server_seq + seq_advance) & 0xFFFFFFFF

    return pkt


def make_udp_packet(
    state: FlowState,
    direction: int,
    payload_len: int,
    timestamp: float,
):
    if direction == 1:
        sport = state.src_port
        dport = state.dst_port
    else:
        sport = state.dst_port
        dport = state.src_port

    udp = UDP(sport=sport, dport=dport)

    pkt = make_ether_layer(state, direction) / make_network_layer(state, direction) / udp

    if payload_len > 0:
        pkt = pkt / Raw(load=payload_bytes(state.flow_key, direction, payload_len))

    pkt.time = timestamp
    return pkt


def generate_packets_for_row(
    row: Dict[str, str],
    port_allocator: SourcePortAllocator,
    handshake_gap_seconds: float = 0.001,
    teardown_gap_seconds: float = 0.001,
    respect_rst: bool = False,
):
    state = build_flow_state(row, port_allocator)

    ipt_ms, directions, payload_sizes, push_flags = parse_ppi(row["PPI"])

    t0 = parse_time(row["TIME_FIRST"])

    if state.protocol == 6:
        # TCP synthetic handshake:
        # SRC -> DST: SYN
        # DST -> SRC: SYN+ACK
        # SRC -> DST: ACK
        yield make_tcp_packet(
            state,
            direction=1,
            flags="S",
            payload_len=0,
            timestamp=t0,
        )

        yield make_tcp_packet(
            state,
            direction=-1,
            flags="SA",
            payload_len=0,
            timestamp=t0 + handshake_gap_seconds,
        )

        yield make_tcp_packet(
            state,
            direction=1,
            flags="A",
            payload_len=0,
            timestamp=t0 + 2 * handshake_gap_seconds,
        )

        data_base_time = t0 + 3 * handshake_gap_seconds
        current_time = data_base_time

        for ipt, direction, size, psh in zip(ipt_ms, directions, payload_sizes, push_flags):
            current_time += ipt / 1000.0

            if direction not in {1, -1}:
                continue

            flags = "PA" if psh else "A"

            yield make_tcp_packet(
                state,
                direction=direction,
                flags=flags,
                payload_len=size,
                timestamp=current_time,
            )

        flag_rst = parse_boolish(row.get("FLAG_RST")) or parse_boolish(row.get("FLAG_RST_REV"))

        if respect_rst and flag_rst:
            yield make_tcp_packet(
                state,
                direction=1,
                flags="RA",
                payload_len=0,
                timestamp=current_time + teardown_gap_seconds,
            )

            yield make_tcp_packet(
                state,
                direction=-1,
                flags="RA",
                payload_len=0,
                timestamp=current_time + 2 * teardown_gap_seconds,
            )

        else:
            # Final packet from each direction has FIN.
            yield make_tcp_packet(
                state,
                direction=1,
                flags="FA",
                payload_len=0,
                timestamp=current_time + teardown_gap_seconds,
            )

            yield make_tcp_packet(
                state,
                direction=-1,
                flags="FA",
                payload_len=0,
                timestamp=current_time + 2 * teardown_gap_seconds,
            )

    elif state.protocol == 17:
        current_time = t0

        for ipt, direction, size in zip(ipt_ms, directions, payload_sizes):
            current_time += ipt / 1000.0

            if direction not in {1, -1}:
                continue

            yield make_udp_packet(
                state,
                direction=direction,
                payload_len=size,
                timestamp=current_time,
            )

    else:
        return


def read_rows(path: Path) -> Iterable[Dict[str, str]]:
    delimiter = sniff_delimiter(path)

    with path.open("r", newline="", errors="replace") as f:
        reader = csv.DictReader(f, delimiter=delimiter)

        for row in reader:
            if not row:
                continue

            if "PPI" not in row or not row.get("PPI"):
                continue

            if "SRC_IP" not in row or "DST_IP" not in row:
                continue

            yield row


def convert_file(
    input_path: Path,
    output_path: Path,
    sort_packets: bool = True,
    respect_rst: bool = False,
) -> Tuple[int, int]:
    port_allocator = SourcePortAllocator()

    flows_written = 0
    packets_written = 0

    if sort_packets:
        all_packets = []

        for row in read_rows(input_path):
            try:
                row_packets = list(
                    generate_packets_for_row(
                        row,
                        port_allocator=port_allocator,
                        respect_rst=respect_rst,
                    )
                )
            except Exception as e:
                print(f"[WARN] Skipping row ID={row.get('ID', '<unknown>')}: {e}")
                continue

            if row_packets:
                flows_written += 1
                all_packets.extend(row_packets)

        all_packets.sort(key=lambda pkt: float(pkt.time))

        writer = PcapWriter(str(output_path), linktype=1, sync=True)

        try:
            for pkt in all_packets:
                writer.write(pkt)
                packets_written += 1
        finally:
            writer.close()

    else:
        writer = PcapWriter(str(output_path), linktype=1, sync=True)

        try:
            for row in read_rows(input_path):
                try:
                    row_packets = list(
                        generate_packets_for_row(
                            row,
                            port_allocator=port_allocator,
                            respect_rst=respect_rst,
                        )
                    )
                except Exception as e:
                    print(f"[WARN] Skipping row ID={row.get('ID', '<unknown>')}: {e}")
                    continue

                if row_packets:
                    flows_written += 1

                for pkt in row_packets:
                    writer.write(pkt)
                    packets_written += 1
        finally:
            writer.close()

    return flows_written, packets_written


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert CESNET-style CSV flow rows into synthetic IPv4/IPv6 PCAP files."
    )

    parser.add_argument(
        "inputs",
        nargs="+",
        help="Input CESNET CSV files.",
    )

    parser.add_argument(
        "--out-dir",
        default="synthetic_pcaps",
        help="Directory where output PCAPs will be written.",
    )

    parser.add_argument(
        "--no-sort",
        action="store_true",
        help=(
            "Do not globally sort packets by timestamp. "
            "This uses less memory but assumes rows are already chronological."
        ),
    )

    parser.add_argument(
        "--respect-rst",
        action="store_true",
        help=(
            "If a row has FLAG_RST or FLAG_RST_REV, end TCP flows with RST+ACK "
            "instead of forcing FIN+ACK."
        ),
    )

    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for input_name in args.inputs:
        input_path = Path(input_name)
        output_path = out_dir / f"{input_path.stem}.pcap"

        flows, packets = convert_file(
            input_path=input_path,
            output_path=output_path,
            sort_packets=not args.no_sort,
            respect_rst=args.respect_rst,
        )

        print(f"[OK] {input_path} -> {output_path}")
        print(f"     flows written:   {flows}")
        print(f"     packets written: {packets}")


if __name__ == "__main__":
    main()