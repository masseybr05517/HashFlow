#!/usr/bin/env python3
"""
Convert CESNET-style flow CSV/TSV rows into synthetic PCAPs.

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
from typing import Dict, Iterable, List, Optional, Tuple

from scapy.all import Ether, IP, TCP, UDP, Raw, PcapWriter


# Use IANA dynamic/private port range.
# This gives 16,384 possible generated source ports per PCAP.
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

    client_seq: int
    server_seq: int
    client_mac: str
    server_mac: str
    ip_id: int = 1


class SourcePortAllocator:
    """
    Deterministically allocate a mostly-unique generated source port per flow.

    Within a single output PCAP, this allocator avoids reusing the same source
    port until the dynamic port range is exhausted. If you have more than 16,384
    flows in one PCAP, source port reuse is unavoidable because TCP/UDP ports
    are 16-bit.

    Even if a source port repeats later, the 5-tuple can still remain unique
    because SRC_IP, DST_IP, DST_PORT, and PROTOCOL may differ.
    """

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

        # Port space exhausted. Reuse deterministically.
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

    First byte 0x02 means locally administered and unicast.
    """
    h = hashlib.blake2b(text.encode("utf-8"), digest_size=5).digest()
    return "02:" + ":".join(f"{b:02x}" for b in h)


def parse_time(value: str) -> float:
    """
    Parse CESNET ISO time into POSIX seconds.

    CESNET values look like:
        2022-01-10T22:00:00
        2022-01-10T22:00:01.111462

    If no timezone is present, treat as UTC for PCAP timestamps.
    """
    value = value.strip()
    dt = datetime.fromisoformat(value)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.timestamp()


def sniff_delimiter(path: Path) -> str:
    """
    Try to detect CSV vs TSV.

    Your pasted sample is tab-separated. If the file is comma-separated, the PPI
    column must be properly quoted because it contains commas.
    """
    sample = path.read_text(errors="replace")[:8192]

    try:
        dialect = csv.Sniffer().sniff(sample, delimiters="\t,;")
        return dialect.delimiter
    except csv.Error:
        # CESNET examples like yours are often TSV-like.
        return "\t"


def parse_boolish(value: Optional[str]) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "t", "yes", "y"}


def parse_int(value: str, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except Exception:
        return default


def parse_ppi(value: str) -> Tuple[List[float], List[int], List[int], List[int]]:
    """
    Return:
        ipt_ms, directions, payload_sizes, push_flags
    """
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
    """
    Use ID when available because it should be unique per CESNET flow.

    Include 5-tuple-ish fields too so that if IDs collide across files, the
    generated details are still reasonably stable.
    """
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


def valid_ipv4(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except Exception:
        return False


def build_flow_state(row: Dict[str, str], port_allocator: SourcePortAllocator) -> FlowState:
    flow_key = make_flow_key(row)

    src_ip = row["SRC_IP"].strip()
    dst_ip = row["DST_IP"].strip()

    if not valid_ipv4(src_ip) or not valid_ipv4(dst_ip):
        raise ValueError(f"Only IPv4 is handled by this script. Bad flow: {flow_key}")

    protocol = parse_int(row.get("PROTOCOL", "0"))
    dst_port = parse_int(row.get("DST_PORT", "0"))

    if not (0 < dst_port <= 65535):
        dst_port = 443 if protocol == 6 else 53

    src_port = port_allocator.allocate(flow_key)

    return FlowState(
        flow_key=flow_key,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        client_seq=stable_u32(flow_key + "|client_seq"),
        server_seq=stable_u32(flow_key + "|server_seq"),
        client_mac=mac_from_text(flow_key + "|client_mac"),
        server_mac=mac_from_text(flow_key + "|server_mac"),
        ip_id=1 + (stable_u32(flow_key + "|ip_id") % 60000),
    )


def payload_bytes(flow_key: str, direction: int, size: int) -> bytes:
    """
    Deterministic fake payload.

    Avoid using random bytes because deterministic output is helpful for
    debugging and repeatability.
    """
    if size <= 0:
        return b""

    seed = hashlib.blake2b(
        f"{flow_key}|{direction}|payload".encode("utf-8"),
        digest_size=32,
    ).digest()

    repeats = (size // len(seed)) + 1
    return (seed * repeats)[:size]


def make_ip_layer(state: FlowState, direction: int) -> IP:
    if direction == 1:
        src = state.src_ip
        dst = state.dst_ip
    else:
        src = state.dst_ip
        dst = state.src_ip

    ip = IP(src=src, dst=dst, id=state.ip_id, ttl=64)
    state.ip_id = (state.ip_id + 1) % 65536
    return ip


def make_ether_layer(state: FlowState, direction: int) -> Ether:
    if direction == 1:
        return Ether(src=state.client_mac, dst=state.server_mac)
    else:
        return Ether(src=state.server_mac, dst=state.client_mac)


def make_tcp_packet(
    state: FlowState,
    direction: int,
    flags: str,
    payload_len: int,
    timestamp: float,
):
    """
    direction:
        +1 means SRC -> DST
        -1 means DST -> SRC
    """

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

    tcp = TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=8192)

    pkt = make_ether_layer(state, direction) / make_ip_layer(state, direction) / tcp

    if payload_len > 0:
        pkt = pkt / Raw(load=payload_bytes(state.flow_key, direction, payload_len))

    pkt.time = timestamp

    seq_advance = payload_len
    if "S" in flags:
        seq_advance += 1
    if "F" in flags:
        seq_advance += 1

    # RST does not consume sequence space in the same way for our purposes here.
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

    pkt = make_ether_layer(state, direction) / make_ip_layer(state, direction) / udp

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
    """
    Yield synthetic packets for one CESNET flow row.
    """

    state = build_flow_state(row, port_allocator)

    ipt_ms, directions, payload_sizes, push_flags = parse_ppi(row["PPI"])

    t0 = parse_time(row["TIME_FIRST"])

    if state.protocol == 6:
        # TCP opening.
        #
        # First packet from SRC direction has SYN.
        # First packet from DST direction has SYN+ACK.
        yield make_tcp_packet(state, direction=1, flags="S", payload_len=0, timestamp=t0)

        yield make_tcp_packet(
            state,
            direction=-1,
            flags="SA",
            payload_len=0,
            timestamp=t0 + handshake_gap_seconds,
        )

        # Client ACK completes the synthetic handshake.
        # This is not the first packet from SRC direction; the first was SYN.
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
            # Optional: if the original row says RST happened, end with RST instead of FIN.
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
            # TCP teardown.
            #
            # Final packet from SRC direction has FIN.
            # Final packet from DST direction has FIN.
            #
            # We intentionally do not add a final pure ACK after the server FIN,
            # because then the final SRC-direction packet would not have FIN,
            # violating your requested invariant.
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
        # UDP has no SYN/FIN.
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
        # Skip unsupported protocols.
        return


def read_rows(path: Path) -> Iterable[Dict[str, str]]:
    delimiter = sniff_delimiter(path)

    with path.open("r", newline="", errors="replace") as f:
        reader = csv.DictReader(f, delimiter=delimiter)

        for row in reader:
            # Skip empty/broken rows.
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
    """
    Returns:
        flows_written, packets_written
    """

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
        # Streaming mode uses less memory, but assumes the input rows are already
        # in roughly chronological order.
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
        description="Convert CESNET-style CSV/TSV flow rows into synthetic PCAP files."
    )

    parser.add_argument(
        "inputs",
        nargs="+",
        help="Input CESNET CSV/TSV files.",
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