"""Statistics, filters, and export helpers for network traffic records."""

from collections import defaultdict
from datetime import datetime
from typing import Mapping, Sequence

import pandas as pd


TrafficRecord = Mapping[str, object]


def calculate_statistics(records: Sequence[TrafficRecord]) -> dict[str, object]:
    """Return the original summary statistics used by the command-line app."""
    packet_totals_by_source: defaultdict[str, int] = defaultdict(int)
    total_packets = 0
    total_bytes = 0
    tcp_records = 0
    udp_records = 0

    for record in records:
        packets = int(record["packets"])
        total_packets += packets
        total_bytes += int(record["bytes"])
        packet_totals_by_source[str(record["src_ip"])] += packets

        protocol = str(record["protocol"]).upper()
        if protocol == "TCP":
            tcp_records += 1
        elif protocol == "UDP":
            udp_records += 1

    most_active_source_ip = None
    if packet_totals_by_source:
        most_active_source_ip = max(
            packet_totals_by_source, key=packet_totals_by_source.get
        )

    return {
        "total_records": len(records),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "tcp_records": tcp_records,
        "udp_records": udp_records,
        "most_active_source_ip": most_active_source_ip,
        "most_active_source_packets": (
            packet_totals_by_source[most_active_source_ip]
            if most_active_source_ip is not None
            else 0
        ),
    }


def prepare_traffic_dataframe(records: Sequence[TrafficRecord]) -> pd.DataFrame:
    """Create a normalized analysis table and derive packet-size estimates.

    When a dataset contains flow totals instead of individual packets, the
    packet-size value is estimated as bytes divided by packets for each row.
    """
    frame = pd.DataFrame(records).copy()
    for column in ("timestamp", "src_ip", "dst_ip", "protocol", "packets", "bytes"):
        if column not in frame:
            frame[column] = pd.Series(dtype="object")

    for column in ("src_port", "dst_port", "packet_size"):
        if column not in frame:
            frame[column] = pd.NA

    frame["packets"] = pd.to_numeric(frame["packets"], errors="coerce").fillna(0)
    frame["bytes"] = pd.to_numeric(frame["bytes"], errors="coerce").fillna(0)
    frame["src_port"] = pd.to_numeric(frame["src_port"], errors="coerce")
    frame["dst_port"] = pd.to_numeric(frame["dst_port"], errors="coerce")
    frame["packet_size"] = pd.to_numeric(frame["packet_size"], errors="coerce")
    frame["protocol"] = (
        frame["protocol"].fillna("UNKNOWN").astype(str).str.strip().str.upper()
    )
    frame["_timestamp_utc"] = pd.to_datetime(
        frame["timestamp"], errors="coerce", utc=True
    )

    estimated_size = frame["bytes"].div(frame["packets"].where(frame["packets"] > 0))
    frame["packet_size_bytes"] = frame["packet_size"].fillna(estimated_size)
    frame["_record_index"] = range(len(frame))
    return frame


def calculate_dashboard_statistics(records: Sequence[TrafficRecord]) -> dict[str, object]:
    """Calculate dashboard KPIs and grouped counts from the selected records."""
    frame = prepare_traffic_dataframe(records)
    protocol_packets = frame.groupby("protocol")["packets"].sum().to_dict()
    protocol_bytes = frame.groupby("protocol")["bytes"].sum().to_dict()

    unique_ips = set(frame["src_ip"].dropna()) | set(frame["dst_ip"].dropna())
    total_packets = int(frame["packets"].sum())
    total_bytes = int(frame["bytes"].sum())

    return {
        "total_records": len(frame),
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "average_packet_size": total_bytes / total_packets if total_packets else 0.0,
        "unique_source_ips": int(frame["src_ip"].nunique()),
        "unique_destination_ips": int(frame["dst_ip"].nunique()),
        "unique_ip_addresses": len(unique_ips),
        "protocol_packet_counts": {
            protocol: int(count) for protocol, count in protocol_packets.items()
        },
        "protocol_byte_totals": {
            protocol: int(count) for protocol, count in protocol_bytes.items()
        },
    }


def filter_records(
    records: Sequence[TrafficRecord],
    *,
    protocols: Sequence[str] | None = None,
    source_ips: Sequence[str] | None = None,
    destination_ips: Sequence[str] | None = None,
    ports: Sequence[int] | None = None,
    packet_size_range: tuple[float, float] | None = None,
    time_range: tuple[datetime, datetime] | None = None,
    search_query: str = "",
) -> list[dict[str, object]]:
    """Apply optional filters and return matching original records."""
    frame = prepare_traffic_dataframe(records)
    selected = pd.Series(True, index=frame.index)

    if protocols:
        normalized_protocols = {value.upper() for value in protocols}
        selected &= frame["protocol"].isin(normalized_protocols)
    if source_ips:
        selected &= frame["src_ip"].isin(source_ips)
    if destination_ips:
        selected &= frame["dst_ip"].isin(destination_ips)
    if ports:
        selected &= frame["src_port"].isin(ports) | frame["dst_port"].isin(ports)
    if packet_size_range is not None:
        minimum_size, maximum_size = packet_size_range
        selected &= frame["packet_size_bytes"].between(minimum_size, maximum_size)
    if time_range is not None:
        start_time, end_time = time_range
        start_utc = pd.to_datetime(start_time, utc=True)
        end_utc = pd.to_datetime(end_time, utc=True)
        selected &= frame["_timestamp_utc"].between(start_utc, end_utc).fillna(False)
    if search_query.strip():
        query = search_query.strip().casefold()
        searchable_columns = [
            column
            for column in ("timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port")
            if column in frame
        ]
        matches = pd.Series(False, index=frame.index)
        for column in searchable_columns:
            matches |= frame[column].astype("string").str.casefold().str.contains(
                query, regex=False, na=False
            )
        selected &= matches

    selected_indices = frame.loc[selected, "_record_index"].astype(int).tolist()
    return [dict(records[index]) for index in selected_indices]


def export_records_to_csv(records: Sequence[TrafficRecord]) -> str:
    """Serialize selected records as CSV, including a useful header when empty."""
    if records:
        return pd.DataFrame(records).to_csv(index=False)
    return "timestamp,src_ip,dst_ip,protocol,packets,bytes\n"
