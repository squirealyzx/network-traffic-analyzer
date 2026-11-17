from collections import defaultdict


def calculate_statistics(records):
    """Calculate summary statistics from loaded network traffic records."""
    packet_totals_by_source = defaultdict(int)
    total_packets = 0
    total_bytes = 0
    tcp_records = 0
    udp_records = 0

    for record in records:
        total_packets += record["packets"]
        total_bytes += record["bytes"]
        packet_totals_by_source[record["src_ip"]] += record["packets"]

        protocol = record["protocol"].upper()
        if protocol == "TCP":
            tcp_records += 1
        elif protocol == "UDP":
            udp_records += 1

    most_active_source_ip = None
    if packet_totals_by_source:
        most_active_source_ip = max(packet_totals_by_source, key=packet_totals_by_source.get)

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
