def detect_anomalies(records, packet_threshold=500, byte_threshold=100000):
    """Summarize traffic by source IP and flag totals above either threshold."""
    # Keep running packet and byte totals for each source IP.
    totals_by_ip = {}

    for record in records:
        source_ip = record["src_ip"]

        # Start each IP's totals at zero the first time we encounter it.
        if source_ip not in totals_by_ip:
            totals_by_ip[source_ip] = {"total_packets": 0, "total_bytes": 0}

        # Add this record's traffic to its source IP's totals.
        totals_by_ip[source_ip]["total_packets"] += record["packets"]
        totals_by_ip[source_ip]["total_bytes"] += record["bytes"]

    results = []

    # Check the combined traffic for each IP against both thresholds.
    for source_ip, totals in totals_by_ip.items():
        exceeded_thresholds = []

        if totals["total_packets"] > packet_threshold:
            exceeded_thresholds.append("packets")
        if totals["total_bytes"] > byte_threshold:
            exceeded_thresholds.append("bytes")

        results.append(
            {
                "src_ip": source_ip,
                "total_packets": totals["total_packets"],
                "total_bytes": totals["total_bytes"],
                "suspicious": bool(exceeded_thresholds),
                "exceeded_thresholds": exceeded_thresholds,
            }
        )

    return results
