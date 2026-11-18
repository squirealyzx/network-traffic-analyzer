"""Explain simple rule-based unusual-traffic findings."""

from collections.abc import Mapping, Sequence


def detect_anomalies(
    records: Sequence[Mapping[str, object]],
    packet_threshold: int = 500,
    byte_threshold: int = 100000,
) -> list[dict[str, object]]:
    """Flag source IP totals above configured limits; a flag is not an attack verdict."""
    if packet_threshold < 0 or byte_threshold < 0:
        raise ValueError("Anomaly thresholds cannot be negative.")

    # Keep running packet and byte totals for each source IP.
    totals_by_ip: dict[str, dict[str, int]] = {}

    for record in records:
        source_ip = str(record["src_ip"])

        # Start each IP's totals at zero the first time we encounter it.
        if source_ip not in totals_by_ip:
            totals_by_ip[source_ip] = {"total_packets": 0, "total_bytes": 0}

        # Add this record's traffic to its source IP's totals.
        totals_by_ip[source_ip]["total_packets"] += int(record["packets"])
        totals_by_ip[source_ip]["total_bytes"] += int(record["bytes"])

    results = []

    # Check the combined traffic for each IP against both thresholds.
    for source_ip, totals in totals_by_ip.items():
        exceeded_thresholds = []

        if totals["total_packets"] > packet_threshold:
            exceeded_thresholds.append("packets")
        if totals["total_bytes"] > byte_threshold:
            exceeded_thresholds.append("bytes")

        reasons = []
        if "packets" in exceeded_thresholds:
            reasons.append(
                f"{totals['total_packets']:,} packets exceed the {packet_threshold:,} packet threshold"
            )
        if "bytes" in exceeded_thresholds:
            reasons.append(
                f"{totals['total_bytes']:,} bytes exceed the {byte_threshold:,} byte threshold"
            )

        if len(exceeded_thresholds) == 2:
            severity = "High"
        elif exceeded_thresholds:
            severity = "Moderate"
        else:
            severity = "Normal"

        results.append(
            {
                "src_ip": source_ip,
                "total_packets": totals["total_packets"],
                "total_bytes": totals["total_bytes"],
                "suspicious": bool(exceeded_thresholds),
                "exceeded_thresholds": exceeded_thresholds,
                "reasons": reasons,
                "severity": severity,
                "assessment": (
                    "Observed unusual traffic; review in context. This is not a confirmation of malicious activity."
                    if exceeded_thresholds
                    else "No configured threshold was exceeded."
                ),
                "thresholds": {
                    "packets": packet_threshold,
                    "bytes": byte_threshold,
                },
            }
        )

    return results
