from analyzer import calculate_statistics
from data_loader import load_network_traffic
from detector import detect_anomalies


def main():
    records = load_network_traffic()
    statistics = calculate_statistics(records)
    anomaly_results = detect_anomalies(records)

    print("Network Traffic Statistics")
    print("--------------------------")
    print(f"Total records: {statistics['total_records']}")
    print(f"Total packets: {statistics['total_packets']}")
    print(f"Total bytes: {statistics['total_bytes']}")
    print(f"TCP records: {statistics['tcp_records']}")
    print(f"UDP records: {statistics['udp_records']}")

    active_ip = statistics["most_active_source_ip"]
    if active_ip is None:
        print("Most active source IP: no records")
    else:
        active_packets = statistics["most_active_source_packets"]
        print(f"Most active source IP: {active_ip} ({active_packets} packets)")

    print("\nAnomaly Detection")
    print("-----------------")
    suspicious_ips = [result for result in anomaly_results if result["suspicious"]]

    if not suspicious_ips:
        print("No anomalies detected.")
    else:
        for result in suspicious_ips:
            thresholds = ", ".join(result["exceeded_thresholds"])
            print(
                f"Suspicious IP: {result['src_ip']} | "
                f"Packets: {result['total_packets']} | "
                f"Bytes: {result['total_bytes']} | "
                f"Exceeded thresholds: {thresholds}"
            )


if __name__ == "__main__":
    main()
