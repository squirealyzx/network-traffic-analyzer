import pytest

from datetime import datetime

from src.analyzer import (
    calculate_dashboard_statistics,
    calculate_statistics,
    export_records_to_csv,
    filter_records,
)


@pytest.fixture
def records():
    return [
        {
            "src_ip": "192.0.2.1", "dst_ip": "203.0.113.1",
            "protocol": "TCP", "packets": 100, "bytes": 1000,
        },
        {
            "src_ip": "192.0.2.1", "dst_ip": "203.0.113.2",
            "protocol": "udp", "packets": 50, "bytes": 500,
        },
        {
            "src_ip": "198.51.100.2", "dst_ip": "203.0.113.1",
            "protocol": "ICMP", "packets": 25, "bytes": 250,
        },
    ]


def test_calculate_statistics_summarizes_records(records):
    result = calculate_statistics(records)

    assert result == {
        "total_records": 3,
        "total_packets": 175,
        "total_bytes": 1750,
        "tcp_records": 1,
        "udp_records": 1,
        "most_active_source_ip": "192.0.2.1",
        "most_active_source_packets": 150,
    }


def test_calculate_statistics_handles_empty_input():
    assert calculate_statistics([]) == {
        "total_records": 0,
        "total_packets": 0,
        "total_bytes": 0,
        "tcp_records": 0,
        "udp_records": 0,
        "most_active_source_ip": None,
        "most_active_source_packets": 0,
    }


def test_dashboard_statistics_calculate_network_kpis(records):
    result = calculate_dashboard_statistics(records)

    assert result["total_packets"] == 175
    assert result["total_bytes"] == 1750
    assert result["average_packet_size"] == 10
    assert result["unique_source_ips"] == 2
    assert result["unique_destination_ips"] == 2
    assert result["unique_ip_addresses"] == 4
    assert result["protocol_packet_counts"] == {"TCP": 100, "UDP": 50, "ICMP": 25}


def test_filter_records_combines_protocol_ip_port_and_search(records):
    records[1]["src_port"] = 53000

    filtered = filter_records(
        records,
        protocols=["udp"],
        source_ips=["192.0.2.1"],
        ports=[53000],
        search_query="192.0.2.1",
    )

    assert len(filtered) == 1
    assert filtered[0]["protocol"] == "udp"


def test_filter_records_can_filter_by_packet_size_and_time():
    records = [
        {
            "timestamp": "2026-11-18T10:00:00Z",
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.2",
            "protocol": "TCP",
            "packets": 2,
            "bytes": 200,
        },
        {
            "timestamp": "2026-11-18T11:00:00Z",
            "src_ip": "192.0.2.2",
            "dst_ip": "198.51.100.3",
            "protocol": "UDP",
            "packets": 1,
            "bytes": 50,
        },
    ]

    filtered = filter_records(
        records,
        packet_size_range=(90, 110),
        time_range=(datetime(2026, 11, 18, 9), datetime(2026, 11, 18, 10, 30)),
    )

    assert len(filtered) == 1
    assert filtered[0]["src_ip"] == "192.0.2.1"


def test_filter_records_returns_empty_for_empty_input():
    assert filter_records([]) == []


def test_export_records_to_csv_handles_rows_and_empty_data(records):
    csv_text = export_records_to_csv(records)

    assert csv_text.startswith("src_ip,dst_ip,protocol,packets,bytes")
    assert "192.0.2.1" in csv_text
    assert export_records_to_csv([]) == "timestamp,src_ip,dst_ip,protocol,packets,bytes\n"
