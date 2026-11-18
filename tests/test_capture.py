from datetime import datetime, timezone

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP

from src import capture
from src.analyzer import calculate_statistics
from src.detector import detect_anomalies


@pytest.fixture
def tcp_packet():
    packet = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=43210, dport=443)
    packet.time = datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc).timestamp()
    return packet


def test_extract_tcp_metadata_matches_pipeline_record(tcp_packet):
    record = capture.extract_packet_metadata(tcp_packet)

    assert record == {
        "timestamp": "2026-11-18T10:00:00+00:00",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "protocol": "TCP",
        "packets": 1,
        "bytes": len(tcp_packet),
        "packet_size": len(tcp_packet),
        "src_port": 43210,
        "dst_port": 443,
    }


def test_captured_record_works_with_existing_analysis_functions(tcp_packet):
    record = capture.extract_packet_metadata(tcp_packet)

    assert record is not None
    assert calculate_statistics([record])["total_packets"] == 1
    assert calculate_statistics([record])["total_bytes"] == len(tcp_packet)
    assert detect_anomalies([record])[0]["src_ip"] == "192.0.2.10"


def test_extract_udp_metadata_includes_ports():
    packet = IP(src="192.0.2.11", dst="203.0.113.53") / UDP(sport=53000, dport=53)

    record = capture.extract_packet_metadata(packet)

    assert record is not None
    assert record["protocol"] == "UDP"
    assert record["src_port"] == 53000
    assert record["dst_port"] == 53


def test_extract_icmp_metadata_has_no_ports():
    packet = IP(src="192.0.2.12", dst="198.51.100.1") / ICMP()

    record = capture.extract_packet_metadata(packet)

    assert record is not None
    assert record["protocol"] == "ICMP"
    assert record["src_port"] is None
    assert record["dst_port"] is None


def test_ignores_non_ip_and_unsupported_ip_packets():
    assert capture.extract_packet_metadata(TCP(sport=1, dport=2)) is None
    assert capture.extract_packet_metadata(IP(proto=2)) is None


def test_capture_uses_explicit_interface_and_does_not_store_packets(
    monkeypatch, tcp_packet
):
    seen = {}

    def fake_sniff(**kwargs):
        seen.update(kwargs)
        kwargs["prn"](tcp_packet)

    monkeypatch.setattr(capture, "get_if_list", lambda: ["test-interface"])
    monkeypatch.setattr(capture, "sniff", fake_sniff)

    records = capture.capture_packets(
        "test-interface", duration=2.5, packet_limit=7
    )

    assert records[0]["src_ip"] == "192.0.2.10"
    assert seen["iface"] == "test-interface"
    assert seen["timeout"] == 2.5
    assert seen["count"] == 7
    assert seen["store"] is False


def test_capture_returns_empty_list_if_no_packets_arrive(monkeypatch):
    monkeypatch.setattr(capture, "get_if_list", lambda: ["test-interface"])
    monkeypatch.setattr(capture, "sniff", lambda **kwargs: None)

    assert capture.capture_packets("test-interface") == []


def test_capture_rejects_unknown_interface(monkeypatch):
    monkeypatch.setattr(capture, "get_if_list", lambda: ["known-interface"])

    with pytest.raises(ValueError, match="Unknown interface"):
        capture.capture_packets("missing-interface")


@pytest.mark.parametrize(
    ("duration", "packet_limit"),
    [(0, 10), (-1, 10), (float("inf"), 10), (1, 0), (1, -1), (1, 1.5)],
)
def test_capture_rejects_invalid_limits(monkeypatch, duration, packet_limit):
    monkeypatch.setattr(capture, "get_if_list", lambda: ["test-interface"])

    with pytest.raises(ValueError):
        capture.capture_packets(
            "test-interface", duration=duration, packet_limit=packet_limit
        )


def test_capture_reports_permission_errors(monkeypatch):
    monkeypatch.setattr(capture, "get_if_list", lambda: ["test-interface"])

    def permission_error(**kwargs):
        raise PermissionError("capture is not allowed")

    monkeypatch.setattr(capture, "sniff", permission_error)

    with pytest.raises(capture.PacketCaptureError, match="Permission denied"):
        capture.capture_packets("test-interface")


def test_capture_wraps_other_capture_errors(monkeypatch):
    monkeypatch.setattr(capture, "get_if_list", lambda: ["test-interface"])

    def capture_error(**kwargs):
        raise OSError("capture backend unavailable")

    monkeypatch.setattr(capture, "sniff", capture_error)

    with pytest.raises(capture.PacketCaptureError, match="capture backend unavailable"):
        capture.capture_packets("test-interface")


def test_capture_reports_interface_enumeration_errors(monkeypatch):
    def missing_npcap():
        raise OSError("Npcap is unavailable")

    monkeypatch.setattr(capture, "get_if_list", missing_npcap)

    with pytest.raises(capture.PacketCaptureError, match="Npcap"):
        capture.capture_packets("test-interface")
