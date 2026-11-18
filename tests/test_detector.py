from src.detector import detect_anomalies


def test_detect_anomalies_aggregates_by_source_and_applies_strict_thresholds():
    records = [
        {"src_ip": "192.0.2.1", "packets": 300, "bytes": 400},
        {"src_ip": "192.0.2.1", "packets": 200, "bytes": 600},
        {"src_ip": "198.51.100.2", "packets": 100, "bytes": 1000},
    ]

    assert detect_anomalies(records, packet_threshold=500, byte_threshold=1000) == [
        {
            "src_ip": "192.0.2.1",
            "total_packets": 500,
            "total_bytes": 1000,
            "suspicious": False,
            "exceeded_thresholds": [],
            "reasons": [],
            "severity": "Normal",
            "assessment": "No configured threshold was exceeded.",
            "thresholds": {"packets": 500, "bytes": 1000},
        },
        {
            "src_ip": "198.51.100.2",
            "total_packets": 100,
            "total_bytes": 1000,
            "suspicious": False,
            "exceeded_thresholds": [],
            "reasons": [],
            "severity": "Normal",
            "assessment": "No configured threshold was exceeded.",
            "thresholds": {"packets": 500, "bytes": 1000},
        },
    ]


def test_detect_anomalies_reports_each_exceeded_threshold():
    records = [{"src_ip": "192.0.2.1", "packets": 501, "bytes": 1001}]

    result = detect_anomalies(records, packet_threshold=500, byte_threshold=1000)

    assert result[0]["suspicious"] is True
    assert result[0]["exceeded_thresholds"] == ["packets", "bytes"]
    assert result[0]["severity"] == "High"
    assert result[0]["reasons"] == [
        "501 packets exceed the 500 packet threshold",
        "1,001 bytes exceed the 1,000 byte threshold",
    ]
    assert "not a confirmation" in result[0]["assessment"]


def test_detect_anomalies_handles_empty_input():
    assert detect_anomalies([]) == []


def test_detect_anomalies_explains_a_single_trigger_as_moderate():
    result = detect_anomalies(
        [{"src_ip": "192.0.2.1", "packets": 501, "bytes": 20}],
        packet_threshold=500,
        byte_threshold=100,
    )[0]

    assert result["severity"] == "Moderate"
    assert result["exceeded_thresholds"] == ["packets"]
    assert result["thresholds"] == {"packets": 500, "bytes": 100}


def test_detect_anomalies_rejects_negative_thresholds():
    import pytest

    with pytest.raises(ValueError, match="cannot be negative"):
        detect_anomalies([], packet_threshold=-1)
