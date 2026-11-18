from src.visualization import (
    ip_activity_figure,
    packet_size_figure,
    port_activity_figure,
    protocol_distribution_figure,
    protocol_volume_figure,
    traffic_over_time_figure,
)


def sample_records():
    return [
        {
            "timestamp": "2026-11-18T10:00:00Z",
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.2",
            "protocol": "TCP",
            "packets": 2,
            "bytes": 200,
            "src_port": 50000,
            "dst_port": 443,
        },
        {
            "timestamp": "2026-11-18T10:01:00Z",
            "src_ip": "192.0.2.2",
            "dst_ip": "198.51.100.3",
            "protocol": "UDP",
            "packets": 1,
            "bytes": 50,
            "src_port": 53000,
            "dst_port": 53,
        },
    ]


def test_protocol_charts_build_from_records():
    records = sample_records()

    assert protocol_distribution_figure(records) is not None
    assert protocol_volume_figure(records) is not None


def test_ip_activity_charts_support_sources_and_destinations():
    records = sample_records()

    assert ip_activity_figure(records, address_column="src_ip") is not None
    assert ip_activity_figure(records, address_column="dst_ip") is not None


def test_time_packet_size_and_port_charts_build_when_data_exists():
    records = sample_records()

    assert traffic_over_time_figure(records) is not None
    assert packet_size_figure(records) is not None
    assert port_activity_figure(records) is not None


def test_charts_return_none_when_optional_data_is_missing():
    records = [
        {
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.2",
            "protocol": "TCP",
            "packets": 1,
            "bytes": 10,
        }
    ]

    assert traffic_over_time_figure(records) is None
    assert port_activity_figure(records) is None


def test_charts_handle_empty_dataset():
    assert protocol_distribution_figure([]) is None
    assert protocol_volume_figure([]) is None
    assert traffic_over_time_figure([]) is None
    assert packet_size_figure([]) is None
