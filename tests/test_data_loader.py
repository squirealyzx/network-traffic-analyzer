from io import StringIO
from pathlib import Path

import pytest

from src import data_loader


def use_csv_fixture(monkeypatch, tmp_path, contents):
    csv_path = tmp_path / "network_traffic.csv"
    csv_path.write_text(contents, encoding="utf-8")
    original_open = Path.open

    def open_fixture(path, *args, **kwargs):
        if path.name == "network_traffic.csv":
            return original_open(csv_path, *args, **kwargs)
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(data_loader, "__file__", str(tmp_path / "src" / "data_loader.py"))
    monkeypatch.setattr(Path, "open", open_fixture)
    return csv_path


def test_load_network_traffic_converts_numeric_columns():
    records = data_loader.load_network_traffic()

    assert records
    assert isinstance(records[0]["packets"], int)
    assert isinstance(records[0]["bytes"], int)


def test_load_network_traffic_rejects_missing_columns(tmp_path, monkeypatch):
    use_csv_fixture(monkeypatch, tmp_path, "timestamp,src_ip\nnow,192.0.2.1\n")

    with pytest.raises(ValueError, match="missing required column"):
        data_loader.load_network_traffic()


def test_load_network_traffic_rejects_non_integer_values(tmp_path, monkeypatch):
    use_csv_fixture(
        monkeypatch,
        tmp_path,
        "timestamp,src_ip,dst_ip,protocol,packets,bytes\n"
        "now,192.0.2.1,198.51.100.2,TCP,many,100\n",
    )

    with pytest.raises(ValueError, match="'packets' must be an integer"):
        data_loader.load_network_traffic()


def test_parse_network_traffic_csv_accepts_optional_port_columns():
    csv_text = (
        "timestamp,src_ip,dst_ip,protocol,packets,bytes,src_port,dst_port\n"
        "2026-11-18 10:00:00,192.0.2.1,198.51.100.2,tcp,2,120,45000,443\n"
    )

    records = data_loader.parse_network_traffic_csv(StringIO(csv_text))

    assert records[0]["protocol"] == "TCP"
    assert records[0]["packets"] == 2
    assert records[0]["src_port"] == 45000
    assert records[0]["dst_port"] == 443


def test_parse_network_traffic_csv_accepts_header_only_dataset():
    csv_text = "timestamp,src_ip,dst_ip,protocol,packets,bytes\n"

    assert data_loader.parse_network_traffic_csv(StringIO(csv_text)) == []


def test_parse_network_traffic_csv_rejects_empty_file():
    with pytest.raises(ValueError, match="empty or has no header"):
        data_loader.parse_network_traffic_csv(StringIO(""))


def test_parse_network_traffic_csv_rejects_negative_counters():
    csv_text = (
        "timestamp,src_ip,dst_ip,protocol,packets,bytes\n"
        "now,192.0.2.1,198.51.100.2,TCP,1,-5\n"
    )

    with pytest.raises(ValueError, match="cannot be negative"):
        data_loader.parse_network_traffic_csv(StringIO(csv_text))


def test_parse_network_traffic_csv_rejects_invalid_optional_port():
    csv_text = (
        "timestamp,src_ip,dst_ip,protocol,packets,bytes,src_port\n"
        "now,192.0.2.1,198.51.100.2,TCP,1,5,70000\n"
    )

    with pytest.raises(ValueError, match="between 0 and 65535"):
        data_loader.parse_network_traffic_csv(StringIO(csv_text))
