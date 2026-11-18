"""Read and validate network traffic CSV datasets."""

import csv
from pathlib import Path
from typing import NotRequired, TextIO, TypedDict


class TrafficRecord(TypedDict):
    """One normalized CSV record used by the analysis modules."""

    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    packets: int
    bytes: int
    src_port: NotRequired[int | None]
    dst_port: NotRequired[int | None]
    packet_size: NotRequired[int | None]


REQUIRED_COLUMNS = {
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "packets",
    "bytes",
}
OPTIONAL_NUMERIC_COLUMNS = ("src_port", "dst_port", "packet_size")


def parse_network_traffic_csv(csv_file: TextIO) -> list[TrafficRecord]:
    """Parse and validate an open text CSV stream.

    A header-only CSV is a valid empty dataset. Required columns must exist;
    port and exact packet-size columns are optional for older sample files.
    """
    try:
        reader = csv.DictReader(csv_file, strict=True)
        if reader.fieldnames is None:
            raise ValueError("CSV file is empty or has no header row.")

        # Trimming header whitespace makes files exported by spreadsheet tools
        # more forgiving, while still validating the expected column names.
        reader.fieldnames = [name.strip() if name else "" for name in reader.fieldnames]
        missing_columns = REQUIRED_COLUMNS - set(reader.fieldnames)
        if missing_columns:
            names = ", ".join(sorted(missing_columns))
            raise ValueError(f"CSV file is missing required column(s): {names}")

        records: list[TrafficRecord] = []
        for line_number, raw_row in enumerate(reader, start=2):
            if None in raw_row:
                raise ValueError(
                    f"CSV line {line_number} has more values than the header columns."
                )

            row = {
                str(column).strip(): (value.strip() if value is not None else None)
                for column, value in raw_row.items()
                if column is not None
            }

            for column in ("src_ip", "dst_ip", "protocol", "packets", "bytes"):
                if not row.get(column):
                    raise ValueError(
                        f"CSV line {line_number}: '{column}' is missing or empty."
                    )

            record: TrafficRecord = {
                "timestamp": row.get("timestamp") or "",
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "protocol": row["protocol"].upper(),
                "packets": _parse_non_negative_integer(
                    row["packets"], "packets", line_number
                ),
                "bytes": _parse_non_negative_integer(
                    row["bytes"], "bytes", line_number
                ),
            }

            for column in OPTIONAL_NUMERIC_COLUMNS:
                if column in row:
                    record[column] = (
                        _parse_non_negative_integer(row[column], column, line_number)
                        if row[column]
                        else None
                    )
                    if column in ("src_port", "dst_port"):
                        port = record[column]
                        if port is not None and port > 65535:
                            raise ValueError(
                                f"CSV line {line_number}: '{column}' must be between 0 and 65535."
                            )

            # Preserve any additional columns for exploration and export.
            for column, value in row.items():
                if column not in record:
                    record[column] = value if value is not None else ""

            records.append(record)

        return records
    except csv.Error as error:
        raise ValueError(f"Could not parse CSV data: {error}") from error


def _parse_non_negative_integer(value: str, column: str, line_number: int) -> int:
    try:
        parsed_value = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"CSV line {line_number}: '{column}' must be an integer; got {value!r}."
        ) from error

    if parsed_value < 0:
        raise ValueError(f"CSV line {line_number}: '{column}' cannot be negative.")
    return parsed_value


def load_network_traffic_file(csv_path: str | Path) -> list[TrafficRecord]:
    """Load a dataset from an explicit CSV file path."""
    csv_path = Path(csv_path)
    try:
        with csv_path.open("r", newline="", encoding="utf-8-sig") as csv_file:
            return parse_network_traffic_csv(csv_file)
    except FileNotFoundError as error:
        raise FileNotFoundError(f"Network traffic CSV file was not found: {csv_path}") from error
    except UnicodeDecodeError as error:
        raise ValueError(f"CSV file is not valid UTF-8: {csv_path}") from error


def load_network_traffic() -> list[TrafficRecord]:
    """Load the project's default sample dataset."""
    csv_path = Path(__file__).resolve().parent.parent / "data" / "network_traffic.csv"
    return load_network_traffic_file(csv_path)
