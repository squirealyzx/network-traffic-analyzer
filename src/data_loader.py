import csv
from pathlib import Path


def load_network_traffic():
    """Load network traffic rows from the project's CSV file."""
    csv_path = Path(__file__).resolve().parent.parent / "data" / "network_traffic.csv"

    try:
        with csv_path.open("r", newline="", encoding="utf-8") as csv_file:
            reader = csv.DictReader(csv_file)
            required_columns = {"timestamp", "src_ip", "dst_ip", "protocol", "packets", "bytes"}

            if reader.fieldnames is None:
                raise ValueError(f"CSV file is empty or has no header: {csv_path}")

            missing_columns = required_columns - set(reader.fieldnames)
            if missing_columns:
                names = ", ".join(sorted(missing_columns))
                raise ValueError(f"CSV file is missing required column(s): {names}")

            rows = []
            for line_number, row in enumerate(reader, start=2):
                if None in row:
                    raise ValueError(f"CSV line {line_number} has more values than the header columns")

                for column in required_columns:
                    if row.get(column) is None or not row[column].strip():
                        raise ValueError(f"CSV line {line_number}: '{column}' is missing or empty")

                for column in ("packets", "bytes"):
                    try:
                        row[column] = int(row[column])
                    except ValueError as error:
                        raise ValueError(
                            f"CSV line {line_number}: '{column}' must be an integer; got {row[column]!r}"
                        ) from error

                rows.append(row)

            return rows
    except FileNotFoundError as error:
        raise FileNotFoundError(f"Network traffic CSV file was not found: {csv_path}") from error

