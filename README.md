# Network Traffic Analyzer

A Streamlit dashboard for exploring **offline network traffic CSV datasets**. It summarizes packet and byte counts, compares protocols and IP activity, filters records, exports analysis results, and flags unusual source-IP totals for review.

The project is designed for learning network analysis and defensive security. A threshold flag is an observation that needs context; it is not proof of an attack or other malicious activity.

## Features

- Load the included sample dataset or upload a CSV file.
- Validate required columns and numeric counters with actionable errors.
- Filter by protocol, source and destination IP, port, bytes per packet, time range, and text search.
- View packet, traffic-volume, average-size, and unique-IP metrics.
- Explore protocol distribution, activity over time, top source and destination IPs, traffic volume, packet-size estimates, and ports when available.
- Review threshold-based outliers with severity, trigger, and explanation.
- Search and sort the traffic table, highlight flagged source IPs, and limit displayed rows.
- Download filtered records and an analysis summary as CSV.
- Run the full test suite offline; packet-capture tests use synthetic Scapy packets and mocks.

## Technology

- Python 3.11 or newer
- Streamlit
- pandas
- Plotly
- Scapy (kept isolated from the dashboard)
- pytest

The application does not use a database. SQLite is part of Python's standard library but is not needed for the current CSV workflow.

## Project structure

```text
network-traffic-analyzer/
├── app.py                     # Streamlit UI, navigation, filters, and exports
├── data/
│   ├── network_traffic.csv    # Included sample dataset
│   └── test_traffic.csv       # Small manual test dataset
├── src/
│   ├── analyzer.py            # Metrics, filters, normalization, CSV export
│   ├── capture.py             # Standalone packet metadata capture; not used by app.py
│   ├── data_loader.py         # CSV parsing and validation
│   ├── detector.py            # Explainable threshold-based outlier rules
│   ├── main.py                # Simple command-line summary
│   └── visualization.py       # Plotly chart builders
├── tests/
│   ├── test_analyzer.py
│   ├── test_capture.py
│   ├── test_data_loader.py
│   ├── test_detector.py
│   └── test_visualization.py
├── requirements.txt
└── README.md
```

## Installation on Windows

Open the repository folder in VS Code, then open a PowerShell terminal in that folder.

```powershell
py --version
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If the Windows Python launcher `py` is unavailable, use `python` in its place. If `.venv` already exists, activate it instead of creating another environment.

## Run the application

```powershell
python -m streamlit run app.py
```

Streamlit prints a local URL in the terminal. Open it in your browser. The app uses the included sample CSV until you upload another dataset. All metrics, charts, anomaly results, and exports follow the selected filters.

## Run tests

```powershell
python -m pytest
```

Tests do not sniff a live interface, require administrator rights, or access a network. They build packet fixtures in memory and mock Scapy's capture function.

## Dataset format

Required CSV columns:

| Column | Meaning |
| --- | --- |
| `timestamp` | Record timestamp; blank or invalid values are omitted from time charts and time filtering. |
| `src_ip` | Source IP address. |
| `dst_ip` | Destination IP address. |
| `protocol` | Protocol label such as TCP, UDP, or ICMP. |
| `packets` | Number of packets represented by the record. |
| `bytes` | Total traffic volume represented by the record, in bytes. |

Optional columns: `src_port`, `dst_port`, and `packet_size`. If exact packet size is absent, the dashboard estimates bytes per packet as `bytes / packets` for that record. The estimate is labeled accordingly.

The included example data is synthetic and intended for demonstration. The CSV can represent aggregated flow records as well as single-packet records; metrics use the values in `packets` and `bytes`.

## Anomaly interpretation

The detector aggregates packet and byte totals by source IP and applies configurable defaults of 500 packets and 100,000 bytes. Exceeding one threshold is marked **Moderate**; exceeding both is marked **High**. These labels describe rule triggers only. They do not establish intent or confirm malicious activity. Adjust thresholds in the sidebar for the dataset and time window being reviewed.

## Screenshots

Screenshots can be added here after capturing the dashboard with a representative dataset:

```text
docs/images/dashboard.png
docs/images/traffic-explorer.png
```

## Limitations and safety

- The Streamlit application analyzes CSV files only. It does not capture live traffic or monitor other devices.
- `src/capture.py` is a separate, standalone module and is not imported by the dashboard. Its tests are offline. Live capture is not part of the app workflow.
- Using `capture.py` directly on Windows requires Npcap and appropriate access to a specific interface. Only capture traffic on a network you are authorized to monitor.
- The dashboard uses simple thresholds and cannot determine whether traffic is malicious.
- Missing port metadata limits port filtering and port charts. Missing or invalid timestamps limit time filtering and timeline charts.
- Large CSV files are loaded into memory; the table limits displayed rows, while filters and exports operate on the selected dataset.

## Future improvements

- Add more robust time-window-aware anomaly baselines and unit tests.
- Add optional offline PCAP import without enabling live capture in the dashboard.
- Add dataset provenance and richer export summaries.
- Add screenshots and a short demonstration GIF.
