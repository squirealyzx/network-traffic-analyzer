"""Streamlit dashboard for offline network traffic analysis."""

from datetime import timedelta
import io

import pandas as pd
import streamlit as st

from src.analyzer import (
    calculate_dashboard_statistics,
    export_records_to_csv,
    filter_records,
    prepare_traffic_dataframe,
)
from src.data_loader import load_network_traffic, parse_network_traffic_csv
from src.detector import detect_anomalies
from src.visualization import (
    ip_activity_figure,
    packet_size_figure,
    port_activity_figure,
    protocol_distribution_figure,
    protocol_volume_figure,
    traffic_over_time_figure,
)


def load_uploaded_csv(uploaded_file) -> list[dict[str, object]]:
    """Decode an uploaded file and use the shared CSV validation logic."""
    csv_text = uploaded_file.getvalue().decode("utf-8-sig")
    return parse_network_traffic_csv(io.StringIO(csv_text))


def format_bytes(value: int | float) -> str:
    """Format bytes using readable binary units."""
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:,.1f} {unit}" if unit != "B" else f"{size:,.0f} B"
        size /= 1024
    return f"{size:,.1f} TB"


def make_anomaly_table(results: list[dict[str, object]]) -> pd.DataFrame:
    """Turn detector results into concise table rows for the interface."""
    rows = []
    for result in results:
        if result["suspicious"]:
            rows.append(
                {
                    "Severity": result["severity"],
                    "Source IP": result["src_ip"],
                    "Packets": result["total_packets"],
                    "Bytes": result["total_bytes"],
                    "Triggered metric": ", ".join(result["exceeded_thresholds"]),
                    "Why flagged": "; ".join(result["reasons"]),
                    "Assessment": result["assessment"],
                }
            )
    return pd.DataFrame(
        rows,
        columns=[
            "Severity",
            "Source IP",
            "Packets",
            "Bytes",
            "Triggered metric",
            "Why flagged",
            "Assessment",
        ],
    )


def build_summary_csv(
    statistics: dict[str, object], source_name: str, suspicious_ip_count: int
) -> str:
    """Serialize dashboard KPIs and protocol packet counts as a summary CSV."""
    summary: dict[str, object] = {
        "dataset": source_name,
        "total_records": statistics["total_records"],
        "total_packets": statistics["total_packets"],
        "total_bytes": statistics["total_bytes"],
        "average_packet_size_bytes": statistics["average_packet_size"],
        "unique_source_ips": statistics["unique_source_ips"],
        "unique_destination_ips": statistics["unique_destination_ips"],
        "unique_ip_addresses": statistics["unique_ip_addresses"],
        "suspicious_ip_count": suspicious_ip_count,
    }
    for protocol, count in statistics["protocol_packet_counts"].items():
        summary[f"{str(protocol).lower()}_packets"] = count
    return pd.DataFrame([summary]).to_csv(index=False)


def render_chart(figure, empty_message: str) -> None:
    """Show a Plotly figure or a calm empty-data message."""
    if figure is None:
        st.info(empty_message)
    else:
        st.plotly_chart(figure, width="stretch", config={"displayModeBar": False})


st.set_page_config(
    page_title="Network Traffic Analyzer",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Keep the interface self-contained and use a consistent dark analytics theme.
st.markdown(
    """
    <style>
    :root { color-scheme: dark; }
    [data-testid="stAppViewContainer"] { background: #080d18; }
    [data-testid="stHeader"] { background: rgba(8, 13, 24, 0.92); }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1524 0%, #0a101c 100%);
        border-right: 1px solid #1e2a3c;
    }
    .block-container { max-width: 1480px; padding-top: 1.5rem; padding-bottom: 3rem; }
    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #111c2d, #0d1625);
        border: 1px solid #24334a;
        border-radius: 14px;
        padding: 16px 18px;
        min-height: 112px;
    }
    [data-testid="stMetricLabel"] { color: #9fb0c7; }
    [data-testid="stMetricValue"] { color: #f2f6fc; }
    .hero {
        padding: 24px 28px;
        margin-bottom: 18px;
        border: 1px solid #23344b;
        border-radius: 18px;
        background: radial-gradient(circle at 84% 12%, #15334a 0, #111c2d 38%, #0d1523 100%);
    }
    .hero-kicker { color: #55d6be; text-transform: uppercase; letter-spacing: .14em;
        font-size: .72rem; font-weight: 700; }
    .hero-title { color: #f3f7fc; font-size: 2rem; font-weight: 750; margin: 6px 0; }
    .hero-copy { color: #a8b7ca; margin: 0; max-width: 760px; }
    h2, h3 { letter-spacing: -.02em; }
    div[data-testid="stDownloadButton"] button { border-radius: 9px; }
    </style>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("### ◈ NETSCOPE")
    st.caption("Offline network analytics")
    page = st.radio(
        "Workspace",
        ["Overview", "Traffic Explorer", "Anomaly Review"],
        label_visibility="collapsed",
    )
    st.divider()
    uploaded_file = st.file_uploader("Load a CSV dataset", type=["csv"])

source_name = uploaded_file.name if uploaded_file is not None else "Sample dataset"
try:
    with st.spinner("Loading and validating traffic records..."):
        if uploaded_file is not None:
            records = load_uploaded_csv(uploaded_file)
        else:
            records = load_network_traffic()
except (FileNotFoundError, OSError, UnicodeDecodeError, ValueError) as error:
    st.error(f"The dataset could not be loaded. Check the CSV structure and try again. Details: {error}")
    st.stop()

all_frame = prepare_traffic_dataframe(records)
with st.sidebar:
    st.caption(f"Dataset: **{source_name}** · {len(records):,} records")
    st.divider()
    st.markdown("#### Filters")

    protocol_options = sorted(value for value in all_frame["protocol"].unique() if value)
    selected_protocols = st.multiselect(
        "Protocol", protocol_options, default=protocol_options
    )

    source_options = sorted(str(value) for value in all_frame["src_ip"].dropna().unique())
    selected_sources = st.multiselect("Source IP", source_options)
    destination_options = sorted(
        str(value) for value in all_frame["dst_ip"].dropna().unique()
    )
    selected_destinations = st.multiselect("Destination IP", destination_options)

    available_ports = sorted(
        {
            int(port)
            for column in ("src_port", "dst_port")
            for port in all_frame[column].dropna().unique()
        }
    )
    if available_ports:
        selected_ports = st.multiselect("Source or destination port", available_ports)
    else:
        selected_ports = []
        st.caption("This dataset has no port metadata.")

    packet_sizes = all_frame["packet_size_bytes"].dropna()
    if not packet_sizes.empty:
        size_min = float(packet_sizes.min())
        size_max = float(packet_sizes.max())
        if size_min < size_max:
            packet_size_range = st.slider(
                "Bytes per packet",
                min_value=size_min,
                max_value=size_max,
                value=(size_min, size_max),
                step=max((size_max - size_min) / 100, 0.1),
                help="Uses reported packet sizes when present; otherwise estimates bytes ÷ packets per record.",
            )
        else:
            packet_size_range = (size_min, size_max)
            st.caption(f"Bytes per packet: {size_min:,.1f}")
    else:
        packet_size_range = None
        st.caption("Packet-size filtering is unavailable for these records.")

    valid_timestamps = all_frame["_timestamp_utc"].dropna()
    if len(valid_timestamps) > 1:
        earliest = valid_timestamps.min().to_pydatetime().replace(tzinfo=None)
        latest = valid_timestamps.max().to_pydatetime().replace(tzinfo=None)
        if earliest < latest:
            selected_time_range = st.slider(
                "Time range (UTC)",
                min_value=earliest,
                max_value=latest,
                value=(earliest, latest),
                step=timedelta(seconds=1),
                format="YYYY-MM-DD HH:mm:ss",
            )
        else:
            selected_time_range = None
            st.caption("All records have the same timestamp.")
    else:
        selected_time_range = None
        st.caption("Time filtering is unavailable without valid timestamps.")

    search_query = st.text_input("Search records", placeholder="IP, protocol, port…")
    st.divider()
    st.markdown("#### Detection thresholds")
    packet_threshold = st.number_input(
        "Packets per source IP", min_value=0, value=500, step=100
    )
    byte_threshold = st.number_input(
        "Bytes per source IP", min_value=0, value=100000, step=10000
    )
    st.caption("Rule-based outliers are review signals, not proof of an attack.")

filtered_records = filter_records(
    records,
    protocols=selected_protocols or None,
    source_ips=selected_sources or None,
    destination_ips=selected_destinations or None,
    ports=selected_ports or None,
    packet_size_range=packet_size_range,
    time_range=selected_time_range,
    search_query=search_query,
)
statistics = calculate_dashboard_statistics(filtered_records)
anomaly_results = detect_anomalies(
    filtered_records,
    packet_threshold=int(packet_threshold),
    byte_threshold=int(byte_threshold),
)
suspicious_table = make_anomaly_table(anomaly_results)
suspicious_ips = set(suspicious_table["Source IP"]) if not suspicious_table.empty else set()

st.markdown(
    f"""
    <div class="hero">
      <div class="hero-kicker">Network intelligence · Offline analysis</div>
      <div class="hero-title">Network Traffic Analyzer</div>
      <p class="hero-copy">Explore traffic patterns, compare protocol and endpoint activity,
      and review threshold-based outliers in authorized CSV datasets.</p>
    </div>
    """,
    unsafe_allow_html=True,
)
st.caption(
    f"Viewing **{len(filtered_records):,} of {len(records):,} records** from **{source_name}**. "
    "All calculations update with the selected filters."
)

if page == "Overview":
    st.subheader("Network overview")
    packet_counts = statistics["protocol_packet_counts"]
    kpi_rows = [
        [
            ("Total packets", statistics["total_packets"]),
            ("Traffic volume", format_bytes(statistics["total_bytes"])),
            ("Average packet size", f"{statistics['average_packet_size']:,.1f} B"),
            ("Unique IP addresses", statistics["unique_ip_addresses"]),
        ],
        [
            ("TCP packets", packet_counts.get("TCP", 0)),
            ("UDP packets", packet_counts.get("UDP", 0)),
            ("ICMP packets", packet_counts.get("ICMP", 0)),
            ("Records", statistics["total_records"]),
        ],
    ]
    for values in kpi_rows:
        columns = st.columns(4)
        for column, (label, value) in zip(columns, values):
            column.metric(label, f"{value:,}" if isinstance(value, int) else value)

    if not filtered_records:
        st.info("No records match the current filters. Adjust the sidebar filters or load another CSV.")
    else:
        st.subheader("Traffic patterns")
        left, right = st.columns(2)
        with left:
            render_chart(
                protocol_distribution_figure(filtered_records),
                "No protocol packet counts are available for this selection.",
            )
        with right:
            render_chart(
                traffic_over_time_figure(filtered_records),
                "No valid timestamps are available for a time-series chart.",
            )

        ip_metric_label = st.radio(
            "Endpoint activity",
            ["Packets", "Traffic volume"],
            horizontal=True,
            key="ip_activity_metric",
        )
        ip_metric = "packets" if ip_metric_label == "Packets" else "bytes"

        left, right = st.columns(2)
        with left:
            render_chart(
                ip_activity_figure(
                    filtered_records, address_column="src_ip", metric=ip_metric
                ),
                "No source IP activity is available.",
            )
        with right:
            render_chart(
                ip_activity_figure(
                    filtered_records, address_column="dst_ip", metric=ip_metric
                ),
                "No destination IP activity is available.",
            )

        left, right = st.columns(2)
        with left:
            render_chart(
                protocol_volume_figure(filtered_records),
                "No protocol traffic volume is available.",
            )
        with right:
            render_chart(
                packet_size_figure(filtered_records),
                "No packet-size values can be calculated for these records.",
            )

        port_figure = port_activity_figure(filtered_records)
        if port_figure is not None:
            render_chart(port_figure, "No port activity is available.")

        st.subheader("Potentially unusual activity")
        st.caption("These rule-based findings need context and do not confirm malicious activity.")
        if suspicious_table.empty:
            st.success("No source IPs exceeded the configured thresholds.")
        else:
            st.dataframe(suspicious_table, width="stretch", hide_index=True)

elif page == "Traffic Explorer":
    st.subheader("Traffic explorer")
    st.caption("Search, sort, filter, and export the currently selected records.")

    if not filtered_records:
        st.info("No records match the current filters. Adjust the sidebar filters or load another CSV.")
    else:
        display_limit = st.slider(
            "Rows to display", min_value=1, max_value=min(len(filtered_records), 1000),
            value=min(len(filtered_records), 250), step=1,
        )
        display_frame = prepare_traffic_dataframe(filtered_records)
        display_frame["status"] = display_frame["src_ip"].map(
            lambda source: "Review" if source in suspicious_ips else "—"
        )
        display_frame["size_basis"] = display_frame["packet_size"].isna().map(
            {True: "Estimated from bytes/packets", False: "Provided in dataset"}
        )
        display_frame = display_frame.drop(
            columns=["_timestamp_utc", "_record_index", "packet_size"]
        )
        display_frame = display_frame.rename(
            columns={
                "timestamp": "Timestamp (UTC)",
                "src_ip": "Source IP",
                "dst_ip": "Destination IP",
                "protocol": "Protocol",
                "packets": "Packets",
                "bytes": "Bytes",
                "src_port": "Source port",
                "dst_port": "Destination port",
                "packet_size_bytes": "Bytes per packet",
                "size_basis": "Size basis",
                "status": "Review status",
            }
        )

        def highlight_flagged_rows(row):
            color = "background-color: #3b2730; color: #ffe4e8" if row["Source IP"] in suspicious_ips else ""
            return [color] * len(row)

        styled_frame = display_frame.head(display_limit).style.apply(
            highlight_flagged_rows, axis=1
        )
        st.dataframe(
            styled_frame,
            width="stretch",
            height=590,
            hide_index=True,
            column_config={
                "Bytes": st.column_config.NumberColumn(format="%,d"),
                "Packets": st.column_config.NumberColumn(format="%,d"),
                "Bytes per packet": st.column_config.NumberColumn(format="%.1f B"),
            },
        )

        export_columns = st.columns(2)
        export_columns[0].download_button(
            "Download filtered traffic CSV",
            data=export_records_to_csv(filtered_records).encode("utf-8-sig"),
            file_name="filtered_network_traffic.csv",
            mime="text/csv",
            width="stretch",
        )
        export_columns[1].download_button(
            "Download analysis summary CSV",
            data=build_summary_csv(
                statistics, source_name, len(suspicious_table)
            ).encode("utf-8-sig"),
            file_name="traffic_analysis_summary.csv",
            mime="text/csv",
            width="stretch",
        )

elif page == "Anomaly Review":
    st.subheader("Anomaly review")
    st.caption(
        f"A source is flagged when its filtered totals exceed {int(packet_threshold):,} packets "
        f"or {int(byte_threshold):,} bytes. A flag is an observation, not a diagnosis."
    )
    if not filtered_records:
        st.info("No records match the current filters.")
    elif suspicious_table.empty:
        st.success("No source IPs exceeded the configured thresholds.")
    else:
        st.warning(f"{len(suspicious_table)} source IP(s) need review.")
        st.dataframe(suspicious_table, width="stretch", hide_index=True)

        with st.expander("Review all source IP totals"):
            all_results = pd.DataFrame(anomaly_results)
            all_results["exceeded_thresholds"] = all_results[
                "exceeded_thresholds"
            ].apply(lambda values: ", ".join(values) if values else "None")
            all_results["reasons"] = all_results["reasons"].apply(
                lambda values: "; ".join(values) if values else "No configured threshold was exceeded."
            )
            st.dataframe(all_results, width="stretch", hide_index=True)

st.divider()
st.caption(
    "NETSCOPE analyzes offline datasets only. Threshold outliers may be benign; "
    "the dashboard does not label activity as confirmed malicious."
)
