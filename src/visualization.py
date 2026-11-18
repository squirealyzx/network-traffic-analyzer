"""Plotly figure builders used by the Streamlit dashboard."""

from collections.abc import Sequence

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from src.analyzer import TrafficRecord, prepare_traffic_dataframe


CHART_TEMPLATE = "plotly_dark"


def protocol_distribution_figure(records: Sequence[TrafficRecord]) -> go.Figure | None:
    """Build a donut chart showing packet counts by protocol."""
    frame = prepare_traffic_dataframe(records)
    grouped = frame.groupby("protocol", as_index=False)["packets"].sum()
    grouped = grouped[grouped["packets"] > 0]
    if grouped.empty:
        return None

    figure = px.pie(
        grouped,
        names="protocol",
        values="packets",
        hole=0.62,
        template=CHART_TEMPLATE,
        color_discrete_sequence=px.colors.qualitative.Bold,
    )
    figure.update_traces(textposition="inside", textinfo="percent+label")
    figure.update_layout(title="Protocol distribution", height=340)
    return _style_figure(figure)


def traffic_over_time_figure(records: Sequence[TrafficRecord]) -> go.Figure | None:
    """Build a line chart of packet counts over valid timestamps."""
    frame = prepare_traffic_dataframe(records)
    timed = frame.dropna(subset=["_timestamp_utc"])
    if timed.empty:
        return None

    grouped = (
        timed.groupby("_timestamp_utc", as_index=False)["packets"]
        .sum()
        .sort_values("_timestamp_utc")
    )
    figure = px.line(
        grouped,
        x="_timestamp_utc",
        y="packets",
        markers=True,
        template=CHART_TEMPLATE,
        labels={"_timestamp_utc": "Timestamp", "packets": "Packets"},
    )
    figure.update_layout(title="Packet activity over time", height=340)
    return _style_figure(figure)


def ip_activity_figure(
    records: Sequence[TrafficRecord],
    *,
    address_column: str,
    metric: str = "packets",
    limit: int = 10,
) -> go.Figure | None:
    """Build a horizontal bar chart for the busiest source or destination IPs."""
    if address_column not in ("src_ip", "dst_ip") or metric not in ("packets", "bytes"):
        raise ValueError("Use src_ip or dst_ip and packets or bytes for the chart.")

    frame = prepare_traffic_dataframe(records)
    grouped = (
        frame.dropna(subset=[address_column])
        .groupby(address_column, as_index=False)[metric]
        .sum()
        .nlargest(limit, metric)
        .sort_values(metric)
    )
    if grouped.empty:
        return None

    label = "Packets" if metric == "packets" else "Bytes"
    title_label = "Source" if address_column == "src_ip" else "Destination"
    figure = px.bar(
        grouped,
        x=metric,
        y=address_column,
        orientation="h",
        template=CHART_TEMPLATE,
        color=metric,
        color_continuous_scale="Teal",
        labels={address_column: "IP address", metric: label},
    )
    figure.update_layout(title=f"Top {title_label} IPs by {label.lower()}", height=360)
    return _style_figure(figure)


def protocol_volume_figure(records: Sequence[TrafficRecord]) -> go.Figure | None:
    """Build a chart comparing byte volume across protocols."""
    frame = prepare_traffic_dataframe(records)
    grouped = frame.groupby("protocol", as_index=False)["bytes"].sum()
    grouped = grouped[grouped["bytes"] > 0]
    if grouped.empty:
        return None

    figure = px.bar(
        grouped,
        x="protocol",
        y="bytes",
        template=CHART_TEMPLATE,
        color="protocol",
        labels={"protocol": "Protocol", "bytes": "Traffic volume (bytes)"},
    )
    figure.update_layout(title="Traffic volume by protocol", height=340, showlegend=False)
    return _style_figure(figure)


def packet_size_figure(records: Sequence[TrafficRecord]) -> go.Figure | None:
    """Build a weighted distribution of packet sizes or per-record estimates."""
    frame = prepare_traffic_dataframe(records).dropna(subset=["packet_size_bytes"])
    if frame.empty:
        return None

    figure = px.histogram(
        frame,
        x="packet_size_bytes",
        y="packets",
        histfunc="sum",
        nbins=20,
        template=CHART_TEMPLATE,
        labels={
            "packet_size_bytes": "Bytes per packet",
            "packets": "Packets represented",
        },
    )
    figure.update_layout(title="Packet-size distribution", height=340)
    return _style_figure(figure)


def port_activity_figure(records: Sequence[TrafficRecord], limit: int = 10) -> go.Figure | None:
    """Build a chart of the most frequently used source and destination ports."""
    frame = prepare_traffic_dataframe(records)
    port_rows = []
    for column in ("src_port", "dst_port"):
        known_ports = frame.dropna(subset=[column])
        if not known_ports.empty:
            port_rows.append(
                known_ports[[column, "packets"]].rename(columns={column: "port"})
            )

    if not port_rows:
        return None

    grouped = (
        pd.concat(port_rows)
        .groupby("port", as_index=False)["packets"]
        .sum()
        .nlargest(limit, "packets")
        .sort_values("packets")
    )
    figure = px.bar(
        grouped,
        x="packets",
        y="port",
        orientation="h",
        template=CHART_TEMPLATE,
        labels={"port": "Port", "packets": "Packets"},
    )
    figure.update_layout(title="Most active ports", height=340)
    return _style_figure(figure)


def _style_figure(figure: go.Figure) -> go.Figure:
    """Apply shared background and spacing to dashboard charts."""
    figure.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin={"l": 18, "r": 18, "t": 64, "b": 22},
        font={"family": "Inter, Segoe UI, sans-serif", "color": "#d7e2f0"},
    )
    return figure
