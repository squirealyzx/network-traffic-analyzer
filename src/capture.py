"""Capture authorized network traffic and return packet metadata records."""

from datetime import datetime, timezone
import math
from typing import TypedDict

from scapy.all import get_if_list, sniff
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Packet


class CapturedPacket(TypedDict):
    """Metadata for one captured packet, compatible with the CSV pipeline."""

    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    packets: int
    bytes: int
    packet_size: int
    src_port: int | None
    dst_port: int | None


class PacketCaptureError(RuntimeError):
    """Raised when Scapy cannot start or complete packet capture."""


def extract_packet_metadata(packet: Packet) -> CapturedPacket | None:
    """Convert a TCP, UDP, or ICMP IPv4 packet to metadata, without its payload."""
    ip_layer = packet.getlayer(IP)
    if ip_layer is None:
        return None

    source_port = None
    destination_port = None

    if packet.haslayer(TCP):
        protocol = "TCP"
        transport_layer = packet.getlayer(TCP)
        source_port = int(transport_layer.sport)
        destination_port = int(transport_layer.dport)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        transport_layer = packet.getlayer(UDP)
        source_port = int(transport_layer.sport)
        destination_port = int(transport_layer.dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    else:
        # Ignore other IP protocols because this module reports TCP, UDP, and ICMP.
        return None

    packet_time = getattr(packet, "time", None)
    try:
        timestamp = datetime.fromtimestamp(
            float(packet_time), tz=timezone.utc
        ).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError, OSError):
        # Use the current UTC time if a packet fixture has no valid timestamp.
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    packet_size = len(packet)
    return {
        "timestamp": timestamp,
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "protocol": protocol,
        # The existing analyzer expects each input record to represent one packet.
        "packets": 1,
        # Keep `bytes` for the existing pipeline and `packet_size` for display.
        "bytes": packet_size,
        "packet_size": packet_size,
        "src_port": source_port,
        "dst_port": destination_port,
    }


def capture_packets(
    interface: str,
    duration: float = 10,
    packet_limit: int = 100,
) -> list[CapturedPacket]:
    """Capture up to `packet_limit` packets for `duration` seconds on one interface.

    Pass only an interface on a network you are authorized to monitor. Payloads
    are not returned or retained: Scapy stores no packet objects after callbacks.
    """
    if not isinstance(interface, str) or not interface.strip():
        raise ValueError("An explicit, non-empty network interface is required.")
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(duration)
        or duration <= 0
    ):
        raise ValueError("duration must be a finite number greater than zero.")
    if isinstance(packet_limit, bool) or not isinstance(packet_limit, int) or packet_limit <= 0:
        raise ValueError("packet_limit must be a positive integer.")

    interface = interface.strip()
    try:
        available_interfaces = get_if_list()
    except Exception as error:
        raise PacketCaptureError(
            "Could not list network interfaces. On Windows, check that Npcap is installed."
        ) from error

    if not available_interfaces:
        raise PacketCaptureError(
            "No network interfaces are available. On Windows, check that Npcap is installed."
        )
    if interface not in available_interfaces:
        available = ", ".join(available_interfaces)
        raise ValueError(
            f"Unknown interface {interface!r}. Available interfaces: {available}"
        )

    records: list[CapturedPacket] = []

    def save_metadata(packet: Packet) -> None:
        record = extract_packet_metadata(packet)
        if record is not None:
            records.append(record)

    try:
        # Scapy stops at whichever limit is reached first. store=False prevents
        # Scapy from keeping full packet objects, including payloads, in memory.
        sniff(
            iface=interface,
            timeout=float(duration),
            count=packet_limit,
            store=False,
            prn=save_metadata,
        )
    except PermissionError as error:
        raise PacketCaptureError(
            f"Permission denied while capturing on {interface!r}. "
            "Check Windows/Npcap capture permissions."
        ) from error
    except Exception as error:
        raise PacketCaptureError(
            f"Capture failed on interface {interface!r}: {error}. "
            "On Windows, verify that Npcap is installed and the interface is available."
        ) from error

    return records
