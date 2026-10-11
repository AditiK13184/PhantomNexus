from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import ipaddress
import json
import logging
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time
from typing import Any

from .data_loader import DATASET_DIR, REQUIRED_COLUMNS

logger = logging.getLogger(__name__)

LIVE_SESSIONS_DIR = DATASET_DIR / "live_sessions"
SUSPICIOUS_PORTS = {23, 2323, 4444, 48101, 5555, 6667}


def is_admin_process() -> bool:
    """Verify whether current process runs with elevated Administrator privileges on Windows."""
    try:
        if sys.platform == "win32":
            return bool(ctypes.windll.shell32.IsUserAnAdmin() != 0)
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def _get_local_ip() -> str:
    """Detect the active local IPv4 address used for default routing."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def get_available_interfaces() -> list[str]:
    """Enumerate all active local IPv4 interface addresses on this machine."""
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass

    default_ip = _get_local_ip()
    if default_ip and not default_ip.startswith("127."):
        ips.add(default_ip)

    return sorted(list(ips))


def select_bind_interface(target_ip: str) -> str:
    """Choose the best local network interface address to sniff for the given target IP."""
    available = get_available_interfaces()

    # 1. If target matches one of our local IPs directly (self-monitoring)
    if target_ip in available:
        return target_ip

    # 2. Try OS routing lookup towards target_ip to pick the matching outbound interface
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 80))
        routed_ip = s.getsockname()[0]
        s.close()
        if routed_ip and not routed_ip.startswith("127."):
            return routed_ip
    except Exception:
        pass

    # 3. Fallback to default route IP or first available
    default_ip = _get_local_ip()
    if default_ip and not default_ip.startswith("127."):
        return default_ip

    return available[0] if available else "127.0.0.1"


def _parse_ipv4_packet(raw_data: bytes) -> dict[str, Any] | None:
    """Disassemble an IPv4 packet and extract basic Layer 3 and Layer 4 fields."""
    if len(raw_data) < 20:
        return None

    # First byte: Version (4 bits) and IHL (4 bits)
    version_ihl = raw_data[0]
    version = version_ihl >> 4
    if version != 4:
        return None

    ihl = (version_ihl & 0x0F) * 4
    if len(raw_data) < ihl:
        return None

    total_length = struct.unpack("!H", raw_data[2:4])[0]
    protocol_num = raw_data[9]
    src_ip = socket.inet_ntoa(raw_data[12:16])
    dest_ip = socket.inet_ntoa(raw_data[16:20])

    protocol = "OTHER"
    src_port = 0
    dest_port = 0

    if protocol_num == 6:  # TCP
        protocol = "TCP"
        if len(raw_data) >= ihl + 4:
            src_port, dest_port = struct.unpack("!HH", raw_data[ihl : ihl + 4])
    elif protocol_num == 17:  # UDP
        protocol = "UDP"
        if len(raw_data) >= ihl + 4:
            src_port, dest_port = struct.unpack("!HH", raw_data[ihl : ihl + 4])
    elif protocol_num == 1:  # ICMP
        protocol = "ICMP"
        dest_port = 0

    return {
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "protocol": protocol,
        "bytes": total_length or len(raw_data),
    }


class LiveMonitoringSession:
    def __init__(self, target_ip: str, session_id: str) -> None:
        self.target_ip = target_ip
        self.session_id = session_id
        self.device_id = f"live_{target_ip.replace('.', '_')}"
        self.start_time = datetime.now(timezone.utc)
        self.stop_time: datetime | None = None
        self.is_active = True

        # System & Elevation Info
        self.backend_pid = os.getpid()
        self.is_process_elevated = is_admin_process()
        self.available_interfaces = get_available_interfaces()
        self.local_interface_ip = select_bind_interface(target_ip)
        self.promiscuous_mode = False

        # Tier 1: Engine Lifecycle
        self.engine_status = "INITIALIZING"
        self.engine_message = "Starting packet capture thread..."

        # Tier 2: Interface Observability
        self.total_interface_packets = 0
        self.total_interface_bytes = 0

        # Tier 3: Target Device Verification
        self.target_packets_verified = 0
        self.target_bytes_verified = 0
        self.verification_state = "AWAITING_TARGET_TRAFFIC"

        # Packet & Flow Storage
        self.flows: list[dict[str, Any]] = []
        self.recent_flows: list[dict[str, Any]] = []
        self.time_series_buckets: dict[str, dict[str, int]] = {}

        # Live Analytics & Threats
        self.unique_destinations: set[str] = set()
        self.port_frequencies: dict[int, int] = {}
        self.protocol_frequencies: dict[str, int] = {}
        self.detected_anomalies: list[str] = []
        self.suspicious_port_hits: list[int] = []
        self.trust_score = 100.0
        self.risk_level = "safe"

        # Synchronization & Thread
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def update_analytics(self, flow: dict[str, Any]) -> None:
        with self._lock:
            self.target_packets_verified += 1
            self.target_bytes_verified += flow["bytes"]
            self.verification_state = "TARGET_TRAFFIC_VERIFIED"

            # Telemetry record adhering to REQUIRED_COLUMNS
            telemetry_row = {
                "device_id": self.device_id,
                "timestamp": flow["timestamp"],
                "src_ip": flow["src_ip"],
                "dest_ip": flow["dest_ip"],
                "dest_port": flow["dest_port"],
                "protocol": flow["protocol"],
                "bytes": flow["bytes"],
                "packets": 1,
            }
            self.flows.append(telemetry_row)
            self.recent_flows = self.flows[-50:]  # Keep latest 50 for stream display

            # Protocol & Port counting
            dest_port = flow["dest_port"]
            protocol = flow["protocol"]
            self.port_frequencies[dest_port] = self.port_frequencies.get(dest_port, 0) + 1
            self.protocol_frequencies[protocol] = self.protocol_frequencies.get(protocol, 0) + 1

            # Destination tracking
            if flow["dest_ip"] != self.target_ip:
                self.unique_destinations.add(flow["dest_ip"])

            # Time series bucketing (by 5-second interval)
            bucket_key = flow["timestamp"][:18] + "0"  # rough 10s slice
            if bucket_key not in self.time_series_buckets:
                self.time_series_buckets[bucket_key] = {"timestamp": bucket_key, "packets": 0, "bytes": 0}
            self.time_series_buckets[bucket_key]["packets"] += 1
            self.time_series_buckets[bucket_key]["bytes"] += flow["bytes"]

            # Anomaly Checks
            anomalies: list[str] = []
            if dest_port in SUSPICIOUS_PORTS and dest_port not in self.suspicious_port_hits:
                self.suspicious_port_hits.append(dest_port)

            if self.suspicious_port_hits:
                anomalies.append(f"Suspicious port activity ({', '.join(map(str, self.suspicious_port_hits))})")

            # Check external destinations count
            external_count = 0
            for dest in self.unique_destinations:
                try:
                    if not ipaddress.ip_address(dest).is_private:
                        external_count += 1
                except ValueError:
                    pass

            if external_count >= 5:
                anomalies.append("Elevated external IP fanout")

            # Check simple beaconing pattern if >= 6 packets
            if len(self.flows) >= 6:
                timestamps = [datetime.fromisoformat(f["timestamp"]) for f in self.flows[-12:]]
                deltas = [(timestamps[i] - timestamps[i - 1]).total_seconds() for i in range(1, len(timestamps))]
                if deltas:
                    avg_d = sum(deltas) / len(deltas)
                    if 0 < avg_d <= 30:
                        variance = (sum((d - avg_d) ** 2 for d in deltas) / len(deltas)) ** 0.5
                        if avg_d > 0 and (variance / avg_d) < 0.25:
                            anomalies.append("Periodic beaconing pattern detected")

            self.detected_anomalies = list(dict.fromkeys(anomalies))

            # Trust scoring deduction
            score = 100.0
            score -= len(self.suspicious_port_hits) * 20.0
            if "Periodic beaconing pattern detected" in self.detected_anomalies:
                score -= 30.0
            if "Elevated external IP fanout" in self.detected_anomalies:
                score -= 15.0

            self.trust_score = round(max(0.0, min(100.0, score)), 1)
            if self.trust_score < 40:
                self.risk_level = "critical"
            elif self.trust_score < 70:
                self.risk_level = "warning"
            else:
                self.risk_level = "safe"

    def stop(self) -> None:
        self._stop_event.set()
        self.is_active = False
        self.stop_time = datetime.now(timezone.utc)
        self.engine_status = "STOPPED"
        self.engine_message = "Capture stopped cleanly."

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            # Sort time series buckets by time
            sorted_series = sorted(self.time_series_buckets.values(), key=lambda b: b["timestamp"])[-20:]
            top_ports = sorted(
                [{"port": str(p), "count": c} for p, c in self.port_frequencies.items()],
                key=lambda x: x["count"],
                reverse=True,
            )[:6]
            top_protocols = [{"protocol": p, "count": c} for p, c in self.protocol_frequencies.items()]

            duration_seconds = int(
                ((self.stop_time or datetime.now(timezone.utc)) - self.start_time).total_seconds()
            )

            return {
                "session_id": self.session_id,
                "target_ip": self.target_ip,
                "device_id": self.device_id,
                "start_time": self.start_time.isoformat(),
                "stop_time": self.stop_time.isoformat() if self.stop_time else None,
                "duration_seconds": max(1, duration_seconds),
                "is_active": self.is_active,
                # Process & Interface Diagnostics
                "backend_pid": self.backend_pid,
                "is_process_elevated": self.is_process_elevated,
                "available_interfaces": self.available_interfaces,
                "local_interface_ip": self.local_interface_ip,
                "promiscuous_mode": self.promiscuous_mode,
                # Tier 1: Engine State
                "engine_status": self.engine_status,
                "engine_message": self.engine_message,
                # Tier 2: Interface Stats
                "total_interface_packets": self.total_interface_packets,
                "total_interface_bytes": self.total_interface_bytes,
                # Tier 3: Target Device Verification
                "target_packets_verified": self.target_packets_verified,
                "target_bytes_verified": self.target_bytes_verified,
                "verification_state": self.verification_state,
                # Telemetry & Threat Metrics
                "trust_score": self.trust_score,
                "risk_level": self.risk_level,
                "detected_anomalies": self.detected_anomalies,
                "suspicious_ports": self.suspicious_port_hits,
                "unique_destinations_count": len(self.unique_destinations),
                # Time Series & Charts
                "traffic_history": sorted_series,
                "port_distribution": top_ports,
                "protocol_distribution": top_protocols,
                # Recent Stream
                "recent_flows": self.recent_flows,
            }


class LiveMonitorService:
    def __init__(self) -> None:
        self.sessions: dict[str, LiveMonitoringSession] = {}
        self.active_session_id: str | None = None
        LIVE_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

    def get_system_diagnostics(self) -> dict[str, Any]:
        """Expose real-time process elevation, PID, and network interface status."""
        return {
            "backend_pid": os.getpid(),
            "is_process_elevated": is_admin_process(),
            "default_local_ip": _get_local_ip(),
            "available_interfaces": get_available_interfaces(),
            "has_active_session": self.active_session_id is not None,
            "active_session_id": self.active_session_id,
        }

    def start_monitoring(self, target_ip: str) -> dict[str, Any]:
        # Validate IPv4 format
        try:
            ip_obj = ipaddress.ip_address(target_ip.strip())
            if ip_obj.version != 4:
                raise ValueError("Only IPv4 addresses are currently supported")
            clean_ip = str(ip_obj)
        except Exception as e:
            return {
                "success": False,
                "error": f"Invalid IP address: {str(e)}",
                "session": None,
            }

        # Stop existing active session if one exists
        if self.active_session_id and self.active_session_id in self.sessions:
            existing = self.sessions[self.active_session_id]
            if existing.is_active:
                existing.stop()
                self._save_session_to_disk(existing)

        session_id = f"live_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{clean_ip.replace('.', '_')}"
        session = LiveMonitoringSession(target_ip=clean_ip, session_id=session_id)
        self.sessions[session_id] = session
        self.active_session_id = session_id

        # Launch packet capture worker in background thread
        thread = threading.Thread(
            target=self._capture_worker,
            args=(session,),
            daemon=True,
            name=f"CaptureWorker-{session_id}",
        )
        session._thread = thread
        thread.start()

        return {
            "success": True,
            "error": None,
            "session": session.snapshot(),
        }

    def stop_monitoring(self, session_id: str | None = None) -> dict[str, Any]:
        target_id = session_id or self.active_session_id
        if not target_id or target_id not in self.sessions:
            return {"success": False, "error": "No active monitoring session found to stop"}

        session = self.sessions[target_id]
        if session.is_active:
            session.stop()
            self._save_session_to_disk(session)

        if self.active_session_id == target_id:
            self.active_session_id = None

        return {"success": True, "session": session.snapshot()}

    def get_status(self, session_id: str | None = None) -> dict[str, Any]:
        target_id = session_id or self.active_session_id
        if not target_id or target_id not in self.sessions:
            return {
                "has_active_session": False,
                "session": None,
                "diagnostics": self.get_system_diagnostics(),
            }

        session = self.sessions[target_id]
        return {
            "has_active_session": session.is_active,
            "session": session.snapshot(),
            "diagnostics": self.get_system_diagnostics(),
        }

    def list_sessions(self) -> list[dict[str, Any]]:
        # Returns summary list of all in-memory and persisted sessions
        summaries = []
        for s in self.sessions.values():
            summaries.append(
                {
                    "session_id": s.session_id,
                    "target_ip": s.target_ip,
                    "device_id": s.device_id,
                    "start_time": s.start_time.isoformat(),
                    "is_active": s.is_active,
                    "verified_packets": s.target_packets_verified,
                    "trust_score": s.trust_score,
                    "risk_level": s.risk_level,
                }
            )
        return summaries

    def export_csv(self, session_id: str) -> str | None:
        if session_id not in self.sessions:
            # Check if saved on disk
            csv_path = LIVE_SESSIONS_DIR / f"{session_id}.csv"
            if csv_path.exists():
                return csv_path.read_text(encoding="utf-8")
            return None

        session = self.sessions[session_id]
        with session._lock:
            if not session.flows:
                # Return empty template with headers
                return ",".join(REQUIRED_COLUMNS) + "\n"

            lines = [",".join(REQUIRED_COLUMNS)]
            for f in session.flows:
                row = [
                    str(f.get("device_id", session.device_id)),
                    str(f.get("timestamp", "")),
                    str(f.get("src_ip", "")),
                    str(f.get("dest_ip", "")),
                    str(f.get("dest_port", 0)),
                    str(f.get("protocol", "TCP")),
                    str(f.get("bytes", 0)),
                    str(f.get("packets", 1)),
                ]
                lines.append(",".join(row))
            return "\n".join(lines)

    def _save_session_to_disk(self, session: LiveMonitoringSession) -> None:
        try:
            # 1. Save metadata JSON
            json_path = LIVE_SESSIONS_DIR / f"{session.session_id}.json"
            json_path.write_text(json.dumps(session.snapshot(), indent=2), encoding="utf-8")

            # 2. Save flow CSV conforming to REQUIRED_COLUMNS
            csv_content = self.export_csv(session.session_id)
            if csv_content:
                csv_path = LIVE_SESSIONS_DIR / f"{session.session_id}.csv"
                csv_path.write_text(csv_content, encoding="utf-8")
        except Exception:
            pass

    def _capture_worker(self, session: LiveMonitoringSession) -> None:
        """Background thread executing socket packet capture with Windows privilege detection."""
        raw_socket = None
        bind_ip = session.local_interface_ip

        # Step 1: Check Administrator Elevation explicitly
        session.is_process_elevated = is_admin_process()
        if not session.is_process_elevated:
            session.engine_status = "PERMISSION_DENIED"
            session.engine_message = (
                f"Backend server process (PID {session.backend_pid}) is running as a standard non-elevated user. "
                "Windows requires Administrator privileges for raw packet sniffing. "
                f"Please close PID {session.backend_pid} and run PowerShell as Administrator."
            )
            return

        # Step 2: Try creating the raw socket
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        except PermissionError:
            session.engine_status = "PERMISSION_DENIED"
            session.engine_message = (
                f"Permission denied creating raw socket (PID {session.backend_pid}). "
                "Ensure process is running with elevated Administrator privileges."
            )
            return
        except OSError as e:
            if getattr(e, "winerror", None) == 10013:
                session.engine_status = "PERMISSION_DENIED"
                session.engine_message = (
                    f"Windows permission error [WinError 10013] on PID {session.backend_pid}. "
                    "Process lacks Administrator elevation token."
                )
                return
            session.engine_status = "SOCKET_CREATE_FAILED"
            session.engine_message = f"Failed to create raw socket: {str(e)}"
            return

        # Step 3: Bind to local interface
        try:
            raw_socket.bind((bind_ip, 0))
            raw_socket.settimeout(1.0)
        except Exception as e:
            session.engine_status = "BIND_FAILED"
            session.engine_message = f"Failed to bind raw socket to interface {bind_ip}: {str(e)}"
            if raw_socket:
                raw_socket.close()
            return

        # Step 4: Try enabling promiscuous mode (SIO_RCVALL), but DO NOT FAIL if driver restricts it
        session.promiscuous_mode = False
        if hasattr(socket, "SIO_RCVALL"):
            try:
                raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                session.promiscuous_mode = True
            except Exception as e:
                # If Wi-Fi adapter NDIS driver restricts promiscuous mode, continue in standard host raw mode!
                logger.warning(
                    "SIO_RCVALL promiscuous mode failed on %s: %s (continuing in standard host raw-socket mode)",
                    bind_ip,
                    e,
                )

        mode_name = "promiscuous mode" if session.promiscuous_mode else "standard host raw-socket mode"
        session.engine_status = (
            "RUNNING_WITH_PROMISCUOUS_PRIVILEGES"
            if session.promiscuous_mode
            else "RUNNING_STANDARD_PRIVILEGES"
        )
        session.engine_message = f"Listening on interface {bind_ip} in {mode_name} for traffic matching {session.target_ip}"

        try:
            while not session._stop_event.is_set():
                try:
                    packet_bytes, _ = raw_socket.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break

                if not packet_bytes:
                    continue

                session.total_interface_packets += 1
                session.total_interface_bytes += len(packet_bytes)

                parsed = _parse_ipv4_packet(packet_bytes)
                if not parsed:
                    continue

                # Filter: check if packet belongs to target device
                is_target_source = parsed["src_ip"] == session.target_ip
                is_target_dest = parsed["dest_ip"] == session.target_ip

                if is_target_source or is_target_dest:
                    parsed["timestamp"] = datetime.now(timezone.utc).isoformat()
                    parsed["direction"] = "outbound" if is_target_source else "inbound"
                    session.update_analytics(parsed)

        finally:
            if raw_socket:
                try:
                    if hasattr(socket, "SIO_RCVALL") and session.promiscuous_mode:
                        raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    raw_socket.close()
                except Exception:
                    pass


# Singleton service instance
live_monitor_service = LiveMonitorService()
