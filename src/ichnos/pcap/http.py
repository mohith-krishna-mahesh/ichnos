"""HTTP stream and message reconstruction from TCP payloads."""

from __future__ import annotations

from typing import Any

from ichnos.pcap.parser import PCAPPacket
from ichnos.pcap.reassembly import reassemble_all_tcp_flows

HTTP_METHODS = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ")


def _parse_http_payload(
    raw: bytes,
    src_endpoint: str,
    dst_endpoint: str,
    timestamp: float,
) -> dict[str, Any] | None:
    """Parses a single HTTP message from raw payload bytes."""
    if len(raw) < 10:
        return None

    # Request
    if any(raw.startswith(m.encode("ascii")) for m in HTTP_METHODS):
        try:
            head, _, body = raw.partition(b"\r\n\r\n")
            lines = head.decode("latin-1", errors="replace").split("\r\n")
            request_line = lines[0]
            parts = request_line.split(" ", 2)
            method = parts[0]
            uri = parts[1] if len(parts) > 1 else "/"
            proto = parts[2] if len(parts) > 2 else "HTTP/1.1"

            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            host = headers.get("host", "")
            full_url = f"http://{host}{uri}" if host else uri

            return {
                "type": "request",
                "method": method,
                "uri": uri,
                "url": full_url,
                "protocol": proto,
                "headers": headers,
                "body_length": len(body),
                "body_preview": body[:128].decode("latin-1", errors="replace"),
                "src": src_endpoint,
                "dst": dst_endpoint,
                "timestamp": timestamp,
            }
        except Exception:
            return None

    # Response
    elif raw.startswith((b"HTTP/1.0 ", b"HTTP/1.1 ", b"HTTP/2.0 ")):
        try:
            head, _, body = raw.partition(b"\r\n\r\n")
            lines = head.decode("latin-1", errors="replace").split("\r\n")
            status_line = lines[0]
            status_parts = status_line.split(" ", 2)
            code = (
                int(status_parts[1]) if len(status_parts) > 1 and status_parts[1].isdigit() else 200
            )
            reason = status_parts[2] if len(status_parts) > 2 else ""

            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            return {
                "type": "response",
                "status_code": code,
                "reason": reason,
                "headers": headers,
                "content_type": headers.get("content-type", ""),
                "body_length": len(body),
                "body_preview": body[:128].decode("latin-1", errors="replace"),
                "src": src_endpoint,
                "dst": dst_endpoint,
                "timestamp": timestamp,
            }
        except Exception:
            return None

    return None


def reconstruct_http(packets: list[PCAPPacket]) -> list[dict[str, Any]]:
    """Reconstructs HTTP requests and responses using TCP stream reassembly."""
    messages: list[dict[str, Any]] = []
    seen: set[str] = set()

    # 1. First reassemble complete TCP streams to catch fragmented/out-of-order HTTP
    streams = reassemble_all_tcp_flows(packets)
    for (src_ip, sport, dst_ip, dport), stream_bytes in streams.items():
        src_ep = f"{src_ip}:{sport}"
        dst_ep = f"{dst_ip}:{dport}"
        parsed = _parse_http_payload(stream_bytes, src_ep, dst_ep, 0.0)
        if parsed:
            key = f"{parsed['type']}:{parsed.get('method') or parsed.get('status_code')}:{parsed.get('url', '')}:{parsed['body_length']}"
            if key not in seen:
                seen.add(key)
                messages.append(parsed)

    # 2. Also check individual packets for non-TCP or unreassembled flows
    for pkt in packets:
        if not pkt.payload:
            continue
        flow_key = (pkt.ip_src, pkt.sport, pkt.ip_dst, pkt.dport)
        if pkt.protocol == "TCP" and flow_key in streams:
            continue
        src_ep = f"{pkt.ip_src}:{pkt.sport}"
        dst_ep = f"{pkt.ip_dst}:{pkt.dport}"
        parsed = _parse_http_payload(pkt.payload, src_ep, dst_ep, pkt.timestamp)
        if parsed:
            key = f"{parsed['type']}:{parsed.get('method') or parsed.get('status_code')}:{parsed.get('url', '')}:{parsed['body_length']}"
            if key not in seen:
                seen.add(key)
                messages.append(parsed)

    return messages


def parse_http_messages(
    target: dict[Any, bytes] | list[PCAPPacket],
) -> list[dict[str, Any]]:
    """Parses HTTP messages from either TCP reassembled flows or packet lists."""
    if isinstance(target, list):
        return reconstruct_http(target)

    messages: list[dict[str, Any]] = []
    seen: set[str] = set()
    for key_tuple, stream_bytes in target.items():
        if len(key_tuple) >= 4:
            src_ep = f"{key_tuple[0]}:{key_tuple[1]}"
            dst_ep = f"{key_tuple[2]}:{key_tuple[3]}"
        else:
            src_ep = "unknown"
            dst_ep = "unknown"
        parsed = _parse_http_payload(stream_bytes, src_ep, dst_ep, 0.0)
        if parsed:
            m_key = f"{parsed['type']}:{parsed.get('method') or parsed.get('status_code')}:{parsed.get('url', '')}:{parsed['body_length']}"
            if m_key not in seen:
                seen.add(m_key)
                messages.append(parsed)
    return messages
