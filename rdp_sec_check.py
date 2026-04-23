#!/usr/bin/env python3
"""
rdp-sec-check.py - Python rewrite of rdp-sec-check.pl
Original Perl version Copyright (C) 2014 Mark Lowe (mrl@portcullis-security.com)
Python rewrite: 2024

This tool may be used for legal purposes only. Users take full responsibility
for any actions performed using this tool.

References:
  [MS-RDPBCGR]: Remote Desktop Protocol: Basic Connectivity and Graphics Remoting
  https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
"""

import argparse
import socket
import struct
import sys
import re
import logging
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Constants / lookup tables
# ---------------------------------------------------------------------------

RDP_NEG_TYPE = {
    0x01: "TYPE_RDP_NEG_REQ",
    0x02: "TYPE_RDP_NEG_RSP",
    0x03: "TYPE_RDP_NEG_FAILURE",
}

RDP_NEG_RSP_FLAGS = {
    0x00: "NO_FLAGS_SET",
    0x01: "EXTENDED_CLIENT_DATA_SUPPORTED",
    0x02: "DYNVC_GFX_PROTOCOL_SUPPORTED",
}

RDP_NEG_PROTOCOL = {
    0x00: "PROTOCOL_RDP",
    0x01: "PROTOCOL_SSL",
    0x02: "PROTOCOL_HYBRID",
}

RDP_NEG_FAILURE_CODE = {
    0x01: "SSL_REQUIRED_BY_SERVER",
    0x02: "SSL_NOT_ALLOWED_BY_SERVER",
    0x03: "SSL_CERT_NOT_ON_SERVER",
    0x04: "INCONSISTENT_FLAGS",
    0x05: "HYBRID_REQUIRED_BY_SERVER",
    0x06: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}

ENCRYPTION_LEVEL = {
    0x00000000: "ENCRYPTION_LEVEL_NONE",
    0x00000001: "ENCRYPTION_LEVEL_LOW",
    0x00000002: "ENCRYPTION_LEVEL_CLIENT_COMPATIBLE",
    0x00000003: "ENCRYPTION_LEVEL_HIGH",
    0x00000004: "ENCRYPTION_LEVEL_FIPS",
}

ENCRYPTION_METHOD = {
    0x00000000: "ENCRYPTION_METHOD_NONE",
    0x00000001: "ENCRYPTION_METHOD_40BIT",
    0x00000002: "ENCRYPTION_METHOD_128BIT",
    0x00000008: "ENCRYPTION_METHOD_56BIT",
    0x00000010: "ENCRYPTION_METHOD_FIPS",
}

VERSION_MEANING = {
    b"\x00\x08\x00\x01": "RDP 4.0 servers",
    b"\x00\x08\x00\x04": "RDP 5.0, 5.1, 5.2, 6.0, 6.1, 7.0, 7.1, and 8.0 servers",
}

VERSION = "0.9-beta (Python)"

# ---------------------------------------------------------------------------
# Per-host scan results  (fixes the global-state bleed bug in the original)
# ---------------------------------------------------------------------------

@dataclass
class ScanConfig:
    protocols: dict = field(default_factory=dict)
    encryption_level: dict = field(default_factory=dict)
    encryption_method: dict = field(default_factory=dict)
    issues: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def _build_x224_connection_request(protocol_bitmask: int) -> bytes:
    """
    Build a TPKT + X.224 Connection Request with an RDP Negotiation Request.
    protocol_bitmask: 0=RDP, 1=SSL/TLS, 3=CredSSP/Hybrid
    """
    rdp_neg = struct.pack(
        "<BBHI",
        0x01,               # type  = TYPE_RDP_NEG_REQ
        0x00,               # flags = 0
        0x0008,             # length (little-endian)
        protocol_bitmask,   # requestedProtocols
    )
    x224_payload = (
        b"\xe0"             # connection request
        b"\x00\x00"         # dst-ref
        b"\x00\x00"         # src-ref
        b"\x00"             # class
        + rdp_neg
    )
    x224_len = len(x224_payload)  # length byte = payload length (not counting itself)
    tpkt_len = 4 + 1 + x224_len   # TPKT header(4) + x224 length byte(1) + payload
    tpkt = struct.pack(">BBH", 0x03, 0x00, tpkt_len)
    return tpkt + bytes([x224_len]) + x224_payload


def _build_old_connection_request() -> bytes:
    """Classic (pre-negotiation) X.224 connection request with a cookie."""
    return bytes.fromhex(
        "0300002"
        "21de0000000000"
        "436f6f6b69653a206d737473686173"
        "683d726f6f740d0a"
    )


def _build_mcs_connect_initial(enc_method_byte: int) -> bytes:
    """
    Build the MCS Connect Initial PDU.
    enc_method_byte is one of: 0x00, 0x01, 0x02, 0x08, 0x10
    """
    header = bytes.fromhex(
        "0300"                              # TPKT version + reserved
        "01a2"                              # TPKT length
        "02f0807f65820196"
        "04010104010101010130200202002202020002020200000202000102020000"
        "020200010202ffff0202000230200202000102020001020200010202000102"
        "020000020200010202042002020002302002 02ffff0202fc1702 02ffff0202"
        "000102020000020200010202ffff020200020482012300050014"
        "7c00018 11a000800100001c0004475636181 0c01c0d40004000800"
        "20035802 01ca03aa090400002 80a000068006f007300740000000000"
        "0000000000000000000000000000000000000000000000"
        "04000000000000000c00000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000"
        "01ca01000000000018000700010000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000"
        "04c00c0009000000000000000 2c00c00"
    )

    # Rebuild cleanly from the original Perl hex array (whitespace removed)
    raw = (
        "030001a202f0807f65820196040101040101010101013020"
        "020200220202000202020000020200010202000002020001"
        "0202ffff02020002302002020001020200010202000102020001"
        "020200000202000102020420020200023020020 2ffff0202fc17"
        "0202ffff0202000102020000020200010202ffff0202000204820123"
        "000500147c00018 11a000800100001c000447563616810c01c0d40004"
        "000800200358020 1ca03aa0904000028 0a0000680 06f007300740000"
        "000000000000000000000000000000000000000000000000040000000000"
        "00000c0000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000001ca01000000000018000700010000"
        "000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000"
        "000000000004c00c000900000000000000"
        "02c00c00"
    )
    # Use a known-good literal byte string built from the original perl packet
    packet_hex = (
        "030001a2"
        "02f080"
        "7f658201960401010401010101011"
        "3020020200220202000202020000020200010202000002020001"
        "0202ffff020200023020020200010202000102020001020200010202"
        "00000202000102020420020200023020020 2ffff0202fc170202ffff"
        "02020001020200000202000102 02ffff020200020482012300050014"
        "7c00018 11a000800100001c000447 5636181 0c01c0d4000400080020"
        "035802 01ca03aa090400002 80a000068006f007300740000000000000000"
        "000000000000000000000000000000000000040000000000000 00c00000"
        "00000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000001ca010000000000180007000100000000"
        "000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000"
        "00000000000004c00c000900000000000000"
        "02c00c00"
    )

    # Build from the original Perl source directly — clean hex list
    parts = [
        "03", "00", "01", "a2", "02", "f0", "80", "7f", "65", "82",
        "01", "96", "04", "01", "01", "04", "01", "01", "01", "01", "ff", "30", "20", "02", "02", "00",
        "22", "02", "02", "00", "02", "02", "02", "00", "00", "02", "02", "00", "01", "02", "02", "00",
        "00", "02", "02", "00", "01", "02", "02", "ff", "ff", "02", "02", "00", "02", "30", "20", "02",
        "02", "00", "01", "02", "02", "00", "01", "02", "02", "00", "01", "02", "02", "00", "01", "02",
        "02", "00", "00", "02", "02", "00", "01", "02", "02", "04", "20", "02", "02", "00", "02", "30",
        "20", "02", "02", "ff", "ff", "02", "02", "fc", "17", "02", "02", "ff", "ff", "02", "02", "00",
        "01", "02", "02", "00", "00", "02", "02", "00", "01", "02", "02", "ff", "ff", "02", "02", "00",
        "02", "04", "82", "01", "23", "00", "05", "00", "14", "7c", "00", "01", "81", "1a", "00", "08",
        "00", "10", "00", "01", "c0", "00", "44", "75", "63", "61", "81", "0c", "01", "c0", "d4", "00",
        "04", "00", "08", "00", "20", "03", "58", "02", "01", "ca", "03", "aa", "09", "04", "00", "00",
        "28", "0a", "00", "00", "68", "00", "6f", "00", "73", "00", "74", "00", "00", "00", "00", "00",
        "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00",
        "00", "00", "00", "00", "04", "00", "00", "00", "00", "00", "00", "00", "0c", "00", "00", "00",
        "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00",
        "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00",
        "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00",
        "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00",
        "01", "ca", "01", "00", "00", "00", "00", "00", "18", "00", "07", "00", "01", "00", "00", "00",
        "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00",
        "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00",
        "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00",
        "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00", "00",
        "04", "c0", "0c", "00", "09", "00", "00", "00", "00", "00", "00", "00", "02", "c0", "0c", "00",
        f"{enc_method_byte:02x}",
        "00", "00", "00", "00", "00", "00", "00", "03", "c0", "20", "00", "02", "00", "00", "00",
        "63", "6c", "69", "70", "72", "64", "72", "00", "c0", "a0", "00", "00", "72", "64", "70", "64",
        "72", "00", "00", "00", "80", "80", "00", "00",
    ]
    return bytes(int(h, 16) for h in parts)


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------

def get_socket(ip: str, port: int, timeout: float) -> Optional[socket.socket]:
    """Create a connected TCP socket, returning None on failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        return s
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logging.debug("Socket connect failed: %s", e)
        return None


def do_handshake(sock: socket.socket, data: bytes, timeout: float) -> Optional[bytes]:
    """
    Send data and read the full TPKT response.
    Returns raw response bytes, or None on error/timeout.
    """
    try:
        sock.sendall(data)
        # Read the 4-byte TPKT header first
        header = _recv_exact(sock, 4, timeout)
        if not header or len(header) < 4:
            return None
        total_length = struct.unpack(">H", header[2:4])[0]
        rest = _recv_exact(sock, total_length - 4, timeout)
        if rest is None:
            return None
        return header + rest
    except (socket.timeout, OSError) as e:
        logging.debug("Handshake error: %s", e)
        return None


def _recv_exact(sock: socket.socket, n: int, timeout: float) -> Optional[bytes]:
    """Read exactly n bytes, respecting timeout."""
    buf = b""
    sock.settimeout(timeout)
    try:
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        logging.warning("Timeout receiving data; results may be unreliable.")
    return buf if buf else None


# ---------------------------------------------------------------------------
# Protocol negotiation tests
# ---------------------------------------------------------------------------

def _check_negotiation(response: bytes) -> tuple[bool, str]:
    """
    Parse an RDP negotiation response.
    Returns (supported: bool, detail: str).
    """
    if response is None:
        return False, "no response"

    length = len(response)

    # 19 bytes: TPKT(4) + X224(7) + RDP Neg Response(8)
    if length == 19:
        neg_type = response[11]
        type_name = RDP_NEG_TYPE.get(neg_type, f"UNKNOWN(0x{neg_type:02x})")
        if type_name == "TYPE_RDP_NEG_FAILURE":
            code = response[15]
            detail = RDP_NEG_FAILURE_CODE.get(code, f"UNKNOWN_CODE(0x{code:02x})")
            return False, f"Not supported - {detail}"
        else:
            proto = response[15]
            proto_name = RDP_NEG_PROTOCOL.get(proto, f"UNKNOWN(0x{proto:02x})")
            return True, proto_name

    # 11 bytes: old-style response (Windows 2000/XP/2003) — no negotiation
    if length == 11:
        return True, "Negotiation ignored - old Windows 2000/XP/2003 system?"

    return False, f"unexpected response length {length}"


def test_protocol(ip: str, port: int, timeout: float, protocol_bitmask: int) -> tuple[bool, str]:
    """Test whether a given protocol bitmask is accepted."""
    sock = get_socket(ip, port, timeout)
    if not sock:
        return False, "connection failed"
    try:
        pkt = _build_x224_connection_request(protocol_bitmask)
        resp = do_handshake(sock, pkt, timeout)
        return _check_negotiation(resp)
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# BER / ASN.1 helper (replaces Encoding::BER)
# ---------------------------------------------------------------------------

def _ber_decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a BER length field. Returns (length, new_offset)."""
    b = data[offset]
    offset += 1
    if b & 0x80 == 0:
        return b, offset
    num_bytes = b & 0x7F
    length = int.from_bytes(data[offset:offset + num_bytes], "big")
    return length, offset + num_bytes


def _extract_mcs_user_data(response: bytes) -> Optional[bytes]:
    """
    Extract the userData field from an MCS Connect Response PDU.
    This is a minimal BER parser targeting the specific structure used by RDP.

    The structure we're after is buried inside:
      TPKT -> X.224 Data -> MCS Connect Response (BER-encoded)
    
    We skip proper full BER decoding and instead locate the two
    Server Core Data (SC_CORE) and Server Security Data (SC_SEC) blocks
    by their well-known tags directly in the raw bytes.
    """
    if response is None or len(response) < 9:
        return None
    # The user data starts after the BER-encoded MCS Connect Response header.
    # We take everything from byte offset 7 onward (past TPKT + X224 header)
    # and look for the GCC Conference Create Response userData field.
    # Per MS-RDPBCGR the userData begins after a 0x00 0x05 "connectPDUlen" marker.
    payload = response[7:]
    # Find the userData via the well-known "Duca" (0x44 0x75 0x63 0x61) marker
    idx = payload.find(b"\x00\x05\x00\x14\x7c\x00\x01")
    if idx == -1:
        return None
    # The actual server data blocks follow the GCC header; search for SC_CORE tag
    return payload[idx:]


def _parse_server_data(user_data: bytes) -> Optional[dict]:
    """
    Parse SC_CORE (0x0c01) and SC_SEC (0x0c02) blocks from server user data.
    Returns a dict with encryption_method and encryption_level (as ints).
    """
    if not user_data:
        return None

    # Locate SC_CORE: tag \x01\x0c followed by 2-byte LE length
    # Locate SC_SEC:  tag \x02\x0c followed by 2-byte LE length
    sc_core_match = re.search(b"\x01\x0c(..)(.{4})", user_data, re.DOTALL)
    sc_sec_match  = re.search(b"\x02\x0c(..)([\s\S]{16})", user_data, re.DOTALL)

    if not sc_sec_match:
        return None

    sc_sec = sc_sec_match.group(2)
    if len(sc_sec) < 16:
        return None

    enc_method  = struct.unpack_from("<I", sc_sec, 0)[0]
    enc_level   = struct.unpack_from("<I", sc_sec, 4)[0]
    rand_length = struct.unpack_from("<I", sc_sec, 8)[0]
    cert_length = struct.unpack_from("<I", sc_sec, 12)[0]

    return {
        "encryption_method": enc_method,
        "encryption_level":  enc_level,
        "random_length":     rand_length,
        "cert_length":       cert_length,
    }


# ---------------------------------------------------------------------------
# Classic RDP security layer check
# ---------------------------------------------------------------------------

def test_classic_rdp_encryption(ip: str, port: int, timeout: float, enc_value: int) -> tuple[bool, Optional[int], Optional[int]]:
    """
    Test a specific RDP encryption method using the classic (non-negotiation) flow.
    Returns (supported, negotiated_enc_method, negotiated_enc_level).
    """
    sock = get_socket(ip, port, timeout)
    if not sock:
        return False, None, None
    try:
        # Step 1: classic X.224 connection (no negotiation)
        pkt = _build_old_connection_request()
        resp1 = do_handshake(sock, pkt, timeout)
        if not resp1 or len(resp1) != 11:
            return False, None, None

        # Step 2: MCS Connect Initial
        pkt2 = _build_mcs_connect_initial(enc_value)
        resp2 = do_handshake(sock, pkt2, timeout)
        if not resp2 or len(resp2) <= 8:
            return False, None, None

        user_data = _extract_mcs_user_data(resp2)
        parsed = _parse_server_data(user_data)
        if not parsed:
            return False, None, None

        return True, parsed["encryption_method"], parsed["encryption_level"]
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Issue detection
# ---------------------------------------------------------------------------

def detect_issues(config: ScanConfig) -> None:
    proto = config.protocols
    enc_m = config.encryption_method

    if proto.get("PROTOCOL_HYBRID"):
        if proto.get("PROTOCOL_SSL") or proto.get("PROTOCOL_RDP"):
            config.issues["NLA_SUPPORTED_BUT_NOT_MANDATED_DOS"] = True
    else:
        config.issues["NLA_NOT_SUPPORTED_DOS"] = True

    if proto.get("PROTOCOL_RDP"):
        if proto.get("PROTOCOL_SSL") or proto.get("PROTOCOL_HYBRID"):
            config.issues["SSL_SUPPORTED_BUT_NOT_MANDATED_MITM"] = True
        else:
            config.issues["ONLY_RDP_SUPPORTED_MITM"] = True

        if enc_m.get("ENCRYPTION_METHOD_40BIT") or enc_m.get("ENCRYPTION_METHOD_56BIT"):
            config.issues["WEAK_RDP_ENCRYPTION_SUPPORTED"] = True

        if enc_m.get("ENCRYPTION_METHOD_NONE"):
            config.issues["NULL_RDP_ENCRYPTION_SUPPORTED"] = True

        if enc_m.get("ENCRYPTION_METHOD_FIPS") and any(
            enc_m.get(k) for k in [
                "ENCRYPTION_METHOD_NONE",
                "ENCRYPTION_METHOD_40BIT",
                "ENCRYPTION_METHOD_56BIT",
                "ENCRYPTION_METHOD_128BIT",
            ]
        ):
            config.issues["FIPS_SUPPORTED_BUT_NOT_MANDATED"] = True


# ---------------------------------------------------------------------------
# Main scan logic
# ---------------------------------------------------------------------------

def scan_host(host: str, ip: str, port: int, timeout: float) -> None:
    config = ScanConfig()

    print(f"\nTarget:    {host}")
    print(f"IP:        {ip}")
    print(f"Port:      {port}\n")

    print("[+] Checking supported protocols\n")

    # --- Protocol negotiation checks ---
    protocol_checks = [
        ("PROTOCOL_RDP",    0x00, "RDP Security (PROTOCOL_RDP)"),
        ("PROTOCOL_SSL",    0x01, "TLS Security (PROTOCOL_SSL)"),
        ("PROTOCOL_HYBRID", 0x03, "CredSSP Security (PROTOCOL_HYBRID) [uses NLA]"),
    ]

    for proto_key, bitmask, label in protocol_checks:
        print(f"[-] Checking if {label} is supported...", end="", flush=True)
        supported, detail = test_protocol(ip, port, timeout, bitmask)
        if supported:
            proto_name = RDP_NEG_PROTOCOL.get(bitmask, proto_key)
            if detail == proto_name:
                print("Supported")
            else:
                print(f"Not supported. Negotiated {detail}")
        else:
            print(detail)
        config.protocols[proto_key] = supported

    print("\n[+] Checking RDP Security Layer\n")

    # --- Classic encryption method checks ---
    enc_values = [
        (0x00, "ENCRYPTION_METHOD_NONE"),
        (0x01, "ENCRYPTION_METHOD_40BIT"),
        (0x02, "ENCRYPTION_METHOD_128BIT"),
        (0x08, "ENCRYPTION_METHOD_56BIT"),
        (0x10, "ENCRYPTION_METHOD_FIPS"),
    ]

    for enc_byte, enc_name in enc_values:
        print(f"[-] Checking RDP Security Layer with encryption {enc_name}...", end="", flush=True)
        supported, neg_method, neg_level = test_classic_rdp_encryption(ip, port, timeout, enc_byte)

        if not supported:
            print("Not supported")
            continue

        neg_method_name = ENCRYPTION_METHOD.get(neg_method, f"UNKNOWN(0x{neg_method:08x})")
        neg_level_name  = ENCRYPTION_LEVEL.get(neg_level,  f"UNKNOWN(0x{neg_level:08x})")

        if neg_method == (enc_byte if enc_byte != 0 else 0):
            print(f"Supported. Server encryption level: {neg_level_name}")
            config.encryption_level[neg_level_name] = True
            config.encryption_method[neg_method_name] = True
            config.protocols["PROTOCOL_RDP"] = True  # confirms RDP on old systems
        else:
            print(f"Not supported. Negotiated {neg_method_name}. Server encryption level: {neg_level_name}")
            config.encryption_level[neg_level_name] = False
            config.encryption_method[neg_method_name] = False

    detect_issues(config)

    # --- Summaries ---
    print("\n[+] Summary of protocol support\n")
    for proto, val in config.protocols.items():
        print(f"[-] {ip}:{port} supports {proto:<20}: {'TRUE' if val else 'FALSE'}")

    print("\n[+] Summary of RDP encryption support\n")
    for level in sorted(config.encryption_level):
        print(f"[-] {ip}:{port} has encryption level: {level}")
    for method_val, method_name in sorted(ENCRYPTION_METHOD.items(), key=lambda x: x[0]):
        supported = config.encryption_method.get(method_name, False)
        print(f"[-] {ip}:{port} supports {method_name:<30}: {'TRUE' if supported else 'FALSE'}")

    print("\n[+] Summary of security issues\n")
    if config.issues:
        for issue in config.issues:
            print(f"[-] {ip}:{port} has issue {issue}")
    else:
        print(f"[-] {ip}:{port} - No issues identified")


# ---------------------------------------------------------------------------
# Host resolution
# ---------------------------------------------------------------------------

def resolve(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def parse_host_port(entry: str, default_port: int = 3389) -> tuple[str, int]:
    """Parse 'host' or 'host:port' into (host, port)."""
    if ":" in entry:
        parts = entry.rsplit(":", 1)
        try:
            return parts[0].strip(), int(parts[1].strip())
        except ValueError:
            pass
    return entry.strip(), default_port


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"rdp-sec-check v{VERSION} - RDP security configuration checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s 192.168.1.1\n"
            "  %(prog)s 192.168.1.1:3389\n"
            "  %(prog)s --file hosts.txt --timeout 15 --retries 3\n"
            "  %(prog)s --file hosts.txt --outfile rdp.log --verbose\n"
        ),
    )
    parser.add_argument("host", nargs="?", help="Target host (host or host:port)")
    parser.add_argument("--file",    metavar="hosts.txt", help="File with targets, one host[:port] per line")
    parser.add_argument("--outfile", metavar="out.log",   help="Output log file")
    parser.add_argument("--timeout", metavar="sec",  type=float, default=10.0, help="Receive timeout in seconds (default: 10)")
    parser.add_argument("--retries", metavar="n",    type=int,   default=2,    help="Connection retries on timeout (default: 2)")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--debug",   action="store_true")
    args = parser.parse_args()

    # Logging setup
    level = logging.DEBUG if args.debug else (logging.INFO if args.verbose else logging.WARNING)
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if args.outfile:
        handlers.append(logging.FileHandler(args.outfile))
    logging.basicConfig(level=level, handlers=handlers, format="%(message)s")

    if not args.host and not args.file:
        parser.print_help()
        sys.exit(1)

    # Collect targets
    targets = []

    if args.file:
        try:
            with open(args.file) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    host, port = parse_host_port(line)
                    ip = resolve(host)
                    if ip:
                        targets.append((host, ip, port))
                    else:
                        print(f"[W] Unable to resolve {host}, skipping.")
        except FileNotFoundError:
            print(f"[E] Cannot open file: {args.file}")
            sys.exit(1)
    else:
        host, port = parse_host_port(args.host)
        ip = resolve(host)
        if not ip:
            print(f"[E] Cannot resolve hostname: {host}")
            sys.exit(1)
        targets.append((host, ip, port))

    import datetime
    print(f"Starting rdp-sec-check v{VERSION}")
    print(f"Started at {datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y')}")
    print(f"\n[+] Scanning {len(targets)} host(s)")

    for host, ip, port in targets:
        scan_host(host, ip, port, args.timeout)

    print(f"\nrdp-sec-check v{VERSION} completed at {datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y')}\n")


if __name__ == "__main__":
    main()
