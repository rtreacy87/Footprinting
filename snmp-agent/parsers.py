from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from oid_maps import CREDENTIAL_KEYWORDS, OID_MAP, PATH_KEYWORDS, SECTION_PREFIXES, SERVICE_KEYWORDS


@dataclass
class SnmpEntry:
    oid: str
    name: str
    type: str
    value: Any
    section: str
    raw_line: str = field(repr=False)


def normalize_oid(raw_oid: str) -> str:
    """Replace leading 'iso.' with '1.' and strip a leading '.'."""
    oid = raw_oid.strip()
    if oid.startswith("iso."):
        oid = "1." + oid[4:]
    if oid.startswith("."):
        oid = oid[1:]
    return oid


def resolve_section(oid: str) -> str:
    """Walk SECTION_PREFIXES in order; return first matching section name."""
    for prefix, section in SECTION_PREFIXES:
        if oid == prefix or oid.startswith(prefix + "."):
            return section
    return "other"


def resolve_name(oid: str) -> str:
    """
    1. Exact match in OID_MAP -> return that name.
    2. Prefix match: strip trailing '.0' sequences then check startswith prefix + '.'.
    3. Fallback: return last numeric segment of the OID.
    """
    if oid in OID_MAP:
        return OID_MAP[oid]

    for known_oid, name in OID_MAP.items():
        col = known_oid.rstrip("0").rstrip(".")
        if oid.startswith(col + "."):
            return name

    segments = oid.split(".")
    return segments[-1] if segments else oid


def parse_value(type_str: str, raw_value: str) -> Any:
    """
    Parse SNMP typed values into appropriate Python types.
    - INTEGER / Gauge32 / Counter32 / Counter64 / UInteger32 -> int
    - Timeticks -> dict {"ticks": int, "formatted": str}
    - All others -> stripped string
    """
    integer_types = {"INTEGER", "Gauge32", "Counter32", "Counter64", "UInteger32"}
    if type_str in integer_types:
        token = raw_value.strip().split()[0] if raw_value.strip() else "0"
        try:
            return int(token)
        except ValueError:
            return raw_value.strip()

    if type_str == "Timeticks":
        match = re.search(r"\((\d+)\)\s+([\d:.]+)", raw_value)
        if match:
            return {"ticks": int(match.group(1)), "formatted": match.group(2)}
        return raw_value.strip()

    # All other types: strip outer quotes and whitespace
    stripped = raw_value.strip()
    if len(stripped) >= 2 and stripped[0] == '"' and stripped[-1] == '"':
        stripped = stripped[1:-1]
    return stripped


def parse_line(line: str) -> Optional[SnmpEntry]:
    """
    Parse a single snmpwalk output line into an SnmpEntry.
    Returns None for blank lines or lines without '='.
    """
    if not line.strip() or "=" not in line:
        return None

    left, _, right = line.partition(" = ")
    raw_oid = left.strip()
    oid = normalize_oid(raw_oid)

    if ": " in right:
        type_str, _, raw_value = right.partition(": ")
        type_str = type_str.strip()
    else:
        type_str = "STRING"
        raw_value = right

    value = parse_value(type_str, raw_value)
    name = resolve_name(oid)
    section = resolve_section(oid)

    return SnmpEntry(
        oid=oid,
        name=name,
        type=type_str,
        value=value,
        section=section,
        raw_line=line,
    )


def parse_raw_output(text: str) -> List[SnmpEntry]:
    """Parse all lines of snmpwalk output, collecting non-None results."""
    entries: List[SnmpEntry] = []
    for line in text.splitlines():
        entry = parse_line(line)
        if entry is not None:
            entries.append(entry)
    return entries


def extract_system_identity(entries: List[SnmpEntry]) -> Dict[str, str]:
    """Extract key system identity fields from SNMP entries."""
    IDENTITY_OIDS = {
        "1.3.6.1.2.1.1.1.0":    "sys_descr",
        "1.3.6.1.2.1.1.3.0":    "uptime",
        "1.3.6.1.2.1.1.4.0":    "sys_contact",
        "1.3.6.1.2.1.1.5.0":    "hostname",
        "1.3.6.1.2.1.1.6.0":    "sys_location",
        "1.3.6.1.2.1.1.7.0":    "sys_services",
        "1.3.6.1.2.1.25.1.4.0": "boot_params",
    }

    identity: Dict[str, str] = {}
    for entry in entries:
        if entry.oid in IDENTITY_OIDS:
            key = IDENTITY_OIDS[entry.oid]
            if isinstance(entry.value, dict):
                identity[key] = entry.value.get("formatted", str(entry.value))
            else:
                identity[key] = str(entry.value)
    return identity


def _value_str(entry: SnmpEntry) -> str:
    """Return a string representation of an entry's value."""
    if isinstance(entry.value, dict):
        return entry.value.get("formatted", str(entry.value))
    return str(entry.value)


def extract_suspicious(entries: List[SnmpEntry]) -> List[Dict[str, str]]:
    """
    Scan entry values for credential keywords, path fragments, and service names.
    Returns list of dicts: {oid, name, value, section, reason}.
    First match per entry wins.
    """
    suspicious: List[Dict[str, str]] = []

    for entry in entries:
        val_str = _value_str(entry)
        lower = val_str.lower()
        reason: Optional[str] = None

        for kw in CREDENTIAL_KEYWORDS:
            if re.search(r'\b' + re.escape(kw) + r'\b', lower):
                reason = f"credential keyword: {kw}"
                break

        if reason is None:
            for kw in PATH_KEYWORDS:
                if kw in lower:
                    reason = f"sensitive path: {kw}"
                    break

        if reason is None:
            for kw in SERVICE_KEYWORDS:
                if re.search(r'\b' + re.escape(kw) + r'\b', lower):
                    reason = f"service keyword: {kw}"
                    break

        if reason is not None:
            suspicious.append({
                "oid": entry.oid,
                "name": entry.name,
                "value": val_str,
                "section": entry.section,
                "reason": reason,
            })

    return suspicious


def extract_wordlists(entries: List[SnmpEntry], target_ip: str) -> Dict[str, List[str]]:
    """
    Extract emails, usernames, hostnames, domains, and IPs from SNMP entries.
    Returns dict of sorted lists keyed by category name.
    """
    EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    emails: set = set()
    usernames: set = set()
    hostnames: set = set()
    domains: set = set()
    ips: set = set()

    for entry in entries:
        val_str = _value_str(entry)

        for match in EMAIL_RE.findall(val_str):
            emails.add(match)
            parts = match.split("@", 1)
            if len(parts) == 2:
                usernames.add(parts[0])
                domain = parts[1]
                domains.add(domain)
                first_segment = domain.split(".")[0]
                if first_segment:
                    hostnames.add(first_segment)

        for match in IPV4_RE.findall(val_str):
            if match != target_ip:
                ips.add(match)

    # Add sysName as a hostname
    sys_name_oid = "1.3.6.1.2.1.1.5.0"
    for entry in entries:
        if entry.oid == sys_name_oid:
            name_val = _value_str(entry).strip()
            if name_val:
                hostnames.add(name_val)
            break

    return {
        "emails":    sorted(emails),
        "usernames": sorted(usernames),
        "hostnames": sorted(hostnames),
        "domains":   sorted(domains),
        "ips":       sorted(ips),
    }


def group_by_section(entries: List[SnmpEntry]) -> Dict[str, List[Dict]]:
    """Group entries by section into lists of dicts with oid/name/type/value keys."""
    groups: Dict[str, List[Dict]] = {}
    for entry in entries:
        record = {
            "oid":   entry.oid,
            "name":  entry.name,
            "type":  entry.type,
            "value": _value_str(entry),
        }
        groups.setdefault(entry.section, []).append(record)
    return groups


def _build_attack_paths(
    identity: Dict[str, str],
    suspicious: List[Dict[str, str]],
    wordlists: Dict[str, List[str]],
    grouped: Dict[str, List[Dict]],
) -> List[Dict]:
    """Build potential attack path dicts from enumerated SNMP data."""
    paths: List[Dict] = []

    if wordlists.get("emails") or wordlists.get("usernames"):
        evidence = []
        if wordlists["emails"]:
            evidence.append(f"Emails found: {', '.join(wordlists['emails'][:5])}")
        if wordlists["usernames"]:
            evidence.append(f"Usernames found: {', '.join(wordlists['usernames'][:5])}")
        paths.append({
            "type": "username_reuse",
            "title": "Username / Credential Reuse",
            "evidence": evidence,
            "recommendation": "Use extracted usernames for password spraying and service enumeration.",
        })

    if identity.get("sys_descr") or grouped.get("installed_software"):
        evidence = []
        if identity.get("sys_descr"):
            evidence.append(f"OS/description: {identity['sys_descr'][:120]}")
        if grouped.get("installed_software"):
            evidence.append(f"Installed software entries: {len(grouped['installed_software'])}")
        paths.append({
            "type": "version_research",
            "title": "Version Research and CVE Lookup",
            "evidence": evidence,
            "recommendation": (
                "Cross-reference identified software versions against CVE databases "
                "(NVD, ExploitDB) for known vulnerabilities."
            ),
        })

    if grouped.get("ip_networking"):
        evidence = [
            f"IP/routing entries: {len(grouped['ip_networking'])}",
        ]
        if wordlists.get("ips"):
            evidence.append(f"Additional IPs discovered: {', '.join(wordlists['ips'][:10])}")
        paths.append({
            "type": "internal_network",
            "title": "Internal Network Mapping",
            "evidence": evidence,
            "recommendation": (
                "Use discovered IPs and routing entries to map internal network topology "
                "and identify further pivot targets."
            ),
        })

    credential_items = [s for s in suspicious if "credential" in s.get("reason", "")]
    if credential_items:
        evidence = [
            f"{item['name']}: {item['value'][:80]} ({item['reason']})"
            for item in credential_items[:5]
        ]
        paths.append({
            "type": "credential_exposure",
            "title": "Potential Credential Exposure",
            "evidence": evidence,
            "recommendation": (
                "Investigate flagged OID values for plaintext credentials or credential paths "
                "that may be accessible via other services."
            ),
        })

    if grouped.get("processes"):
        evidence = [
            f"Running process entries: {len(grouped['processes'])}",
        ]
        service_procs = [
            p for p in grouped["processes"]
            if any(kw in p.get("value", "").lower() for kw in SERVICE_KEYWORDS)
        ]
        if service_procs:
            evidence.append(
                f"Service-related processes: {', '.join(p['value'][:40] for p in service_procs[:5])}"
            )
        paths.append({
            "type": "process_inspection",
            "title": "Running Process Inspection",
            "evidence": evidence,
            "recommendation": (
                "Review running processes for exploitable services, debug builds, "
                "or processes running as privileged users."
            ),
        })

    return paths


def build_all_findings(
    entries: List[SnmpEntry],
    target_ip: str,
    label: str,
) -> Dict:
    """Assemble all parsed findings into a single structured dict."""
    identity = extract_system_identity(entries)
    suspicious = extract_suspicious(entries)
    wordlists = extract_wordlists(entries, target_ip)
    grouped = group_by_section(entries)
    attack_paths = _build_attack_paths(identity, suspicious, wordlists, grouped)

    return {
        "asset": {
            "ip":       target_ip,
            "label":    label,
            "hostname": identity.get("hostname", ""),
        },
        "system_identity":       identity,
        "network_interfaces":    grouped.get("network_interfaces", []),
        "ip_networking":         grouped.get("ip_networking", []),
        "tcp":                   grouped.get("tcp", []),
        "udp":                   grouped.get("udp", []),
        "processes":             grouped.get("processes", []),
        "installed_software":    grouped.get("installed_software", []),
        "storage":               grouped.get("storage", []),
        "users_contacts":        wordlists["emails"],
        "suspicious_strings":    suspicious,
        "potential_attack_paths": attack_paths,
    }
