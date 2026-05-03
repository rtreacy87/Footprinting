from __future__ import annotations

import re
from typing import Any

from ..models import ProtocolSecurityInfo
from .parser import Parser
from .parser_registry import register_parser


@register_parser("nmap:version")
class NmapVersionParser(Parser):
    """Parses nmap service-version output to extract SMB version banners.

    Looks for lines like:
        445/tcp  open  microsoft-ds  Samba 4.6.2 (...)
        445/tcp  open  netbios-ssn   Microsoft Windows Server 2019
    """

    def parse(self, raw_output: str) -> list[str]:
        banners: list[str] = []
        for line in raw_output.splitlines():
            if re.search(r"(139|445)/tcp\s+open", line, re.IGNORECASE):
                # Strip the port/state prefix and grab the service info
                m = re.search(
                    r"(?:139|445)/tcp\s+open\s+\S+\s+(.*)",
                    line,
                    re.IGNORECASE,
                )
                if m:
                    banner = m.group(1).strip()
                    if banner:
                        banners.append(banner)
        return banners


@register_parser("nmap:smb_scripts")
class NmapSmbScriptParser(Parser):
    """Parses nmap NSE script output for SMB security info.

    Handles output from:
        smb-security-mode, smb2-security-mode, smb-protocols, smb-os-discovery
    """

    def parse(self, raw_output: str) -> list[ProtocolSecurityInfo]:
        info = ProtocolSecurityInfo()
        # Track whether we've seen any SMB script output at all
        any_smb_output = False

        for line in raw_output.splitlines():
            # Strip nmap NSE prefix characters (|_, |, spaces)
            line_clean = re.sub(r"^[|\s_]+", "", line).strip()
            line_lower = line_clean.lower()

            if not line_clean:
                continue

            # Detect SMB script sections
            if "smb-security-mode" in line_lower or "smb2-security-mode" in line_lower:
                any_smb_output = True

            # SMB signing detection — these appear as sub-lines of smb-security-mode
            # "message_signing: disabled (dangerous, but default)"
            # "message_signing: required"
            # "Message signing enabled but not required"
            if "message_signing" in line_lower or "message signing" in line_lower:
                any_smb_output = True
                if "required" in line_lower and "not required" not in line_lower:
                    info.signing_enabled = True
                    info.signing_required = True
                elif "enabled but not required" in line_lower:
                    info.signing_enabled = True
                    info.signing_required = False
                elif "disabled" in line_lower:
                    info.signing_enabled = False
                    info.signing_required = False
                elif "required" in line_lower:
                    info.signing_enabled = True
                    info.signing_required = True

            # smb2-security-mode: "Message signing enabled but not required"
            if "signing enabled but not required" in line_lower:
                info.signing_enabled = True
                info.signing_required = False
                any_smb_output = True

            if "signing enabled and required" in line_lower or "signing required" in line_lower:
                info.signing_enabled = True
                info.signing_required = True
                any_smb_output = True

            # Protocol versions from smb-protocols
            # |     SMBv1  or  |     2.02
            if re.match(r"SMBv1", line_clean, re.IGNORECASE):
                if "SMBv1" not in info.smb_versions:
                    info.smb_versions.append("SMBv1")
                info.smb1_enabled = True
                any_smb_output = True

            m = re.match(r"(2\.\d+|3\.\d+)\s*$", line_clean)
            if m:
                ver = f"SMB {m.group(1)}"
                if ver not in info.smb_versions:
                    info.smb_versions.append(ver)
                any_smb_output = True

            # Dialect from version header lines like "3.1.1:" or "311:"
            m_dialect = re.match(r"(\d+\.\d+\.\d+|\d{3}):\s*$", line_clean)
            if m_dialect and not info.dialect:
                raw_d = m_dialect.group(1)
                # Normalise "311" -> "3.1.1"
                if re.match(r"\d{3}$", raw_d):
                    info.dialect = ".".join(raw_d)
                else:
                    info.dialect = raw_d

        # If we found any SMB2/3 version but no SMBv1, mark smb1 disabled
        has_smb2_or_3 = any("SMB 2" in v or "SMB 3" in v for v in info.smb_versions)
        if has_smb2_or_3 and info.smb1_enabled is None:
            info.smb1_enabled = False

        return [info] if (
            any_smb_output
            or info.smb_versions
            or info.signing_enabled is not None
            or info.smb1_enabled is not None
        ) else []
