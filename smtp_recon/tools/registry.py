from __future__ import annotations

import shutil

from .nmap_tool import NmapSmtpTool
from .openssl_tool import OpenSslTool
from .smtp_user_enum_tool import SmtpUserEnumTool
from .swaks_tool import SwaksTool

TOOL_REGISTRY = {
    "nmap": NmapSmtpTool,
    "swaks": SwaksTool,
    "openssl": OpenSslTool,
    "smtp-user-enum": SmtpUserEnumTool,
}


def is_available(tool_name: str) -> bool:
    """Return True if *tool_name* is found on PATH."""
    return shutil.which(tool_name) is not None
