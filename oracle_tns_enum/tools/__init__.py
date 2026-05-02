from .nmap import NmapTool
from .odat import OdatTool
from .hydra import HydraTool
from .tnscmd import TnsCmdTool

TOOL_REGISTRY = {
    "nmap": NmapTool,
    "odat": OdatTool,
    "hydra": HydraTool,
    "tnscmd": TnsCmdTool,
}

__all__ = ["NmapTool", "OdatTool", "HydraTool", "TnsCmdTool", "TOOL_REGISTRY"]
