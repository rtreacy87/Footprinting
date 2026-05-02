from .nmap_parser import NmapServiceDetectionParser, NmapSidBruteParser, NmapOracleBruteParser
from .odat_parser import OdatAllParser, OdatSidGuesserParser, OdatPasswordGuesserParser

PARSER_REGISTRY = {
    "nmap_service_detection": NmapServiceDetectionParser,
    "nmap_sid_brute": NmapSidBruteParser,
    "nmap_oracle_brute": NmapOracleBruteParser,
    "odat_all": OdatAllParser,
    "odat_sidguesser": OdatSidGuesserParser,
    "odat_passwordguesser": OdatPasswordGuesserParser,
}

__all__ = [
    "NmapServiceDetectionParser",
    "NmapSidBruteParser",
    "NmapOracleBruteParser",
    "OdatAllParser",
    "OdatSidGuesserParser",
    "OdatPasswordGuesserParser",
    "PARSER_REGISTRY",
]
