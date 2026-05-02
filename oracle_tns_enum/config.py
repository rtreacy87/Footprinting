from __future__ import annotations
from pathlib import Path
from pydantic import BaseModel, Field

from .models.credential import Credential


class ScanConfig(BaseModel):
    aggressive: bool = False
    run_post_auth: bool = True
    save_raw_output: bool = True
    save_json: bool = True
    save_markdown: bool = True
    timeout_seconds: int = 120
    oracle_client_lib: str = "/usr/lib/oracle/19.6/client64/lib"

    wordlist_sids: Path = Path(__file__).parent / "wordlists" / "common_sids.txt"
    wordlist_credentials: Path = Path(__file__).parent / "wordlists" / "default_oracle_credentials.txt"

    nmap_path: str = "nmap"
    odat_path: str = "odat.py"
    hydra_path: str = "hydra"
    sqlplus_path: str = "sqlplus"


class ScanContext(BaseModel):
    model_config = {"arbitrary_types_allowed": True}

    target_host: str
    target_port: int
    config: ScanConfig = Field(default_factory=ScanConfig)
    output_base: Path = Path("output")

    tool_status: dict[str, bool] = Field(default_factory=dict)
    discovered_sids: list[str] = Field(default_factory=list)
    discovered_service_names: list[str] = Field(default_factory=list)
    valid_credentials: list[Credential] = Field(default_factory=list)
    findings: list = Field(default_factory=list)
    decision_trace: list[str] = Field(default_factory=list)
    post_auth_data: dict = Field(default_factory=dict)

    def has_connection_identifiers(self) -> bool:
        return bool(self.discovered_sids or self.discovered_service_names)

    def oracle_detected(self) -> bool:
        return self.tool_status.get("oracle_detected", False)
