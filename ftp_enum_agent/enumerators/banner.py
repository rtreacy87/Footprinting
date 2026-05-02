from __future__ import annotations

from ..clients.ftp_client import FTPClient
from ..config import ScanConfig
from ..models import EnumerationResult, Evidence
from ..utils.hashing import sha256_text


class BannerEnumerator:
    name = "banner"

    def run(self, client: FTPClient, config: ScanConfig) -> tuple[EnumerationResult, list[Evidence], str]:
        """Returns (result, evidence_list, banner_text)."""
        evidence: list[Evidence] = []
        banner = ""
        features = ""
        system = ""

        try:
            banner = client.connect()
            features = client.get_features()
            system = client.get_system()

            raw = f"Banner: {banner}\nSYST: {system}\nFEAT:\n{features}"
            save_path = config.raw_path("banner.txt")
            save_path.write_text(raw, encoding="utf-8")

            ev = Evidence(
                evidence_id="ev-banner",
                target=config.target,
                collector="BannerEnumerator",
                command_or_action="TCP connect + SYST + FEAT",
                raw_output_path=str(save_path),
                sha256=sha256_text(raw),
                notes=f"Banner: {banner}",
            )
            evidence.append(ev)

            result = EnumerationResult(
                check_name=self.name,
                status="success",
                success=True,
                summary=f"FTP reachable. Banner: {banner}",
                details={"banner": banner, "features": features, "system": system},
                evidence_ids=["ev-banner"],
            )
        except Exception as exc:
            result = EnumerationResult(
                check_name=self.name,
                status="not_reachable",
                success=False,
                summary=f"FTP not reachable: {exc}",
                errors=[str(exc)],
            )

        return result, evidence, banner
