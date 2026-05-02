"""FTP enumeration orchestrator.

Controls flow: banner → login → listing → download → secret scan → upload → classify → report.
Each step is delegated to a single-responsibility component.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .analyzers.attack_path_classifier import AttackPathClassifier
from .analyzers.secret_scanner import DEFAULT_SCANNER_REGISTRY
from .clients.ftp_client import FTPClient
from .config import ScanConfig
from .enumerators.anonymous_login import AnonymousLoginEnumerator
from .enumerators.banner import BannerEnumerator
from .enumerators.directory_listing import DirectoryListingEnumerator
from .enumerators.download import DownloadEnumerator
from .enumerators.upload import UploadEnumerator
from .models import EnumerationResult, Evidence, ScanReport, Target
from .reporting.json_writer import JsonWriter
from .reporting.markdown_writer import MarkdownWriter


class FtpOrchestrator:
    """Runs the full FTP enumeration workflow for one target."""

    def __init__(self, config: ScanConfig) -> None:
        self._config = config

    def run(self) -> ScanReport:
        config = self._config
        target = Target(host=config.target, port=config.port, protocol=config.protocol)
        report = ScanReport(target=target)

        client = FTPClient(config.target, config.port, config.timeout, config.idle_gap)

        # --- Phase 1: Banner ---
        banner_result, banner_ev, _banner = BannerEnumerator().run(client, config)
        self._add(report, banner_result, banner_ev)

        if not banner_result.success:
            report.errors.append("FTP not reachable — aborting scan")
            target.scan_completed_at = datetime.now(timezone.utc).isoformat()
            return report

        report.ftp_reachable = True

        # --- Phase 2: Anonymous login ---
        anon_result, anon_ev = AnonymousLoginEnumerator().run(client, config)
        self._add(report, anon_result, anon_ev)
        report.anonymous_login_success = anon_result.success

        # If anonymous login failed and user credentials are provided, try them
        if not anon_result.success and config.username:
            try:
                client.login(config.username, config.password or "")
                anon_result = EnumerationResult(
                    check_name="anonymous_login",
                    status="success",
                    success=True,
                    summary=f"Authenticated as {config.username}",
                    details={"accepted_username": config.username},
                )
                report.anonymous_login_success = True
            except Exception as exc:
                report.errors.append(f"Credential login failed: {exc}")

        if not report.anonymous_login_success:
            # No valid auth — still classify and report
            self._finalize(report, config, client)
            return report

        # --- Phase 3: Enumerate (recursive listing) ---
        listing_result, listing_ev, file_inventory = DirectoryListingEnumerator().run(client, config)
        self._add(report, listing_result, listing_ev)
        report.file_inventory = file_inventory
        report.listing_allowed = listing_result.success

        # --- Phase 4: Download ---
        download_result, download_ev, downloaded = DownloadEnumerator().run(client, config, file_inventory)
        self._add(report, download_result, download_ev)
        report.downloaded_files = downloaded
        report.download_allowed = download_result.success

        # --- Phase 5: Secret scan downloaded files ---
        cred_candidates = []
        for dl_entry in downloaded:
            if dl_entry.local_path:
                cands = DEFAULT_SCANNER_REGISTRY.scan_file(Path(dl_entry.local_path))
                cred_candidates.extend(cands)
        report.credential_candidates = cred_candidates
        report.credentials_or_configs_found = bool(cred_candidates)

        if cred_candidates:
            # Add synthetic result for the check table
            report.enumeration_results.append(EnumerationResult(
                check_name="secret_scan",
                status="success",
                success=True,
                summary=f"{len(cred_candidates)} candidate(s) found",
                evidence_ids=["ev-secret-scan"],
            ))

        # --- Phase 6: Upload check ---
        writable_dirs = ["/"] + [e.path for e in file_inventory if e.is_dir]
        upload_result, upload_ev = UploadEnumerator().run(client, config, writable_dirs)
        self._add(report, upload_result, upload_ev)
        report.upload_allowed = upload_result.success

        client.close()

        self._finalize(report, config, client)
        return report

    def _add(self, report: ScanReport, result: EnumerationResult, evidence: list[Evidence]) -> None:
        report.enumeration_results.append(result)
        report.evidence.extend(evidence)

    def _finalize(self, report: ScanReport, config: ScanConfig, client: FTPClient) -> None:
        # Attack path classification
        report.findings = AttackPathClassifier().classify(
            report.enumeration_results,
            report.downloaded_files,
            report.credential_candidates,
            report.file_inventory,
        )

        report.target.scan_completed_at = datetime.now(timezone.utc).isoformat()

        # Write reports
        JsonWriter().write(report, config.normalized_path(""))
        MarkdownWriter().write(report, config.reports_path(""))
