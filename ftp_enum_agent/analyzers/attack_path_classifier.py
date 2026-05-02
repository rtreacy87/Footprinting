from __future__ import annotations

from ..models import AttackPathFinding, CredentialCandidate, EnumerationResult, FileEntry


class AttackPathClassifier:
    """Consumes normalized enumeration results and produces risk findings."""

    def classify(
        self,
        enumeration_results: list[EnumerationResult],
        downloaded_files: list[FileEntry],
        credential_candidates: list[CredentialCandidate],
        file_inventory: list[FileEntry],
    ) -> list[AttackPathFinding]:
        findings: list[AttackPathFinding] = []
        result_map = {r.check_name: r for r in enumeration_results}

        anon = result_map.get("anonymous_login")
        listing = result_map.get("directory_listing")
        download = result_map.get("download")
        upload = result_map.get("upload")

        anon_ok = anon and anon.success
        listing_ok = listing and listing.success
        download_ok = download and download.success
        upload_ok = upload and upload.success

        # Rule: Anonymous readable FTP
        if anon_ok and listing_ok and download_ok:
            findings.append(AttackPathFinding(
                finding_id="FTP-001",
                title="Anonymous FTP Exposes Downloadable Files",
                category="file_disclosure",
                severity="high",
                confidence="high",
                is_attack_path=True,
                attack_path_type="anonymous_file_disclosure",
                description="FTP allows anonymous login, directory listing, and file download. "
                            "Internal files are accessible without authentication.",
                recommended_next_steps=[
                    "Review downloaded files for credentials and configuration data",
                    "Search for internal hostnames, usernames, and service details",
                    "Check whether writable FTP directories map to web-accessible paths",
                ],
                report_ready_summary="Anonymous FTP grants read access to internal files.",
                evidence_ids=["ev-anon-login", "ev-recursive-listing", "ev-download-manifest"],
            ))
        elif anon_ok and listing_ok:
            findings.append(AttackPathFinding(
                finding_id="FTP-001a",
                title="Anonymous FTP Allows Directory Listing",
                category="information_disclosure",
                severity="medium",
                confidence="high",
                is_attack_path=True,
                attack_path_type="anonymous_directory_listing",
                description="Anonymous login and directory listing succeed. Files are visible but download may be restricted.",
                recommended_next_steps=["Attempt targeted downloads of interesting files"],
                report_ready_summary="Anonymous FTP reveals directory structure.",
                evidence_ids=["ev-anon-login", "ev-recursive-listing"],
            ))
        elif anon_ok:
            findings.append(AttackPathFinding(
                finding_id="FTP-001b",
                title="Anonymous FTP Login Succeeds",
                category="access_control",
                severity="low",
                confidence="high",
                is_attack_path=True,
                attack_path_type="anonymous_login",
                description="Anonymous login accepted but listing or download may be restricted.",
                recommended_next_steps=["Test directory traversal with known paths"],
                report_ready_summary="Anonymous FTP login is allowed.",
                evidence_ids=["ev-anon-login"],
            ))

        # Rule: Anonymous writable FTP
        if anon_ok and upload_ok:
            findings.append(AttackPathFinding(
                finding_id="FTP-002",
                title="Anonymous FTP Allows File Upload",
                category="write_access",
                severity="high",
                confidence="high",
                is_attack_path=True,
                attack_path_type="anonymous_write_access",
                description="FTP permits anonymous upload. This may allow staging, data tampering, "
                            "or code execution if the upload path maps to an executable context.",
                recommended_next_steps=[
                    "Determine whether the upload directory is web-accessible",
                    "Check if cron/automation jobs read from the FTP upload path",
                ],
                report_ready_summary="Anonymous FTP upload is permitted — potential write path.",
                evidence_ids=["ev-anon-login", "ev-upload-test"],
            ))

        # Rule: Credentials or config files found
        if credential_candidates:
            high_conf = [c for c in credential_candidates if c.confidence == "high"]
            sev = "critical" if high_conf else "high"
            findings.append(AttackPathFinding(
                finding_id="FTP-003",
                title="Credential or Secret Material Found in Downloaded Files",
                category="credential_disclosure",
                severity=sev,
                confidence="medium" if not high_conf else "high",
                is_attack_path=True,
                attack_path_type="credential_disclosure",
                description=f"{len(credential_candidates)} credential/secret candidate(s) found in downloaded files. "
                            f"Types: {', '.join({c.match_type for c in credential_candidates})}.",
                recommended_next_steps=[
                    "Validate each credential candidate within authorized scope",
                    "Check for credential reuse across FTP, SSH, web, database services",
                ],
                report_ready_summary=f"{len(credential_candidates)} secret candidate(s) found in downloaded files.",
                evidence_ids=["ev-secret-scan"],
            ))

        # Rule: No useful access
        if not anon_ok and not credential_candidates:
            findings.append(AttackPathFinding(
                finding_id="FTP-000",
                title="No Useful FTP Access Identified",
                category="no_finding",
                severity="info",
                confidence="high",
                is_attack_path=False,
                attack_path_type="none_currently_identified",
                description="Anonymous login failed and no credentials are available. "
                            "FTP does not currently represent a viable attack path.",
                recommended_next_steps=["Check whether credentials discovered elsewhere are valid for FTP"],
                report_ready_summary="FTP is reachable but no useful access identified.",
            ))

        return findings
