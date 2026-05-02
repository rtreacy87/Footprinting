from __future__ import annotations

from ..clients.ftp_client import FTPClient
from ..config import ScanConfig
from ..models import EnumerationResult, Evidence
from ..utils.hashing import sha256_text


class AnonymousLoginEnumerator:
    name = "anonymous_login"

    def run(self, client: FTPClient, config: ScanConfig) -> tuple[EnumerationResult, list[Evidence]]:
        """Try each anonymous credential pair and return on first success."""
        evidence: list[Evidence] = []
        transcript_lines: list[str] = []

        for username, password in config.anonymous_credentials:
            display_pass = password if password else "(empty)"
            transcript_lines.append(f"Trying {username}/{display_pass} ...")
            try:
                client.login(username, password)
                transcript_lines.append(f"  => Login successful")

                raw = "\n".join(transcript_lines)
                save_path = config.raw_path("anonymous_login.txt")
                save_path.write_text(raw, encoding="utf-8")

                ev = Evidence(
                    evidence_id="ev-anon-login",
                    target=config.target,
                    collector="AnonymousLoginEnumerator",
                    command_or_action=f"USER {username} / PASS {display_pass}",
                    raw_output_path=str(save_path),
                    sha256=sha256_text(raw),
                    notes=f"Accepted username={username}",
                )
                evidence.append(ev)

                return EnumerationResult(
                    check_name=self.name,
                    status="success",
                    success=True,
                    summary=f"Anonymous login succeeded with {username}/{display_pass}",
                    details={
                        "accepted_username": username,
                        "accepted_password_type": "empty" if not password else "email_style",
                    },
                    evidence_ids=["ev-anon-login"],
                ), evidence

            except PermissionError:
                transcript_lines.append(f"  => Login failed")
            except Exception as exc:
                transcript_lines.append(f"  => Error: {exc}")

        raw = "\n".join(transcript_lines)
        save_path = config.raw_path("anonymous_login.txt")
        save_path.write_text(raw, encoding="utf-8")

        return EnumerationResult(
            check_name=self.name,
            status="failed",
            success=False,
            summary="Anonymous login failed with all credential pairs",
            details={"transcript": raw},
            evidence_ids=[],
        ), evidence
