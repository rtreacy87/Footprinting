"""Risk-scored findings engine for MSSQL enumeration results."""

from __future__ import annotations

from ..config import Finding


class FindingsEngine:
    def analyze(
        self,
        auth_context: dict,
        config: list[dict],
        logins: list[dict],
        role_memberships: list[dict],
        linked_servers: list[dict],
        agent_jobs: list[dict],
        agent_steps: list[dict],
        dangerous_features: list[dict],
    ) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_sysadmin(auth_context))
        findings.extend(self._check_dangerous_features(dangerous_features))
        findings.extend(self._check_linked_servers(linked_servers))
        findings.extend(self._check_agent_jobs(agent_jobs, agent_steps))
        findings.extend(self._check_disabled_sa(logins))
        return findings

    def _check_sysadmin(self, auth_context: dict) -> list[Finding]:
        if auth_context.get("is_sysadmin") == 1:
            return [Finding(
                id="MSSQL-PRIV-001",
                severity="critical",
                category="privilege",
                title="Current login has sysadmin role",
                description="The authenticated login is a member of the sysadmin server role, granting full control over the SQL Server instance.",
                evidence={"login": auth_context.get("system_user"), "is_sysadmin": 1},
                recommended_manual_check="Verify all actions permitted under engagement rules. Consider xp_cmdshell, linked servers, and credential extraction.",
            )]
        return []

    def _check_dangerous_features(self, features: list[dict]) -> list[Finding]:
        results = []
        for feat in features:
            if feat.get("enabled"):
                results.append(Finding(
                    id=f"MSSQL-EXEC-{feat['name'][:20].replace(' ', '_').upper()}",
                    severity="high",
                    category="execution_path",
                    title=f"Dangerous feature enabled: {feat['name']}",
                    description=f"The server configuration '{feat['name']}' is enabled, which may provide a path to OS-level execution or data exfiltration.",
                    evidence={"config_name": feat["name"], "value_in_use": feat.get("value_in_use")},
                    recommended_manual_check=f"Verify whether the current login can exploit '{feat['name']}' under authorized engagement rules.",
                ))
        return results

    def _check_linked_servers(self, servers: list[dict]) -> list[Finding]:
        results = []
        for srv in servers:
            if srv.get("is_rpc_out_enabled"):
                results.append(Finding(
                    id=f"MSSQL-LINK-RPC-{srv['name'][:20]}",
                    severity="high",
                    category="linked_server",
                    title=f"Linked server '{srv['name']}' has RPC Out enabled",
                    description="RPC Out on a linked server may allow executing stored procedures on the remote instance, potentially with elevated privilege.",
                    evidence={"linked_server": srv["name"], "data_source": srv.get("data_source")},
                    recommended_manual_check="Verify the security context used for the linked server and whether RPC Out can be leveraged for lateral movement.",
                ))
        return results

    def _check_agent_jobs(self, jobs: list[dict], steps: list[dict]) -> list[Finding]:
        risky_subsystems = {"CmdExec", "PowerShell", "SSIS", "ActiveScripting"}
        results = []
        for step in steps:
            if step.get("subsystem") in risky_subsystems:
                results.append(Finding(
                    id=f"MSSQL-AGENT-{step['job_name'][:15]}-{step['step_id']}",
                    severity="medium",
                    category="agent_job",
                    title=f"SQL Agent job '{step['job_name']}' uses {step['subsystem']} subsystem",
                    description="A SQL Agent job step runs commands outside the database engine. These steps may contain embedded credentials or perform privileged OS operations.",
                    evidence={"job_name": step["job_name"], "subsystem": step["subsystem"]},
                    recommended_manual_check="Review job step command for embedded credentials, network paths, or sensitive operations.",
                ))
        return results

    def _check_disabled_sa(self, logins: list[dict]) -> list[Finding]:
        for login in logins:
            if login.get("name", "").lower() == "sa":
                if login.get("is_disabled") == 0:
                    return [Finding(
                        id="MSSQL-AUTH-SA-ENABLED",
                        severity="medium",
                        category="authentication",
                        title="SA account is enabled",
                        description="The built-in 'sa' account is enabled. If it has a weak or default password it represents a high-value target.",
                        evidence={"login": "sa", "is_disabled": 0},
                        recommended_manual_check="Test SA account with common passwords only if explicitly authorized by the engagement scope.",
                    )]
        return []
