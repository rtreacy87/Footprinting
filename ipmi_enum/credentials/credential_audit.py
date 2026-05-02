from __future__ import annotations

from ..context import ScanContext
from ..models import CredentialFinding
from ..tools.ipmitool import IpmiTool
from .default_credentials import DEFAULT_CREDENTIAL_REGISTRY


class CredentialAuditor:
    def __init__(self, ipmitool: IpmiTool) -> None:
        self._ipmitool = ipmitool

    def run(self, context: ScanContext, continue_on_success: bool = False) -> None:
        candidates = []

        # Build candidate list from all registered providers
        for name in DEFAULT_CREDENTIAL_REGISTRY.all_names():
            provider_cls = DEFAULT_CREDENTIAL_REGISTRY.get(name)
            provider = provider_cls()
            candidates.extend(provider.candidates())

        # Also add any user-supplied credentials
        for username, password in context.config.credentials:
            from .default_credentials import CredentialPair
            candidates.insert(0, CredentialPair(username, password, source="user_supplied"))

        for cred in candidates:
            valid = self._ipmitool.test_credential(context.target, cred.username, cred.password)
            status = "valid" if valid else "invalid"
            context.credentials.append(CredentialFinding(
                target=context.target,
                username=cred.username,
                password=cred.password if valid else None,
                status=status,
                source=cred.source,
            ))
            if valid and not continue_on_success:
                break
