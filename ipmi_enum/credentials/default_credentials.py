from __future__ import annotations

from dataclasses import dataclass

from ..core.registry import Registry


@dataclass
class CredentialPair:
    username: str
    password: str
    source: str = "known_default"


class CredentialProvider:
    vendor: str = "generic"

    def candidates(self) -> list[CredentialPair]:
        return []


DEFAULT_CREDENTIAL_REGISTRY: Registry[type[CredentialProvider]] = Registry()


@DEFAULT_CREDENTIAL_REGISTRY.register("dell_idrac")
class DellIdracCredentials(CredentialProvider):
    vendor = "Dell iDRAC"

    def candidates(self) -> list[CredentialPair]:
        return [CredentialPair("root", "calvin")]


@DEFAULT_CREDENTIAL_REGISTRY.register("supermicro")
class SupermicroCredentials(CredentialProvider):
    vendor = "Supermicro"

    def candidates(self) -> list[CredentialPair]:
        return [CredentialPair("ADMIN", "ADMIN")]


@DEFAULT_CREDENTIAL_REGISTRY.register("generic")
class GenericCredentials(CredentialProvider):
    vendor = "generic"

    def candidates(self) -> list[CredentialPair]:
        return [
            CredentialPair("admin", "admin"),
            CredentialPair("admin", "password"),
            CredentialPair("admin", ""),
            CredentialPair("root", "root"),
            CredentialPair("root", ""),
            CredentialPair("ADMIN", "ADMIN"),
        ]
