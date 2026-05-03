from __future__ import annotations

CONTROL_DEFINITIONS: dict[str, dict] = {
    "CTRL-SMB-AUTH-001": {
        "name": "Anonymous SMB access disabled",
        "description": (
            "Verify that anonymous (null session) share listing is rejected "
            "by the SMB server."
        ),
    },
    "CTRL-SMB-SHARE-001": {
        "name": "No anonymous readable shares",
        "description": (
            "Verify that no SMB shares can be read without valid credentials."
        ),
    },
    "CTRL-SMB-SHARE-002": {
        "name": "No anonymous writable shares",
        "description": (
            "Verify that no SMB shares permit anonymous write access."
        ),
    },
    "CTRL-SMB-PROTO-001": {
        "name": "SMB signing enforced",
        "description": (
            "Verify that the SMB server requires message signing on all connections, "
            "preventing relay attacks."
        ),
    },
    "CTRL-SMB-PROTO-002": {
        "name": "SMBv1 disabled",
        "description": (
            "Verify that SMBv1 is not enabled on the target, eliminating exposure "
            "to EternalBlue and similar exploits."
        ),
    },
    "CTRL-SMB-DATA-001": {
        "name": "No exposed credential files",
        "description": (
            "Verify that no files containing credentials or private keys are "
            "accessible via SMB shares."
        ),
    },
    "CTRL-SMB-DATA-002": {
        "name": "No exposed backup files",
        "description": (
            "Verify that no backup or archive files are accessible via SMB shares."
        ),
    },
}
