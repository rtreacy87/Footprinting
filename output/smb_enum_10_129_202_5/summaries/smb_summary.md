# SMB Enumeration Summary

**Target:** `10.129.202.5`
**Profile:** `standard`
**Domain:** `DEVOPS`

## Protocol Information
- **SMB Versions:** SMB 2.1, SMB 3.0
- **Signing Enabled:** True
- **Signing Required:** False
- **SMBv1 Enabled:** False
- **Dialect:** 3.1.1
- **Banner:** `Samba smbd 4`

## Authentication Results
- **AUTH-001** (Anonymous SMB Share Listing): `VULNERABLE` — Anonymous share listing succeeded.
- **AUTH-002** (Anonymous IPC$ Access (Null Session)): `VULNERABLE` — Null session to IPC$ succeeded — anonymous RPC access allowed.
- **AUTH-003** (Credential Validation): `INCONCLUSIVE` — No credentials provided — skipping AUTH-003

## Share Access Summary
| Share | Readable | Writable | Anonymous | Comment |
|-------|----------|----------|-----------|---------|
| print$ | False | False | None | Printer Drivers |
| sambashare | True | False | True | InFreight SMB v3.1 |
| IPC$ | False | False | None | IPC Service (InlaneFreight SMB server (Samba, Ubuntu)) |

## Sensitive Files Found
No high-risk files detected.

## Attack Paths
No attack paths identified.
