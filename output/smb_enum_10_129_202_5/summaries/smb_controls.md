# SMB Security Controls Assessment

## Passed Controls
### CTRL-SMB-SHARE-002: No anonymous writable shares
- **Status:** PASSED
- **Confidence:** high
- **Reason:** No shares were anonymously writable.
- **Evidence:** EVID-50EF47AB

### CTRL-SMB-PROTO-002: SMBv1 disabled
- **Status:** PASSED
- **Confidence:** high
- **Reason:** SMBv1 is disabled.
- **Evidence:** EVID-3B1E26F6

### CTRL-SMB-DATA-001: No exposed credential files
- **Status:** PASSED
- **Confidence:** medium
- **Reason:** No credential files found in accessible shares.

### CTRL-SMB-DATA-002: No exposed backup files
- **Status:** PASSED
- **Confidence:** medium
- **Reason:** No backup files found in accessible shares.

## Failed Controls
### CTRL-SMB-AUTH-001: Anonymous SMB access disabled
- **Status:** FAILED
- **Confidence:** high
- **Reason:** Anonymous share listing succeeded — anonymous access is enabled.
- **Evidence:** EVID-949294B4

### CTRL-SMB-SHARE-001: No anonymous readable shares
- **Status:** FAILED
- **Confidence:** high
- **Reason:** Anonymous read access to: sambashare
- **Evidence:** EVID-ED703FC2

### CTRL-SMB-PROTO-001: SMB signing enforced
- **Status:** FAILED
- **Confidence:** high
- **Reason:** SMB signing is not required — relay attacks may be viable.
- **Evidence:** EVID-A5FF4773

## Inconclusive / Not Tested
All controls were tested.

## Test Coverage
- **PROTO-001** (SMB Version Detection): `passed_vulnerable` — confidence: high
- **PROTO-002** (SMB Signing Status): `passed_vulnerable` — confidence: high
- **AUTH-001** (Anonymous SMB Share Listing): `passed_vulnerable` — confidence: high
- **AUTH-002** (Anonymous IPC$ Access (Null Session)): `passed_vulnerable` — confidence: high
- **AUTH-003** (Credential Validation): `inconclusive` — confidence: unknown
- **SHARE-001** (Enumerate Visible Shares): `passed_vulnerable` — confidence: high
- **SHARE-002** (Determine Readable Shares): `passed_vulnerable` — confidence: high
- **SHARE-003** (Determine Writable Shares): `failed_secure` — confidence: high
- **PROTO-003** (SMBv1 Enabled Check): `failed_secure` — confidence: high
- **PROTO-004** (SMB Relay Risk Check): `passed_vulnerable` — confidence: high
- **PERM-001** (Anonymous Write Check): `failed_secure` — confidence: high
- **PERM-002** (Authenticated Write Check): `inconclusive` — confidence: unknown
- **PERM-003** (World-Readable Sensitive File Check): `inconclusive` — confidence: unknown
