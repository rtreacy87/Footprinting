# FTP Enumeration Python Package Specification

## Purpose

Build a Python package that enumerates FTP services in a structured, repeatable way. The package should collect raw evidence, normalize findings into JSON, generate human-readable Markdown summaries, and classify whether discovered FTP behavior represents a viable attack path.

The package should support two primary consumers:

1. **Agentic decision systems** that need structured recon data to decide whether FTP offers a good next path forward.
2. **Human reporting workflows** that need clean evidence, screenshots/command output references, risk summaries, and report-ready findings.

The package should follow the same general pattern as the previously planned MySQL, MSSQL, SNMP, Oracle TNS, and IPMI enumeration packages: pull available information, preserve raw outputs, transform the data into useful structured formats, then produce a concise assessment of attack paths.

---

## Five Required FTP Enumeration Objectives

The FTP enumeration workflow must always evaluate these five core items:

1. **Try anonymous login immediately**
2. **Enumerate everything**
3. **Download everything accessible**
4. **Look for credentials and configuration files**
5. **Check for upload capability**

Each item must produce:

- A raw evidence artifact
- A normalized JSON result
- A Markdown summary section
- A vulnerability/path classification
- A recommendation for next action

---

## Package Goals

The package should answer the following questions for each target FTP service:

- Is FTP exposed and reachable?
- What banner, version, and feature information can be collected?
- Does anonymous login work?
- Can files and directories be listed?
- Can files be downloaded?
- Do downloaded files contain credentials, configuration data, internal hostnames, keys, tokens, or sensitive business data?
- Can files be uploaded?
- Can uploaded files be executed or used by another service?
- Are discovered credentials locked down, reused, or potentially valid elsewhere?
- Is FTP a useful attack path, dead end, or supporting recon source?

---

## Ethical and Scope Requirements

The package must be designed for authorized penetration testing, lab environments, and internal security validation only.

The package must include guardrails:

- Require an explicit target argument.
- Require an output directory argument or create a clearly named default output directory.
- Avoid destructive FTP commands by default.
- Do not delete, rename, or overwrite remote files unless an explicit `--unsafe-write-tests` or equivalent flag is enabled.
- Upload testing should use harmless probe files only.
- Bulk downloads should require an explicit flag or size limit.
- Preserve timestamps and raw command output for auditability.

---

## High-Level Architecture

The package should be modular and built around single-responsibility components.

Recommended package name:

`ftp_enum_agent`

Recommended structure:

---

ftp_enum_agent/
  __init__.py
  cli.py
  config.py
  models.py
  orchestrator.py
  clients/
    __init__.py
    ftp_client.py
    ftps_client.py
    external_tools.py
  enumerators/
    __init__.py
    banner.py
    anonymous_login.py
    directory_listing.py
    download.py
    upload.py
    permissions.py
    tls.py
  analyzers/
    __init__.py
    credential_scanner.py
    config_scanner.py
    secret_scanner.py
    file_classifier.py
    attack_path_classifier.py
  registries/
    __init__.py
    enumerator_registry.py
    analyzer_registry.py
    risk_registry.py
  reporting/
    __init__.py
    json_writer.py
    markdown_writer.py
    evidence_writer.py
  utils/
    __init__.py
    paths.py
    hashing.py
    logging.py
    redaction.py
    size_limits.py
tests/
  unit/
  integration/
pyproject.toml
README.md

---

## Clean Code and SOLID Requirements

The package must follow clean coding and SOLID principles.

### Single Responsibility Principle

Each class or function should do one thing:

- FTP connection handling belongs in `FTPClient`.
- Anonymous login checks belong in `AnonymousLoginEnumerator`.
- Recursive listing belongs in `DirectoryListingEnumerator`.
- File downloads belong in `DownloadEnumerator`.
- Upload checks belong in `UploadEnumerator`.
- Credential scanning belongs in `CredentialScanner`.
- Risk/path classification belongs in `AttackPathClassifier`.
- Markdown output belongs in `MarkdownWriter`.
- JSON output belongs in `JsonWriter`.

Avoid functions that both perform enumeration and make risk decisions. Enumeration collects facts. Analysis interprets facts.

### Open/Closed Principle

The package should be easy to extend without editing the orchestration flow. Add new enumerators or analyzers through registries.

Bad pattern:

---

if service == "ftp":
    run_ftp()
elif service == "ftps":
    run_ftps()
elif service == "tftp":
    run_tftp()

---

Preferred pattern:

---

registry.register("anonymous_login", AnonymousLoginEnumerator())
registry.register("directory_listing", DirectoryListingEnumerator())
registry.register("upload_check", UploadEnumerator())

for name, enumerator in registry.enabled_items(config):
    result = enumerator.run(context)

---

### Dependency Inversion

Enumerators should depend on interfaces/protocols, not concrete implementations.

For example:

- `AnonymousLoginEnumerator` should depend on a generic `FTPClientProtocol`.
- Reporting components should depend on normalized result models, not raw FTP client objects.

### Interface Segregation

Do not create one massive FTP interface. Split capabilities:

- `ConnectableClient`
- `AuthenticatableClient`
- `ListableClient`
- `DownloadableClient`
- `UploadableClient`

### Liskov Substitution

FTPS and FTP clients should be usable through the same high-level interfaces where possible.

---

## Recommended Core Data Models

Use Pydantic models or dataclasses for normalized output.

### Target Model

Fields:

- `host`
- `port`
- `protocol`
- `service_name`
- `scan_started_at`
- `scan_completed_at`
- `resolved_hostname`
- `source_scope_label`

### Evidence Model

Fields:

- `evidence_id`
- `target`
- `collector`
- `command_or_action`
- `raw_output_path`
- `timestamp`
- `sha256`
- `notes`

### Enumeration Result Model

Fields:

- `check_name`
- `status`
- `success`
- `summary`
- `details`
- `evidence_ids`
- `errors`

Recommended statuses:

- `not_tested`
- `not_reachable`
- `blocked`
- `success`
- `failed`
- `partial`
- `error`

### Attack Path Finding Model

Fields:

- `finding_id`
- `title`
- `category`
- `severity`
- `confidence`
- `is_attack_path`
- `attack_path_type`
- `description`
- `evidence_ids`
- `recommended_next_steps`
- `report_ready_summary`

Recommended severity values:

- `info`
- `low`
- `medium`
- `high`
- `critical`

Recommended confidence values:

- `low`
- `medium`
- `high`

---

## Output Directory Structure

For each target, the package should create a folder using IP or hostname as the default identifier.

---

outputs/
  10.129.14.136/
    raw/
      nmap_ftp.txt
      banner.txt
      anonymous_login.txt
      directory_listing.txt
      recursive_listing.txt
      upload_test.txt
      wget_mirror.log
    downloads/
      Calendar.pptx
      Clients/
      Documents/
      Employees/
    normalized/
      target.json
      enumeration_results.json
      findings.json
      credential_candidates.json
      config_candidates.json
      file_inventory.json
    reports/
      summary.md
      attack_paths.md
      evidence_index.md

---

## Enumeration Workflow

### Phase 1: Service Discovery and Fingerprinting

Goal: Determine whether FTP is reachable and collect initial service metadata.

Recommended checks:

- TCP connection to port 21 or provided port
- Banner grab
- Optional Nmap service scan
- Optional TLS/FTPS check
- Passive mode support check

Recommended tools:

- Python `ftplib`
- `socket`
- `nmap` optional wrapper
- `openssl s_client` for FTPS checks

Expected output:

- Banner
- Reachability status
- Service version if available
- Supported features if collected
- Evidence file containing raw connection output

Classification logic:

- FTP reachable with clear-text login: informational or low by itself
- Version disclosed in banner: informational, may become higher if vulnerable version is known
- FTPS not supported: low/medium depending on credential exposure risk

---

## Phase 2: Try Anonymous Login Immediately

Goal: Test whether anonymous authentication works.

Default credentials to test:

- username: `anonymous`, password: `anonymous@`
- username: `anonymous`, password: empty string
- username: `ftp`, password: `ftp`

The package should support custom anonymous credential attempts through configuration.

Required outputs:

- `anonymous_login.success`
- `anonymous_login.accepted_username`
- `anonymous_login.accepted_password_type`
- `anonymous_login.server_response`
- Raw login transcript

Classification logic:

| Condition | Attack Path? | Severity | Notes |
|---|---:|---|---|
| Anonymous login fails | No | Info | Continue authenticated checks only if credentials are provided. |
| Anonymous login succeeds but no listing | Maybe | Low | Access exists, but usefulness is limited. |
| Anonymous login succeeds and listing works | Yes | Medium | Strong recon path. |
| Anonymous login succeeds and files are downloadable | Yes | High | Potential data exposure. |
| Anonymous login succeeds and upload works | Yes | High/Critical | Potential write or RCE path depending on execution context. |

Agent-facing decision:

- If anonymous login succeeds, mark FTP as a priority path.
- If anonymous login fails and no credentials are available, mark FTP as a low-priority path unless banner/version suggests known weakness.

---

## Phase 3: Enumerate Everything

Goal: Collect the full visible FTP directory structure and metadata.

Required behavior:

- Run a root listing.
- Attempt recursive listing if supported.
- Traverse accessible directories manually if recursive listing is unavailable.
- Collect file names, paths, sizes, timestamps, owners/groups if exposed, and permissions if exposed.
- Detect whether user/group IDs are hidden as `ftp` or exposed numerically.

Recommended FTP commands/actions:

- `PWD`
- `SYST`
- `FEAT`
- `LIST`
- `NLST`
- Recursive `LIST -R` if supported
- Directory traversal through `CWD`

Required outputs:

- `file_inventory.json`
- `directory_listing.txt`
- `recursive_listing.txt`
- Markdown table of files and directories

Classification logic:

| Condition | Attack Path? | Severity | Notes |
|---|---:|---|---|
| Directory listing denied | No/Maybe | Info | FTP may still allow direct downloads if paths are known. |
| Listing allowed but no sensitive files | Maybe | Low | Useful for recon. |
| Listing exposes internal names/projects | Maybe | Low/Medium | Can support phishing, vhost discovery, or password guessing. |
| Listing exposes backups/configs/secrets | Yes | High | Strong path for credential discovery. |

Agent-facing decision:

- Prioritize directories with names like `backup`, `config`, `conf`, `home`, `users`, `www`, `web`, `logs`, `ssh`, `keys`, `database`, `db`, `admin`, `prod`, `dev`, `clients`, `employees`.
- Prioritize files with extensions like `.conf`, `.config`, `.ini`, `.env`, `.json`, `.yaml`, `.yml`, `.xml`, `.sql`, `.bak`, `.backup`, `.zip`, `.tar`, `.gz`, `.pem`, `.key`, `.kdbx`, `.txt`, `.docx`, `.xlsx`.

---

## Phase 4: Download Everything Accessible

Goal: Mirror accessible content while preserving evidence and avoiding unnecessary risk.

Required behavior:

- Support selective download by default.
- Support full mirroring with explicit flag.
- Enforce configurable max file size and max total download size.
- Hash every downloaded file.
- Preserve original remote path metadata.
- Avoid downloading very large files unless explicitly allowed.

Recommended tools:

- Python `ftplib`
- Optional `wget -m` wrapper

Example external tool command:

---

wget -m --no-passive ftp://anonymous:anonymous@TARGET

---

The package should not rely only on `wget`; Python-native downloads should be the default so the package can normalize metadata and handle exceptions cleanly.

Required outputs:

- Mirrored files under `downloads/`
- Download manifest
- SHA256 hashes
- Download errors
- File inventory with local path mapping

Classification logic:

| Condition | Attack Path? | Severity | Notes |
|---|---:|---|---|
| Downloads denied | Maybe | Info/Low | Listing may still be useful. |
| Public files downloadable | Maybe | Low | Depends on sensitivity. |
| Internal documents downloadable | Yes | Medium | Report as data exposure. |
| Configs/backups/keys downloadable | Yes | High/Critical | Likely direct path forward. |

Agent-facing decision:

- If download succeeds, immediately run file classifiers and secret scanners.
- If downloads fail but upload succeeds, pivot to upload testing path.
- If both download and upload fail, mark FTP as limited unless creds are available.

---

## Phase 5: Look for Credentials and Configuration Files

Goal: Identify whether downloaded or listed files contain sensitive information that enables further access.

The package should scan both:

1. **File names and metadata** before download.
2. **File contents** after download.

### Credential and Secret Indicators

Look for:

- Passwords
- API keys
- Database connection strings
- SSH private keys
- Public/private key pairs
- Cloud keys
- Tokens
- JWTs
- `.env` files
- Backup archives
- SQL dumps
- KeePass databases
- VPN configs
- Web app configs
- WordPress/Joomla/Drupal config files
- Internal hostnames
- Email addresses/usernames

### Suggested Filename Patterns

---

.env
*.conf
*.config
*.ini
*.yml
*.yaml
*.json
*.xml
*.sql
*.bak
*.backup
*.old
*.zip
*.tar
*.tar.gz
*.tgz
*.7z
id_rsa
id_dsa
id_ecdsa
id_ed25519
*.pem
*.key
*.kdbx
wp-config.php
configuration.php
settings.php
web.config
appsettings.json
application.properties

---

### Suggested Content Patterns

The package should use a registry of scanners instead of one large regex function.

Recommended scanner registry entries:

- `PasswordAssignmentScanner`
- `PrivateKeyScanner`
- `AWSKeyScanner`
- `AzureSecretScanner`
- `DatabaseConnectionStringScanner`
- `JWTScanner`
- `EmailScanner`
- `InternalHostnameScanner`
- `SSHConfigScanner`
- `WebConfigScanner`

Each scanner should return:

- matched file
- match type
- redacted value
- line number if text-based
- confidence
- evidence reference

### Credentials Locked Down or Not

The package should distinguish between credential discovery and credential usefulness.

Credential state values:

- `not_found`
- `candidate_found_not_tested`
- `candidate_found_locked_down_unknown`
- `candidate_valid_for_ftp`
- `candidate_valid_for_other_service`
- `candidate_invalid`
- `candidate_reused`
- `candidate_expired_or_disabled`

By default, the package should not automatically test credentials against other services unless explicitly configured and in scope.

For FTP-specific credential validation:

- If credentials are provided or discovered, optionally test FTP login only.
- Record whether the account is locked down through observed permissions:
  - Can login?
  - Can list?
  - Can download?
  - Can upload?
  - Chrooted to home directory?
  - Can traverse upward?

Classification logic:

| Condition | Attack Path? | Severity | Notes |
|---|---:|---|---|
| No credentials/configs found | No/Maybe | Info | FTP may still be useful for file exposure. |
| Candidate creds found but untested | Maybe | Medium | Needs validation. |
| Valid FTP creds with read access | Yes | Medium/High | Depends on file sensitivity. |
| Valid creds with write access | Yes | High | Upload/persistence path possible. |
| Reused creds across services | Yes | Critical | Direct pivot/lateral movement path. |
| SSH/private/cloud keys found | Yes | Critical | Strong path forward. |

Agent-facing decision:

- Treat private keys, database configs, and cloud credentials as high-priority next steps.
- Treat usernames and email addresses as supporting recon unless paired with passwords or hashes.
- Treat credentials as unproven until validated or manually confirmed.

---

## Phase 6: Check Upload Capability

Goal: Determine whether FTP allows file upload and whether that upload could become an attack path.

Required behavior:

- Use harmless probe files only.
- Upload to writable directories discovered during enumeration.
- Use randomized file names.
- Attempt to list the uploaded file after upload.
- Attempt to download the uploaded file to confirm write/read integrity.
- Do not delete the file unless cleanup is explicitly enabled and authorized.

Recommended probe file:

---

ftp-enum-agent-upload-test-<uuid>.txt

Content:
Authorized FTP upload capability test.
No executable payload.

---

Required outputs:

- Upload attempted: yes/no
- Upload path
- Upload success
- Can list uploaded file
- Can download uploaded file
- Cleanup status
- Raw transcript

Classification logic:

| Condition | Attack Path? | Severity | Notes |
|---|---:|---|---|
| Upload denied everywhere | No | Info | No write path found. |
| Upload allowed but not web-accessible | Maybe | Medium | Could still support staging or data tampering. |
| Upload allowed to web root | Yes | Critical | Possible web shell/RCE path if executable. |
| Upload allowed to config/automation path | Yes | High/Critical | Could affect scheduled jobs or service behavior. |
| Upload allowed with anonymous login | Yes | High/Critical | Major misconfiguration. |

Agent-facing decision:

- If upload works, check whether the FTP path maps to HTTP/SMB/NFS/web root paths discovered elsewhere.
- If upload works in a directory with scripts, templates, cron-like names, or web assets, mark as high-priority manual review.
- Do not assume RCE from upload alone. Mark RCE as possible only if execution path is confirmed or strongly evidenced.

---

## Attack Path Classifier

The `AttackPathClassifier` should consume normalized enumeration and analyzer results and produce final findings.

Example classifier rules:

### Rule: Anonymous Readable FTP

Inputs:

- Anonymous login succeeds
- Directory listing succeeds
- At least one file downloadable

Output:

- `is_attack_path: true`
- `severity: medium` or `high`
- `attack_path_type: anonymous_file_disclosure`

### Rule: Anonymous Writable FTP

Inputs:

- Anonymous login succeeds
- Upload succeeds

Output:

- `is_attack_path: true`
- `severity: high`
- `attack_path_type: anonymous_write_access`

Severity escalates to `critical` if the upload location is likely web-accessible or connected to automation.

### Rule: Credentials Found

Inputs:

- Credential scanner finds password/token/key material

Output:

- `is_attack_path: true`
- `severity: high` or `critical`
- `attack_path_type: credential_disclosure`

### Rule: Config Files Found

Inputs:

- Downloaded files include database, web app, service, SSH, VPN, or cloud config files

Output:

- `is_attack_path: true`
- `severity: medium` to `critical`
- `attack_path_type: configuration_disclosure`

### Rule: No Useful Access

Inputs:

- FTP reachable
- Anonymous login fails
- No credentials provided
- No version-specific issue identified

Output:

- `is_attack_path: false`
- `severity: info`
- `attack_path_type: none_currently_identified`

---

## Agent-Friendly JSON Output Example

---

{
  "target": {
    "host": "10.129.14.136",
    "port": 21,
    "protocol": "ftp"
  },
  "summary": {
    "ftp_reachable": true,
    "anonymous_login": true,
    "listing_allowed": true,
    "download_allowed": true,
    "credentials_or_configs_found": true,
    "upload_allowed": false,
    "best_next_action": "Review downloaded configuration files and validate discovered credential candidates within scope."
  },
  "attack_paths": [
    {
      "title": "Anonymous FTP exposes downloadable internal files",
      "is_attack_path": true,
      "severity": "high",
      "confidence": "high",
      "attack_path_type": "anonymous_file_disclosure",
      "evidence_ids": ["ev-anon-login", "ev-recursive-listing", "ev-download-manifest"]
    },
    {
      "title": "Credential candidates discovered in downloaded files",
      "is_attack_path": true,
      "severity": "high",
      "confidence": "medium",
      "attack_path_type": "credential_disclosure",
      "evidence_ids": ["ev-secret-scan"]
    }
  ]
}

---

## Markdown Report Skeleton

The package should generate `reports/summary.md` with this structure:

---

# FTP Enumeration Summary: <target>

## Executive Summary

Brief explanation of whether FTP represents a viable attack path.

## Target Information

| Field | Value |
|---|---|
| Host | <host> |
| Port | <port> |
| Protocol | FTP/FTPS |
| Banner | <banner> |
| Scan Time | <timestamp> |

## Required Checks

| Check | Result | Attack Path? | Severity | Evidence |
|---|---|---:|---|---|
| Anonymous login | <result> | <yes/no/maybe> | <severity> | <evidence_id> |
| Enumerate everything | <result> | <yes/no/maybe> | <severity> | <evidence_id> |
| Download everything accessible | <result> | <yes/no/maybe> | <severity> | <evidence_id> |
| Credentials/configs review | <result> | <yes/no/maybe> | <severity> | <evidence_id> |
| Upload capability | <result> | <yes/no/maybe> | <severity> | <evidence_id> |

## Attack Path Assessment

### Finding: <finding title>

- Severity: <severity>
- Confidence: <confidence>
- Attack Path: <yes/no>
- Evidence: <evidence IDs>
- Description: <description>
- Recommended Next Steps: <next steps>

## File Inventory Highlights

| Path | Size | Type | Reason Interesting |
|---|---:|---|---|
| <remote path> | <size> | <type> | <reason> |

## Credential and Configuration Candidates

| File | Type | Confidence | Redacted Value | Notes |
|---|---|---|---|---|
| <file> | <secret type> | <confidence> | <redacted> | <notes> |

## Evidence Index

| Evidence ID | Collector | Raw Output Path | SHA256 |
|---|---|---|---|
| <id> | <collector> | <path> | <hash> |

---

## CLI Requirements

Recommended CLI commands:

---

ftp-enum-agent scan --target 10.129.14.136 --port 21 --output outputs/
ftp-enum-agent scan --target 10.129.14.136 --anonymous-only
ftp-enum-agent scan --target 10.129.14.136 --mirror --max-total-download-mb 100
ftp-enum-agent scan --target 10.129.14.136 --check-upload
ftp-enum-agent scan --target 10.129.14.136 --username user --password pass
ftp-enum-agent report --input outputs/10.129.14.136/normalized --format markdown

---

Important CLI flags:

- `--target`
- `--port`
- `--protocol ftp|ftps`
- `--username`
- `--password`
- `--anonymous-only`
- `--mirror`
- `--max-file-size-mb`
- `--max-total-download-mb`
- `--check-upload`
- `--cleanup-upload-test`
- `--safe-mode`
- `--unsafe-write-tests`
- `--output`
- `--json`
- `--markdown`

Default behavior should be safe:

- Try anonymous login.
- Enumerate listing if login works.
- Download small text/config-like files only.
- Do not bulk mirror unless requested.
- Do not upload unless `--check-upload` is provided.

---

## External Tool Integration

External tools should be wrapped behind adapters so they are optional and replaceable.

Recommended external tools:

- `nmap` for service/version detection and FTP NSE scripts
- `wget` for optional mirroring
- `openssl` for FTPS inspection
- `grep` or Python-native scanning for quick local triage
- Optional secret scanning tool if approved, such as `trufflehog` or `gitleaks`, against downloaded files only

External tool outputs must be saved under `raw/` and referenced in the evidence index.

---

## Testing Requirements

### Unit Tests

Test each component independently:

- Anonymous login parser
- Directory listing parser
- File inventory builder
- Download manifest writer
- Upload result parser
- Credential scanners
- Config scanners
- Attack path classifier
- Markdown writer
- JSON writer

### Integration Tests

Use a local Docker or VM FTP server with controlled configurations:

1. Anonymous login disabled
2. Anonymous login enabled, listing only
3. Anonymous login enabled, downloads allowed
4. Anonymous login enabled, uploads allowed
5. Local user login with chroot enabled
6. FTPS enabled
7. Hidden IDs enabled
8. Recursive listing enabled

### Example Test Cases

#### Test: Anonymous Login Fails

Expected:

- `anonymous_login.success = false`
- `is_attack_path = false`
- Severity `info`

#### Test: Anonymous Login and Download Succeed

Expected:

- `anonymous_login.success = true`
- `download_allowed = true`
- Attack path `anonymous_file_disclosure`
- Severity at least `medium`

#### Test: Upload Succeeds

Expected:

- `upload_allowed = true`
- Attack path `anonymous_write_access` if anonymous
- Severity at least `high`

#### Test: Private Key Found

Expected:

- Secret scanner detects private key
- Attack path `credential_disclosure`
- Severity `critical`
- Secret value redacted in reports

---

## Implementation Notes

### FTP Client Wrapper

The package should not spread direct `ftplib` usage across the codebase. Create a wrapper class that handles:

- Connection
- Login
- Passive mode
- Directory listing
- Directory traversal
- Download
- Upload test
- Timeout handling
- Error normalization

### Error Handling

Normalize common FTP errors:

- Connection refused
- Timeout
- Login incorrect
- Permission denied
- Passive mode failure
- File unavailable
- Transfer aborted
- TLS negotiation failure

### Redaction

Reports must redact secrets by default.

Examples:

- Password: `P@ssw0rd123!` → `P@*********!`
- API key: show first 4 and last 4 characters only
- Private keys: never print full key material

Raw files may contain sensitive content, so the package should warn users that `outputs/` must be protected.

---

## Final Decision Output

At the end of every run, the package should produce a concise decision summary for downstream automation:

---

{
  "target": "10.129.14.136:21",
  "ftp_is_useful_path": true,
  "best_attack_path": "anonymous_file_disclosure",
  "highest_severity": "high",
  "confidence": "high",
  "next_steps": [
    "Review downloaded files for credentials and configuration data",
    "Validate discovered credential candidates within scope",
    "Check whether writable FTP directories map to web-accessible paths"
  ]
}

---

## Development Priorities

Build in this order:

1. Core models and output structure
2. FTP client wrapper
3. Anonymous login enumerator
4. Directory listing enumerator
5. Download enumerator and file inventory
6. Credential/config scanners
7. Upload capability checker
8. Attack path classifier
9. JSON and Markdown reporting
10. Tests and local FTP lab fixtures

---

## Bottom Line

This package should not merely say, “FTP is open.” It should determine whether FTP creates a practical path forward.

The final answer for each target should be clear:

- **No useful FTP path found**
- **FTP provides useful recon only**
- **FTP exposes sensitive files**
- **FTP exposes credentials/configuration**
- **FTP allows uploads and may lead to execution or tampering**

