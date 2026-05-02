# IPMI Enumeration Package Specification

## Purpose

Build a Python package that performs structured, repeatable enumeration of IPMI/BMC services and saves both raw tool output and normalized findings. The package should behave like the MySQL/SNMP enumeration packages: pull all available metadata, preserve raw evidence, transform the evidence into JSON/Markdown, and produce an analyst-friendly summary of likely next steps.

IPMI is high-value because it provides out-of-band hardware management through the Baseboard Management Controller (BMC). Compromise of a BMC can be roughly equivalent to physical access to the server because the interface may allow power control, console access, virtual media mounting, firmware management, and OS reinstallation.

## Scope and Safety Assumptions

This package is intended for authorized internal penetration tests, labs, and defensive exposure reviews.

The default mode should be **safe enumeration only**:

- Detect IPMI exposure.
- Fingerprint protocol version and vendor hints.
- Check for known default usernames/passwords only when explicitly enabled.
- Retrieve RAKP hashes only when explicitly enabled.
- Never power cycle, reset, mount media, change configuration, create users, or open KVM sessions unless a future module is deliberately built for those actions.

The package should separate **enumeration**, **credential testing**, **hash retrieval**, and **post-auth inventory** into distinct modules so that risky actions are opt-in and auditable.

---

# Enumeration Decision Tree

## Level 0: Input Normalization

**Input options**

- Single target IP or hostname
- CIDR range
- File containing targets
- Optional credentials
- Optional username list
- Optional password list
- Optional output directory
- Optional execution profile: `passive`, `standard`, `credentialed`, `hash-audit`

**Default target key**

- Use IP address as the primary output folder name.
- Store hostname, reverse DNS, and vendor values as metadata.

---

## Level 1: Discovery

```text
Start
  |
  |-- Is UDP/623 open or open|filtered?
  |       |
  |       |-- No  -> record "IPMI not detected" and stop IPMI workflow
  |       |
  |       |-- Yes -> continue to IPMI fingerprinting
```

Primary tools:

- `nmap -sU -p623 --script ipmi-version <target>`
- Optional faster precheck: `nmap -sU -p623 --open <target>`
- Optional Metasploit version module: `auxiliary/scanner/ipmi/ipmi_version`

Record:

- Port state
- Service name, usually `asf-rmcp`
- IPMI version
- Authentication types
- Privilege/authentication level
- MAC address and vendor hint
- Raw command output

---

## Level 2: BMC Interface Expansion

```text
IPMI detected
  |
  |-- Check common BMC companion services
          |
          |-- HTTP/HTTPS web console? -> fingerprint title, cert, redirects, vendor strings
          |-- SSH?                    -> capture banner only
          |-- Telnet?                 -> capture banner only
          |-- SNMP?                   -> hand off to SNMP package or record companion service
```

Useful ports to scan around a BMC:

| Service | Ports | Purpose |
|---|---:|---|
| IPMI/RMCP | UDP 623 | Core IPMI protocol |
| HTTP | TCP 80, 8080 | Web management console |
| HTTPS | TCP 443, 8443 | Web management console |
| SSH | TCP 22 | CLI access on some BMCs |
| Telnet | TCP 23 | Legacy CLI access |
| SNMP | UDP 161 | Hardware alerts/inventory |

Primary tools:

- `nmap -sV -sC -p22,23,80,443,8080,8443 <target>`
- `nmap -sU -p161,623 <target>`
- `curl -k -I https://<target>/`
- `curl -k -L https://<target>/` with strict timeout and body size limits
- Optional: `whatweb`, `httpx`, or `wappalyzer-cli` for web console fingerprinting

Record:

- Web title
- HTTP headers
- TLS certificate subject/issuer/SANs
- Redirect paths
- Vendor clues: iLO, iDRAC, DRAC, Supermicro, MegaRAC, XClarity, IMM, CIMC
- SSH/Telnet banners only, no interactive login by default

---

## Level 3: Vendor and Platform Classification

```text
Fingerprint data collected
  |
  |-- Vendor confidently identified?
  |       |
  |       |-- Yes -> apply vendor-specific checks and default credential set
  |       |
  |       |-- No  -> apply generic IPMI checks only
```

Vendor hints may come from:

- MAC OUI
- TLS certificate fields
- HTTP title/header/body snippets
- IPMI version output
- SSH/Telnet banner
- Login page strings

Vendor examples:

| Vendor/Product | Common Indicators | Default Credential Notes |
|---|---|---|
| Dell iDRAC/DRAC | `iDRAC`, `Integrated Dell Remote Access Controller` | `root:calvin` commonly tested |
| HP/HPE iLO | `iLO`, `Hewlett Packard Enterprise` | `Administrator:<random 8-char>` often label-based |
| Supermicro IPMI | `Supermicro`, `ATEN`, `MegaRAC` | `ADMIN:ADMIN` commonly tested |
| Lenovo IMM/XClarity | `IMM`, `XClarity` | Use vendor-specific default list |
| Cisco CIMC | `Cisco Integrated Management Controller` | Use vendor-specific default list |

---

## Level 4: Default Credential Audit Optional

```text
Credential testing enabled?
  |
  |-- No -> record skipped and continue
  |
  |-- Yes
        |
        |-- Select vendor-specific credential set
        |-- Try low-volume default credential attempts
        |-- Stop on first success unless --continue-on-success is set
```

This stage should be disabled by default because it performs authentication attempts.

Recommended default checks from the writeup:

| Product | Username | Password |
|---|---|---|
| Dell iDRAC | `root` | `calvin` |
| HP iLO | `Administrator` | randomized 8-character uppercase/digit value; do not brute force by default |
| Supermicro IPMI | `ADMIN` | `ADMIN` |

Useful tools:

- Metasploit `auxiliary/scanner/ipmi/ipmi_dumphashes` with common cracking enabled
- `ipmitool -I lanplus -H <target> -U <user> -P <pass> chassis status`
- `ipmitool -I lanplus -H <target> -U <user> -P <pass> mc info`
- Optional: `ipmiutil`, `freeipmi` tools such as `ipmi-sensors`, `bmc-info`, `ipmi-chassis`

Credential testing should be implemented through a registry so that each vendor can provide credential candidates without changing core flow-control code.

---

## Level 5: RAKP Hash Retrieval Optional

```text
Hash audit enabled?
  |
  |-- No -> record skipped and continue
  |
  |-- Yes
        |
        |-- Run RAKP hash retrieval against known/default username list
        |-- Save hashes in Hashcat and John formats when possible
        |-- Optionally run bounded offline cracking profile
        |-- Record cracked credentials separately from raw hashes
```

The IPMI 2.0 RAKP flaw allows retrieval of salted password hashes for valid BMC users before authentication completes. Those hashes can be cracked offline. This is not directly fixable because it is part of the IPMI 2.0 specification, so mitigation usually means segmentation and strong unique passwords.

Primary tools:

- Metasploit `auxiliary/scanner/ipmi/ipmi_dumphashes`
- Hashcat mode `7300`
- John the Ripper if John-format output is produced

Hashcat examples to support:

```bash
hashcat -m 7300 ipmi_hashes.txt wordlist.txt
hashcat -m 7300 ipmi_hashes.txt -a 3 '?1?1?1?1?1?1?1?1' -1 '?d?u'
```

The mask attack above is specifically useful for HP iLO-style factory defaults where the password is an 8-character string of uppercase letters and digits. It should never run automatically unless the user enables a cracking profile and accepts runtime cost.

---

## Level 6: Post-Auth Inventory Optional

```text
Valid credential available?
  |
  |-- No -> skip post-auth inventory
  |
  |-- Yes
        |
        |-- Query BMC metadata
        |-- Query chassis status
        |-- Query users and privilege levels if allowed
        |-- Query sensors and event log
        |-- Do not perform state-changing actions
```

Useful `ipmitool` commands:

```bash
ipmitool -I lanplus -H <target> -U <user> -P <pass> mc info
ipmitool -I lanplus -H <target> -U <user> -P <pass> chassis status
ipmitool -I lanplus -H <target> -U <user> -P <pass> user list
ipmitool -I lanplus -H <target> -U <user> -P <pass> channel info
ipmitool -I lanplus -H <target> -U <user> -P <pass> lan print
ipmitool -I lanplus -H <target> -U <user> -P <pass> sensor
ipmitool -I lanplus -H <target> -U <user> -P <pass> sel info
ipmitool -I lanplus -H <target> -U <user> -P <pass> sel list
```

Useful FreeIPMI alternatives:

```bash
bmc-info -h <target> -u <user> -p <pass>
ipmi-chassis -h <target> -u <user> -p <pass> --get-chassis-status
ipmi-sensors -h <target> -u <user> -p <pass>
ipmi-sel -h <target> -u <user> -p <pass>
```

Post-auth inventory should produce a clear risk summary:

- BMC firmware version
- User accounts and privilege levels
- Network configuration
- Exposed management protocols
- Sensor/event log anomalies
- Evidence of default or reused credentials

---

# Package Architecture

## Proposed Package Name

`ipmi_enum`

## Directory Layout

```text
ipmi_enum/
  pyproject.toml
  README.md
  src/ipmi_enum/
    __init__.py
    cli.py
    config.py
    context.py
    models.py
    logging_config.py

    core/
      orchestrator.py
      registry.py
      runner.py
      parser.py
      errors.py
      redaction.py
      filesystem.py

    discovery/
      ipmi_discovery.py
      companion_services.py

    fingerprinting/
      vendor_classifier.py
      oui_lookup.py
      http_fingerprint.py
      tls_fingerprint.py
      banner_fingerprint.py

    tools/
      base.py
      nmap.py
      metasploit.py
      ipmitool.py
      hashcat.py
      john.py
      curl.py
      freeipmi.py

    credentials/
      default_credentials.py
      credential_audit.py
      username_sources.py

    hashes/
      rakp_dump.py
      crack_profiles.py
      hash_parsers.py

    postauth/
      inventory.py
      sensors.py
      users.py
      event_logs.py
      network_config.py

    reporting/
      json_report.py
      markdown_report.py
      finding_builder.py
      evidence_index.py

  tests/
    unit/
      test_registry.py
      test_vendor_classifier.py
      test_nmap_parser.py
      test_msf_parsers.py
      test_ipmitool_parsers.py
      test_report_schema.py
    fixtures/
      nmap_ipmi_version.txt
      msf_ipmi_version.txt
      msf_ipmi_dumphashes.txt
      ipmitool_mc_info.txt
      ipmitool_user_list.txt
```

---

# SOLID Design Rules

## Single Responsibility Principle

Each function should do one thing:

- One function builds a command.
- One function executes a command.
- One function parses one output format.
- One function writes one report artifact.
- One orchestrator coordinates flow.

Avoid functions like:

```python
run_ipmi_scan_and_parse_and_write_report()
```

Prefer:

```python
command = nmap_tool.build_command(target)
result = runner.run(command)
parsed = nmap_parser.parse(result.stdout)
report_writer.write(parsed)
```

## Open/Closed Principle

New tools, vendors, output formats, or checks should be added through registries rather than editing long `if/elif` chains.

Examples:

- Tool registry
- Parser registry
- Vendor fingerprint registry
- Credential provider registry
- Report renderer registry
- Risk finding registry

## Liskov Substitution Principle

Every tool adapter should implement the same interface:

```python
class ToolAdapter(Protocol):
    name: str
    def build(self, context: ScanContext) -> CommandSpec: ...
    def parse(self, result: CommandResult) -> ToolFinding: ...
```

The orchestrator should not care whether the tool is Nmap, Metasploit, Hashcat, or ipmitool.

## Interface Segregation Principle

Do not force every module to support every behavior.

Separate interfaces:

- `DiscoveryTool`
- `FingerprintTool`
- `CredentialAuditTool`
- `HashRetrievalTool`
- `HashCrackerTool`
- `PostAuthInventoryTool`
- `ReportRenderer`

## Dependency Inversion Principle

High-level workflows depend on abstractions, not concrete tools.

Good:

```python
class IpmiWorkflow:
    def __init__(self, discovery_tools: list[DiscoveryTool], runner: CommandRunner):
        ...
```

Bad:

```python
class IpmiWorkflow:
    def run(self):
        subprocess.run("nmap ...")
```

---

# Registry Patterns

## Tool Registry

```python
TOOL_REGISTRY = Registry[ToolAdapter]()

@TOOL_REGISTRY.register("nmap_ipmi_version")
class NmapIpmiVersionTool:
    ...

@TOOL_REGISTRY.register("msf_ipmi_version")
class MetasploitIpmiVersionTool:
    ...
```

The workflow requests tools by capability:

```python
tools = registry.by_capability("ipmi.version_fingerprint")
```

## Vendor Fingerprint Registry

```python
VENDOR_FINGERPRINTS = Registry[VendorFingerprint]()

@VENDOR_FINGERPRINTS.register("dell_idrac")
class DellIdracFingerprint:
    patterns = ["idrac", "integrated dell remote access controller", "dell"]
```

Each fingerprint returns a confidence score:

```json
{
  "vendor": "Dell iDRAC",
  "confidence": 0.92,
  "evidence": ["HTTP title contains iDRAC", "TLS subject contains Dell"]
}
```

## Default Credential Provider Registry

```python
DEFAULT_CREDENTIAL_REGISTRY = Registry[CredentialProvider]()

@DEFAULT_CREDENTIAL_REGISTRY.register("supermicro")
class SupermicroDefaultCredentials:
    def candidates(self):
        return [Credential("ADMIN", "ADMIN", source="known_default")]
```

The credential auditor should ask every matching provider for candidates instead of hardcoding defaults in the auditor.

## Parser Registry

```python
PARSER_REGISTRY = Registry[OutputParser]()

@PARSER_REGISTRY.register("nmap.ipmi-version.text")
class NmapIpmiVersionParser:
    ...
```

Each parser should return normalized models, not loose dictionaries.

---

# Core Data Models

Use Pydantic or dataclasses for strict output shapes.

## ScanContext

```python
@dataclass
class ScanContext:
    target: str
    target_id: str
    output_dir: Path
    profile: ScanProfile
    credentials: list[Credential]
    username_files: list[Path]
    password_files: list[Path]
    options: ScanOptions
```

## CommandSpec

```python
@dataclass
class CommandSpec:
    tool_name: str
    argv: list[str]
    timeout_seconds: int
    cwd: Path | None = None
    env: dict[str, str] | None = None
    sensitive_args: list[str] = field(default_factory=list)
```

## CommandResult

```python
@dataclass
class CommandResult:
    command_id: str
    tool_name: str
    return_code: int
    stdout_path: Path
    stderr_path: Path
    started_at: str
    ended_at: str
    parsed: bool = False
```

## IpmiFinding

```python
@dataclass
class IpmiFinding:
    target: str
    ipmi_detected: bool
    port: int = 623
    protocol_version: str | None = None
    user_auth: list[str] = field(default_factory=list)
    pass_auth: list[str] = field(default_factory=list)
    privilege_level: str | None = None
    vendor: str | None = None
    vendor_confidence: float | None = None
    evidence_refs: list[str] = field(default_factory=list)
```

## CredentialFinding

```python
@dataclass
class CredentialFinding:
    target: str
    username: str
    password: str | None
    status: Literal["valid", "invalid", "unknown", "hash_only", "cracked"]
    source: str
    privilege: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
```

---

# Tool Adapters

## Nmap IPMI Version Adapter

Purpose:

- Determine whether UDP/623 is open.
- Extract IPMI version and authentication capabilities.

Command:

```bash
nmap -sU --script ipmi-version -p623 <target>
```

Parser should extract:

- `623/udp open asf-rmcp`
- `Version: IPMI-2.0`
- `UserAuth`
- `PassAuth`
- `Level`
- MAC/vendor line when present

## Metasploit IPMI Version Adapter

Purpose:

- Cross-check Nmap IPMI detection.
- Retrieve auth/pass auth capabilities.

Module:

```text
auxiliary/scanner/ipmi/ipmi_version
```

Implementation approach:

- Generate a temporary `.rc` file.
- Run `msfconsole -q -r <file.rc>`.
- Save raw output.
- Parse output into normalized finding.

Example `.rc`:

```text
use auxiliary/scanner/ipmi/ipmi_version
set RHOSTS <target>
set RPORT 623
set THREADS 10
run
exit -y
```

## Metasploit IPMI Dump Hashes Adapter

Purpose:

- Retrieve RAKP hashes for valid BMC users.
- Optionally save Hashcat/John format output.

Module:

```text
auxiliary/scanner/ipmi/ipmi_dumphashes
```

Example `.rc`:

```text
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS <target>
set RPORT 623
set USER_FILE <username_file>
set PASS_FILE <password_file>
set CRACK_COMMON true
set OUTPUT_HASHCAT_FILE <output_dir>/hashes/ipmi_hashcat.txt
set OUTPUT_JOHN_FILE <output_dir>/hashes/ipmi_john.txt
run
exit -y
```

Parser should extract:

- Username
- Hash string
- Whether Metasploit cracked it
- Cracked password if available
- Output file paths

## Hashcat Adapter

Purpose:

- Crack captured IPMI hashes offline.

Modes:

- Dictionary mode
- HP iLO-style mask mode
- Rules-based mode

Command examples:

```bash
hashcat -m 7300 <hash_file> <wordlist>
hashcat -m 7300 <hash_file> -a 3 '?1?1?1?1?1?1?1?1' -1 '?d?u'
```

The adapter must:

- Require explicit enablement.
- Support timeout limits.
- Save potfile/show output.
- Never delete raw hashes.

## ipmitool Adapter

Purpose:

- Validate credentials.
- Collect post-auth inventory.

Safe commands:

```bash
ipmitool -I lanplus -H <target> -U <user> -P <pass> mc info
ipmitool -I lanplus -H <target> -U <user> -P <pass> chassis status
ipmitool -I lanplus -H <target> -U <user> -P <pass> user list
ipmitool -I lanplus -H <target> -U <user> -P <pass> channel info
ipmitool -I lanplus -H <target> -U <user> -P <pass> lan print
ipmitool -I lanplus -H <target> -U <user> -P <pass> sensor
ipmitool -I lanplus -H <target> -U <user> -P <pass> sel info
ipmitool -I lanplus -H <target> -U <user> -P <pass> sel list
```

Do not include commands such as:

- `chassis power off`
- `chassis power cycle`
- `user set password`
- `lan set`
- `mc reset`

These should be blocked by a denylist in the command runner.

## Curl/Web Fingerprint Adapter

Purpose:

- Identify web-based BMC console.
- Capture headers, redirects, page title, and small body snippets.

Commands:

```bash
curl -k -I --max-time 10 https://<target>/
curl -k -L --max-time 10 --max-filesize 1048576 https://<target>/
```

Parser should extract:

- HTTP status
- Server header
- Location redirects
- HTML title
- Vendor keywords
- TLS certificate if captured separately

## FreeIPMI Adapter Optional

Purpose:

- Provide alternative post-auth inventory collection.
- Useful when `ipmitool` output is incomplete or inconsistent.

Tools:

- `bmc-info`
- `ipmi-chassis`
- `ipmi-sensors`
- `ipmi-sel`
- `ipmi-fru`

---

# Output Design

## Folder Structure

```text
output/
  <target>/
    metadata.json
    report.md
    findings.json
    evidence_index.json

    raw/
      nmap_ipmi_version.stdout.txt
      nmap_ipmi_version.stderr.txt
      msf_ipmi_version.stdout.txt
      msf_ipmi_dumphashes.stdout.txt
      curl_https_headers.stdout.txt
      ipmitool_mc_info.stdout.txt

    parsed/
      ipmi_detection.json
      companion_services.json
      vendor_fingerprint.json
      credentials.json
      hashes.json
      postauth_inventory.json

    hashes/
      ipmi_hashcat.txt
      ipmi_john.txt
      hashcat_show.txt

    markdown/
      detection.md
      vendor.md
      credentials.md
      hashes.md
      postauth_inventory.md
```

## JSON Report Schema

```json
{
  "target": "10.129.42.195",
  "scan_profile": "standard",
  "ipmi": {
    "detected": true,
    "port": 623,
    "transport": "udp",
    "service": "asf-rmcp",
    "version": "IPMI-2.0",
    "user_auth": ["auth_msg", "auth_user", "non_null_user"],
    "pass_auth": ["password", "md5", "md2", "null"],
    "level": "2.0"
  },
  "vendor": {
    "name": "Hewlett Packard Enterprise",
    "product": "iLO",
    "confidence": 0.86,
    "evidence": ["MAC OUI", "HTTP title", "TLS certificate"]
  },
  "companion_services": [
    {"port": 443, "protocol": "tcp", "service": "https", "state": "open"}
  ],
  "credentials": [
    {
      "username": "ADMIN",
      "status": "cracked",
      "source": "rakp_hash",
      "privilege": null
    }
  ],
  "hashes": {
    "rakp_hashes_found": true,
    "hashcat_file": "hashes/ipmi_hashcat.txt",
    "john_file": "hashes/ipmi_john.txt",
    "cracked_count": 1
  },
  "risk_summary": {
    "severity": "high",
    "reasons": [
      "IPMI exposed on UDP/623",
      "IPMI 2.0 RAKP hash retrieval possible",
      "Credential cracked offline"
    ]
  },
  "evidence_refs": [
    "raw/nmap_ipmi_version.stdout.txt",
    "raw/msf_ipmi_dumphashes.stdout.txt"
  ]
}
```

## Markdown Report Sections

```text
# IPMI Enumeration Report: <target>

## Executive Summary
## Detected Services
## IPMI Fingerprint
## Vendor Classification
## Companion Management Interfaces
## Default Credential Audit
## RAKP Hash Retrieval
## Cracking Results
## Post-Auth Inventory
## Findings and Risk
## Recommended Remediation
## Raw Evidence Index
```

---

# Finding Rules

Implement findings as registered rule classes.

## Example Finding Registry

```python
FINDING_RULES = Registry[FindingRule]()

@FINDING_RULES.register("ipmi_exposed")
class IpmiExposedRule:
    severity = "medium"
    def match(self, report):
        return report.ipmi.detected
```

## Suggested Findings

| Finding | Severity | Trigger |
|---|---|---|
| IPMI exposed | Medium | UDP/623 open |
| IPMI 2.0 RAKP hash retrieval possible | High | Hash retrieved |
| Default BMC credential valid | Critical | Default credential works |
| BMC password cracked offline | Critical | Hashcat/Metasploit cracked password |
| BMC web console exposed | High | HTTP/HTTPS console available |
| Telnet exposed on BMC | High | TCP/23 open |
| Weak/reused BMC credential suspected | High | Cracked credential matches known/default or appears reused |
| Post-auth user list contains admin defaults | High | User list includes `ADMIN`, `root`, default usernames |
| Outdated firmware observed | Medium/High | Firmware version captured and matched to stale version source |

---

# Execution Profiles

## passive

- No login attempts
- No hash retrieval
- No cracking
- Discovery and fingerprinting only

Tools:

- Nmap UDP/623
- HTTP/TLS/banner fingerprinting

## standard

- Discovery
- IPMI version fingerprinting
- Companion service enumeration
- Vendor classification
- No credential attempts
- No hash retrieval

## credentialed

- Everything in `standard`
- Validate supplied credentials only
- Collect safe post-auth inventory

## hash-audit

- Everything in `standard`
- Run RAKP hash retrieval
- Save Hashcat/John files
- Optional bounded cracking profile

## default-credential-audit

- Everything in `standard`
- Try minimal vendor-specific defaults
- Stop on first success
- Optional post-auth inventory after success

---

# CLI Design

## Examples

```bash
ipmi-enum scan --target 10.129.42.195 --profile standard
ipmi-enum scan --target 10.129.42.195 --profile passive --output ./out
ipmi-enum scan --targets targets.txt --profile hash-audit --user-file users.txt --hashcat-file ./out/ipmi_hashes.txt
ipmi-enum scan --target 10.129.42.195 --profile credentialed --username ADMIN --password ADMIN
ipmi-enum report --input ./out/10.129.42.195/findings.json --format markdown
```

## Important CLI Flags

| Flag | Purpose |
|---|---|
| `--target` | Single target |
| `--targets` | File of targets |
| `--profile` | Execution profile |
| `--output` | Output directory |
| `--username` | Supplied username |
| `--password` | Supplied password |
| `--user-file` | Username list for RAKP/default audit |
| `--password-file` | Password list for default audit/cracking |
| `--enable-default-creds` | Explicitly allow default credential checks |
| `--enable-rakp` | Explicitly allow RAKP hash retrieval |
| `--enable-cracking` | Explicitly allow offline cracking |
| `--max-runtime` | Global timeout |
| `--rate-limit` | Control speed across many hosts |
| `--redact-secrets` | Redact passwords in Markdown output |

---

# Implementation Notes

## Command Runner

The command runner should:

- Accept `CommandSpec` objects only.
- Save stdout/stderr to files.
- Record start/end timestamps.
- Enforce timeouts.
- Redact sensitive arguments in logs.
- Block denylisted destructive commands.
- Return `CommandResult` objects.

## Redaction

Redact secrets from Markdown by default:

- Passwords
- Hashes, unless `--include-hashes-in-report` is set
- Session tokens
- Cookies

Raw evidence can retain full values, but the evidence index should mark files containing secrets.
Include a flag that allows hashes, passwords, Session tokens and Cookies to be included in the report when the user accepts the risk of exposing them.

## Parsing Strategy

Parsers should be tolerant of tool version differences:

- Use regex for known fields.
- Preserve unknown lines under `unparsed_lines`.
- Never fail the entire scan because one parser fails.
- Attach parser errors to the report.

## Error Handling

Use explicit error types:

- `ToolMissingError`
- `CommandTimeoutError`
- `ParseError`
- `CredentialRejectedError`
- `UnsafeCommandBlockedError`
- `UnsupportedProfileError`

The final report should include skipped tools and why they were skipped.

---

# Test Plan

## Unit Tests

- Registry registers and resolves tools by capability.
- Nmap parser extracts IPMI version and auth fields.
- Metasploit version parser extracts auth/pass auth/level.
- Metasploit dump parser extracts usernames, hashes, and cracked passwords.
- Vendor classifier combines evidence into confidence score.
- Credential provider returns correct vendor defaults.
- Report writer generates valid JSON and Markdown.
- Redactor removes passwords from Markdown.
- Command runner blocks destructive `ipmitool` commands.

## Fixture-Based Parser Tests

Store known outputs in `tests/fixtures/`:

- `nmap_ipmi_version_hp_ilo.txt`
- `msf_ipmi_version_generic.txt`
- `msf_ipmi_dumphashes_admin_admin.txt`
- `ipmitool_mc_info_supermicro.txt`
- `ipmitool_user_list.txt`
- `curl_idrac_login_page.html`

## Integration Tests

Use mocks for external tools first. Later, add optional lab tests behind an environment variable:

```bash
RUN_IPMI_LAB_TESTS=1 pytest tests/integration/
```

---

# Recommended Remediation Text for Reports

The package should generate remediation guidance based on findings:

- Restrict BMC/IPMI access to a dedicated management network.
- Block UDP/623 from user networks and the internet.
- Change all default BMC credentials.
- Use long, unique BMC passwords that are not reused elsewhere.
- Disable IPMI over LAN where not required.
- Prefer vendor-supported secure management configurations.
- Keep BMC firmware updated.
- Disable Telnet and require SSH/HTTPS where management access is necessary.
- Monitor for IPMI hash retrieval attempts and unusual BMC login activity.

---

# Build Sequence

## Phase 1: Minimum Viable Enumerator

- CLI skeleton
- Command runner
- Nmap IPMI version adapter
- JSON/Markdown output
- Basic finding rules

## Phase 2: Companion Interface Fingerprinting

- HTTP/HTTPS fingerprinting
- TLS certificate capture
- SSH/Telnet banner capture
- Vendor classifier registry

## Phase 3: Optional Hash Audit

- Metasploit `ipmi_dumphashes` adapter
- Hashcat file handling
- Hash parser
- Cracking profile abstraction

## Phase 4: Credentialed Inventory

- ipmitool adapter
- Safe command allowlist
- Post-auth inventory parsers

## Phase 5: Extensibility and Agent Review

- Stable JSON schema
- Markdown digest optimized for LLM review
- Finding rule plugin system
- Vendor plugin templates

---

# Analyst Workflow Summary

```text
1. Discover UDP/623.
2. Fingerprint IPMI version and auth capabilities.
3. Expand to BMC companion services: web, SSH, Telnet, SNMP.
4. Classify vendor/product.
5. If authorized, test minimal vendor defaults.
6. If authorized, retrieve RAKP hashes and crack offline.
7. If credentials are available, collect safe post-auth inventory.
8. Save raw evidence, normalized JSON, and Markdown summary.
9. Highlight risk: exposed BMC, default creds, cracked hashes, web console, Telnet, reused credentials.
```

The main design rule: **the orchestrator controls flow, registries control extension, and individual functions only build, run, parse, or report one thing at a time.**
