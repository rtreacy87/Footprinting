# SMB Enumeration Python Package Architecture

## Purpose

Build a Python package that performs structured SMB enumeration and produces two complementary outputs:

1. **Agent-ready recon data**: detailed JSON, raw command output, parsed evidence, validation status, and candidate attack paths.
2. **Reporting-ready summaries**: reduced markdown and JSON summaries that clearly describe both vulnerable findings and controls that appeared secure during testing.

The package must be designed for change. SMB enumeration workflows, tools, parsing rules, risk scoring, and attack path logic will evolve over time. The architecture should therefore follow clean code and SOLID principles, avoid large conditional blocks, and use registry patterns wherever possible.

---

## Core Principles

### 1. Preserve raw output

Every external tool call must save raw stdout, stderr, exit code, command metadata, and timestamp. Parsed results are useful, but raw output is the evidence source.

### 2. Separate execution, parsing, validation, and reporting

Do not combine tool execution, parsing logic, risk scoring, attack path generation, and report writing in one function or class.

Each component should do one thing.

### 3. Track what was tested, not only what was vulnerable

The system must explicitly record:

- What test was run
- What tool was used
- What evidence was collected
- Whether the control passed, failed, or was inconclusive
- Confidence level
- Why that conclusion was reached

This prevents wasted effort and creates a feedback loop when the package misses a vulnerability.

### 4. Treat attack paths as hypotheses

Attack paths should be generated from validated evidence, not assumptions. Each candidate path should reference the tests and evidence that support it.

### 5. Prefer registries over conditional-heavy orchestration

Avoid long `if/elif/else` blocks for choosing tools, parsers, tests, file classifiers, and attack path rules.

Use registries such as:

- Test registry
- Tool adapter registry
- Parser registry
- File classifier registry
- Attack path rule registry
- Reporter registry

---

## Desired Output Tree

The package should create the following output structure for each target.

---

```text
smb_enum_<target>/
├── metadata/
│   ├── target.json
│   ├── smb_version.json
│   ├── os_info.json
│   └── run_metadata.json
│
├── tests/
│   ├── authentication_tests.json
│   ├── share_tests.json
│   ├── permission_tests.json
│   ├── protocol_tests.json
│   └── test_results.json
│
├── authentication/
│   ├── anonymous_access.json
│   ├── login_attempts.json
│   └── credential_validation.json
│
├── shares/
│   ├── share_list.json
│   ├── share_permissions.json
│   ├── accessible_shares.json
│   ├── inaccessible_shares.json
│   └── share_tree/
│       └── <share_name>/
│           ├── file_index.json
│           ├── sensitive_files.json
│           ├── credentials.json
│           ├── scripts.json
│           ├── configs.json
│           ├── backups.json
│           ├── writable_locations.json
│           └── raw_listing.txt
│
├── users/
│   ├── users.json
│   ├── groups.json
│   ├── sessions.json
│   └── domain_info.json
│
├── security/
│   ├── smb_signing.json
│   ├── smb_protocols.json
│   ├── smb_vulnerabilities.json
│   └── relay_risk.json
│
├── validation/
│   ├── passed_controls.json
│   ├── failed_controls.json
│   ├── inconclusive_controls.json
│   ├── test_coverage.json
│   └── validation_summary.json
│
├── attack_paths/
│   ├── candidate_paths.json
│   ├── credential_sources.json
│   ├── lateral_movement.json
│   └── blocked_paths.json
│
├── raw/
│   ├── nmap/
│   ├── smbclient/
│   ├── smbmap/
│   ├── enum4linux/
│   ├── rpcclient/
│   ├── crackmapexec/
│   └── impacket/
│
└── summaries/
    ├── smb_summary.md
    ├── smb_controls.md
    ├── smb_findings.json
    ├── smb_risk_scores.json
    └── executive_summary.md
```

---

## Recommended Package Layout

---

```text
smb_enum/
├── pyproject.toml
├── README.md
├── src/
│   └── smb_enum/
│       ├── __init__.py
│       ├── cli.py
│       │
│       ├── core/
│       │   ├── models.py
│       │   ├── enums.py
│       │   ├── exceptions.py
│       │   ├── result.py
│       │   └── context.py
│       │
│       ├── config/
│       │   ├── settings.py
│       │   ├── defaults.py
│       │   └── tool_profiles.py
│       │
│       ├── execution/
│       │   ├── command_runner.py
│       │   ├── command_result.py
│       │   ├── tool_adapter.py
│       │   └── tool_registry.py
│       │
│       ├── tools/
│       │   ├── nmap_adapter.py
│       │   ├── smbclient_adapter.py
│       │   ├── smbmap_adapter.py
│       │   ├── enum4linux_adapter.py
│       │   ├── rpcclient_adapter.py
│       │   ├── crackmapexec_adapter.py
│       │   └── impacket_adapter.py
│       │
│       ├── testspecs/
│       │   ├── base_test.py
│       │   ├── test_registry.py
│       │   ├── authentication_tests.py
│       │   ├── share_tests.py
│       │   ├── permission_tests.py
│       │   └── protocol_tests.py
│       │
│       ├── parsers/
│       │   ├── parser.py
│       │   ├── parser_registry.py
│       │   ├── nmap_parsers.py
│       │   ├── smbclient_parsers.py
│       │   ├── smbmap_parsers.py
│       │   ├── enum4linux_parsers.py
│       │   └── rpcclient_parsers.py
│       │
│       ├── classifiers/
│       │   ├── file_classifier.py
│       │   ├── classifier_registry.py
│       │   ├── credential_classifier.py
│       │   ├── config_classifier.py
│       │   ├── script_classifier.py
│       │   └── backup_classifier.py
│       │
│       ├── validation/
│       │   ├── control.py
│       │   ├── control_registry.py
│       │   ├── validator.py
│       │   ├── evidence.py
│       │   └── coverage.py
│       │
│       ├── attack_paths/
│       │   ├── attack_path.py
│       │   ├── rule.py
│       │   ├── rule_registry.py
│       │   ├── credential_rules.py
│       │   ├── writable_share_rules.py
│       │   ├── relay_rules.py
│       │   └── lateral_movement_rules.py
│       │
│       ├── reporting/
│       │   ├── reporter.py
│       │   ├── report_registry.py
│       │   ├── markdown_reporter.py
│       │   ├── json_reporter.py
│       │   └── executive_reporter.py
│       │
│       ├── storage/
│       │   ├── output_writer.py
│       │   ├── artifact_paths.py
│       │   ├── json_store.py
│       │   ├── markdown_store.py
│       │   └── raw_store.py
│       │
│       └── orchestration/
│           ├── workflow.py
│           ├── phase.py
│           └── smb_enumerator.py
│
└── tests/
    ├── unit/
    ├── integration/
    └── fixtures/
```

---

## Major Components

## 1. CLI Layer

### File

`src/smb_enum/cli.py`

### Responsibility

Expose the package through a clean command-line interface.

### Example Commands

```bash
smb-enum scan --target 10.129.14.128
smb-enum scan --target 10.129.14.128 --username user --password pass
smb-enum scan --target 10.129.14.128 --profile safe
smb-enum scan --target 10.129.14.128 --profile full
smb-enum report --input smb_enum_10.129.14.128
```

### CLI Requirements

The CLI should accept:

- Target IP or hostname
- Optional domain
- Optional username
- Optional password
- Optional NTLM hash
- Output directory
- Tool profile
- Timeout settings
- Safe mode / aggressive mode

---

## 2. Core Data Models

### File

`src/smb_enum/core/models.py`

### Purpose

Define shared data structures used across the package.

Use dataclasses or Pydantic models. Pydantic is preferred if strict validation and JSON serialization are important.

### Suggested Models

```python
class Target:
    host: str
    ports: list[int]
    domain: str | None

class Credential:
    username: str | None
    password: str | None
    domain: str | None
    ntlm_hash: str | None
    source: str

class TestResult:
    test_id: str
    name: str
    category: str
    tool: str
    command: str
    status: str
    evidence_ids: list[str]
    confidence: str
    notes: str | None

class Evidence:
    evidence_id: str
    source_tool: str
    raw_path: str
    parsed_path: str | None
    summary: str
    confidence: str

class Share:
    name: str
    comment: str | None
    share_type: str | None
    readable: bool | None
    writable: bool | None
    anonymous_access: bool | None

class FileFinding:
    path: str
    share: str
    file_type: str
    risk_score: int
    matched_rules: list[str]
    evidence_ids: list[str]

class ControlAssessment:
    control_id: str
    name: str
    status: str
    evidence_ids: list[str]
    confidence: str
    reason: str

class AttackPath:
    path_id: str
    title: str
    description: str
    required_conditions: list[str]
    evidence_ids: list[str]
    confidence: str
    impact: str
    next_steps: list[str]
```

---

## 3. Execution Layer

### Folder

`src/smb_enum/execution/`

### Responsibility

Run external commands safely and consistently.

### Key Classes

#### `CommandRunner`

Responsible only for executing commands.

It should:

- Accept command arguments as a list, not a shell string
- Enforce timeouts
- Capture stdout and stderr
- Capture exit code
- Record start and end timestamps
- Return a `CommandResult`

It should not parse output.

#### `ToolAdapter`

Abstract interface for external tools.

Each adapter should:

- Build commands
- Know required binaries
- Know which parser should handle its output
- Return command metadata

It should not interpret security meaning.

### External Tools to Support

Minimum supported tools:

- `nmap`
- `smbclient`
- `smbmap`
- `enum4linux-ng` or `enum4linux`
- `rpcclient`
- `crackmapexec` / `netexec`
- Impacket SMB tools

### Tool Adapter Example

```python
class SmbClientAdapter(ToolAdapter):
    name = "smbclient"

    def build_list_shares_command(self, target: Target, credential: Credential | None) -> list[str]:
        ...
```

---

## 4. Test Specification Layer

### Folder

`src/smb_enum/testspecs/`

### Responsibility

Define what the package tests.

A test specification should not know how to parse every tool output. It should define:

- Test ID
- Test name
- Category
- Required tool
- Required inputs
- Expected secure condition
- Result mapping logic

### Example Test IDs

Authentication tests:

- `AUTH-001`: Anonymous share listing
- `AUTH-002`: Anonymous IPC access
- `AUTH-003`: Provided credential validation

Share tests:

- `SHARE-001`: Enumerate visible shares
- `SHARE-002`: Determine readable shares
- `SHARE-003`: Determine writable shares
- `SHARE-004`: Recursively list accessible shares

Permission tests:

- `PERM-001`: Anonymous write check
- `PERM-002`: Authenticated write check
- `PERM-003`: World-readable sensitive file check

Protocol tests:

- `PROTO-001`: SMB version detection
- `PROTO-002`: SMB signing status
- `PROTO-003`: SMBv1 enabled check
- `PROTO-004`: Relay risk check

### Test Registry Pattern

The orchestrator should not hard-code which tests exist.

Use a registry:

```python
TEST_REGISTRY = {
    "AUTH-001": AnonymousShareListingTest,
    "SHARE-001": ShareEnumerationTest,
    "PROTO-002": SmbSigningTest,
}
```

The workflow should request tests by category or profile.

---

## 5. Parser Layer

### Folder

`src/smb_enum/parsers/`

### Responsibility

Convert raw tool output into structured data.

Parsers should not run tools. Parsers should not create reports. Parsers should not decide whether something is exploitable unless that decision is purely syntactic.

### Parser Registry

```python
PARSER_REGISTRY = {
    "nmap:smb_protocols": NmapSmbProtocolParser,
    "smbclient:share_list": SmbClientShareListParser,
    "smbmap:permissions": SmbMapPermissionParser,
    "rpcclient:users": RpcClientUserParser,
}
```

### Parser Output

Parsers should return structured objects such as:

- `Share`
- `User`
- `Group`
- `ProtocolSecurityInfo`
- `FileFinding`
- `Evidence`

---

## 6. File Classification Layer

### Folder

`src/smb_enum/classifiers/`

### Responsibility

Classify discovered files into meaningful categories.

This is important because SMB shares can contain thousands of files. The package should reduce this into useful signals.

### Classifier Categories

- Credentials
- Config files
- Scripts
- Backups
- Database files
- SSH keys
- Certificates
- Logs
- Office documents
- Source code
- Deployment artifacts

### Example Classification Rules

Credentials:

- Filenames containing `password`, `passwd`, `cred`, `secret`, `token`, `key`
- File extensions such as `.kdbx`, `.key`, `.pem`, `.ppk`
- Content matches such as `password=`, `connectionString`, `AWS_SECRET_ACCESS_KEY`

Configs:

- `.conf`, `.config`, `.ini`, `.yaml`, `.yml`, `.json`, `.xml`, `.env`
- `web.config`, `appsettings.json`, `.npmrc`, `.pypirc`

Scripts:

- `.ps1`, `.bat`, `.cmd`, `.sh`, `.py`, `.pl`, `.vbs`

Backups:

- `.bak`, `.old`, `.backup`, `.zip`, `.tar`, `.gz`, `.7z`
- Names containing `backup`, `dump`, `archive`, `copy`

### Classifier Registry

```python
CLASSIFIER_REGISTRY = {
    "credentials": CredentialFileClassifier,
    "configs": ConfigFileClassifier,
    "scripts": ScriptFileClassifier,
    "backups": BackupFileClassifier,
}
```

Each classifier should implement a common interface:

```python
class FileClassifier:
    def classify(self, file_metadata: FileMetadata) -> list[FileFinding]:
        ...
```

---

## 7. Validation Layer

### Folder

`src/smb_enum/validation/`

### Responsibility

Convert test results and evidence into security control assessments.

This is the layer that answers:

- What appears secure?
- What appears vulnerable?
- What could not be confirmed?
- How confident are we?

### Required Control Statuses

Use an enum, not free text.

```python
class ControlStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    NOT_TESTED = "not_tested"
```

### Example Controls

- `CTRL-SMB-AUTH-001`: Anonymous SMB access disabled
- `CTRL-SMB-SHARE-001`: No anonymous readable shares
- `CTRL-SMB-SHARE-002`: No anonymous writable shares
- `CTRL-SMB-PROTO-001`: SMB signing enforced
- `CTRL-SMB-PROTO-002`: SMBv1 disabled
- `CTRL-SMB-DATA-001`: No exposed credential files found
- `CTRL-SMB-DATA-002`: No exposed backup files found

### Important Validation Rule

Do not mark a control as passed unless the corresponding test was actually executed and produced usable evidence.

If a scan fails, times out, or gives ambiguous output, mark the control as `inconclusive`, not `passed`.

---

## 8. Attack Path Layer

### Folder

`src/smb_enum/attack_paths/`

### Responsibility

Generate candidate attack paths from validated evidence.

Attack paths should reference:

- Required conditions
- Evidence IDs
- Confidence
- Impact
- Suggested next steps

### Example Attack Path Rules

#### Anonymous Readable Share

Condition:

- Anonymous access succeeded
- At least one readable share exists

Possible path:

- Anonymous SMB access to exposed share
- Download sensitive files
- Search for credentials

#### Writable Share

Condition:

- Share is writable
- Scripts or executable paths are present

Possible path:

- Upload payload or modify script
- Wait for scheduled execution or user interaction

#### Credential Leakage

Condition:

- Credential-like files discovered
- Extracted credential has medium or high confidence

Possible path:

- Validate credential
- Use credential against SMB, WinRM, MSSQL, RDP, or LDAP

#### SMB Relay Risk

Condition:

- SMB signing is not required
- Authentication surface exists

Possible path:

- Relay captured authentication to SMB-compatible services

### Blocked Paths

The package should also produce `blocked_paths.json`.

Example:

```json
[
  {
    "path": "Anonymous SMB share access",
    "blocked_by": ["CTRL-SMB-AUTH-001"],
    "reason": "Anonymous login was denied",
    "confidence": "high"
  }
]
```

This helps both agents and human operators avoid repeating tests that already failed.

---

## 9. Reporting Layer

### Folder

`src/smb_enum/reporting/`

### Responsibility

Create human-readable and machine-readable reports.

Reporting should consume structured results. It should not run tools or parse raw outputs.

### Required Reports

#### `summaries/smb_summary.md`

Audience: technical operator.

Should include:

- Target
- SMB version and OS information
- Authentication results
- Share access summary
- Sensitive files found
- Candidate attack paths
- Recommended next actions

#### `summaries/smb_controls.md`

Audience: report writer / assessor.

Should include:

- Passed controls
- Failed controls
- Inconclusive controls
- Test coverage
- Evidence references

#### `summaries/executive_summary.md`

Audience: non-technical stakeholders.

Should include:

- High-level risk
- Business impact
- Most important remediation steps
- What was tested and appeared secure

#### `summaries/smb_findings.json`

Machine-readable summary of findings.

#### `summaries/smb_risk_scores.json`

Machine-readable scoring output.

---

## 10. Storage Layer

### Folder

`src/smb_enum/storage/`

### Responsibility

Write outputs consistently to the expected file tree.

The storage layer should abstract file paths so business logic does not manually construct output paths everywhere.

### Key Classes

#### `ArtifactPaths`

Responsible for creating and resolving output paths.

#### `JsonStore`

Responsible for JSON writes and reads.

#### `RawStore`

Responsible for raw command output.

#### `MarkdownStore`

Responsible for markdown output.

---

## Enumeration Workflow

The main workflow should be implemented in `orchestration/smb_enumerator.py`.

### Recommended Phases

1. Initialize target context
2. Create output directory tree
3. Run metadata and protocol discovery
4. Test anonymous access
5. Enumerate share list
6. Test share read/write permissions
7. Recursively enumerate accessible shares
8. Classify discovered files
9. Enumerate users, groups, sessions, and domain info where possible
10. Validate security controls
11. Generate candidate and blocked attack paths
12. Generate reports

### Workflow Rule

Each phase should consume structured input and produce structured output.

Avoid passing raw strings between phases unless the phase is explicitly responsible for parsing raw command output.

---

## Test Profiles

The package should support profiles so that enumeration can be adjusted to scope and engagement rules.

### `safe`

Low-noise enumeration.

Includes:

- Version detection
- Anonymous access check
- Share listing
- Basic permissions
- No brute force
- No exploit checks

### `standard`

Default mode.

Includes:

- Everything in `safe`
- Recursive listing of accessible shares
- File classification
- User and group enumeration where allowed
- SMB signing and SMBv1 checks

### `full`

More complete enumeration.

Includes:

- Everything in `standard`
- Deeper recursive enumeration
- Credential validation if credentials are found and validation is permitted
- More expensive Nmap NSE scripts

### `custom`

Allow user-defined test selection.

---

## Example Test Result Object

```json
{
  "test_id": "AUTH-001",
  "name": "Anonymous SMB Share Listing",
  "category": "authentication",
  "tool": "smbclient",
  "command": "smbclient -L //10.129.14.128 -N",
  "status": "failed_secure",
  "expected_secure_result": "Access denied",
  "actual_result": "NT_STATUS_ACCESS_DENIED",
  "evidence_ids": ["EVID-0001"],
  "confidence": "high",
  "notes": "Anonymous share listing was denied."
}
```

---

## Example Passed Control Object

```json
{
  "control_id": "CTRL-SMB-AUTH-001",
  "name": "Anonymous SMB access disabled",
  "status": "passed",
  "evidence_ids": ["EVID-0001"],
  "confidence": "high",
  "reason": "Anonymous share listing returned access denied."
}
```

---

## Example Failed Control Object

```json
{
  "control_id": "CTRL-SMB-SHARE-002",
  "name": "No anonymous writable shares",
  "status": "failed",
  "evidence_ids": ["EVID-0014", "EVID-0015"],
  "confidence": "high",
  "reason": "The Public share allowed anonymous write access."
}
```

---

## Example Attack Path Object

```json
{
  "path_id": "PATH-SMB-001",
  "title": "Anonymous writable SMB share",
  "description": "The target exposes a writable SMB share to anonymous users. This may allow payload staging, script replacement, or data tampering depending on how the share is used.",
  "required_conditions": [
    "CTRL-SMB-AUTH-001 failed",
    "CTRL-SMB-SHARE-002 failed"
  ],
  "evidence_ids": ["EVID-0014", "EVID-0015"],
  "confidence": "high",
  "impact": "Potential staging point, data exposure, or remote code execution if files are executed by users or services.",
  "next_steps": [
    "Review writable share contents",
    "Identify scripts, scheduled jobs, or application paths",
    "Determine whether uploaded files can be executed"
  ]
}
```

---

## Example Blocked Path Object

```json
{
  "path_id": "BLOCKED-SMB-001",
  "title": "Anonymous SMB enumeration blocked",
  "blocked_by": ["CTRL-SMB-AUTH-001"],
  "evidence_ids": ["EVID-0001"],
  "confidence": "high",
  "reason": "Anonymous access was denied during share enumeration."
}
```

---

## SOLID Design Requirements

### Single Responsibility Principle

Each class should have one reason to change.

Good:

- `CommandRunner` runs commands.
- `SmbMapPermissionParser` parses smbmap permission output.
- `MarkdownReporter` writes markdown reports.

Bad:

- A single `SMBScanner` class that runs commands, parses output, scores risk, and writes reports.

### Open/Closed Principle

The package should be open for extension but closed for modification.

To add a new tool, create a new adapter and register it.

To add a new parser, create a new parser and register it.

To add a new attack path rule, create a new rule and register it.

Do not modify core orchestration every time a feature is added.

### Liskov Substitution Principle

Any implementation of a shared interface should be usable wherever the interface is expected.

For example, any `ToolAdapter` should be usable by the execution system.

### Interface Segregation Principle

Avoid giant interfaces.

Good:

- `ToolAdapter`
- `Parser`
- `Reporter`
- `FileClassifier`
- `AttackPathRule`

Bad:

- One interface requiring every class to implement command execution, parsing, validation, and reporting methods.

### Dependency Inversion Principle

High-level orchestration should depend on interfaces, not concrete implementations.

The workflow should depend on registries and protocols, not directly on `NmapAdapter` or `SmbMapAdapter`.

---

## Clean Code Requirements

### Functions

Functions should be small and named by intent.

Good:

```python
def is_access_denied(output: str) -> bool:
    ...
```

Bad:

```python
def parse(output):
    ...
```

### Error Handling

Use explicit exceptions for expected failure modes:

- `ToolNotFoundError`
- `CommandTimeoutError`
- `ParseError`
- `EvidenceNotFoundError`
- `InconclusiveTestError`

Do not silently ignore failed commands.

### Logging

Use structured logging.

Each log event should include:

- target
- phase
- test ID where applicable
- tool where applicable
- status

### Type Hints

All public functions and methods must include type hints.

### Tests

Every parser, classifier, validator, and attack path rule should have unit tests.

Use fixtures for sample outputs from:

- nmap
- smbclient
- smbmap
- enum4linux
- rpcclient

---

## Recommended Initial Milestone

### Milestone 1: Minimal Useful Enumerator

Implement:

- Output tree creation
- Command runner
- Raw output storage
- `smbclient` adapter
- `smbmap` adapter
- Anonymous access test
- Share listing test
- Share permission test
- JSON output for tests and validation
- Markdown summary report

This milestone should answer:

- Is anonymous access allowed?
- What shares exist?
- Which shares are readable?
- Which shares are writable?
- Which controls passed, failed, or were inconclusive?

### Milestone 2: File Intelligence

Add:

- Recursive file indexing
- File classifiers
- Sensitive file summaries
- Credential source tracking
- Config/script/backup reports

### Milestone 3: Attack Path Engine

Add:

- Attack path rule registry
- Candidate attack paths
- Blocked attack paths
- Confidence scoring
- Next-step recommendations

### Milestone 4: Multi-tool Correlation

Add:

- Nmap protocol parsing
- rpcclient user enumeration
- enum4linux support
- crackmapexec/netexec support
- Impacket support
- Cross-tool evidence correlation

---

## Final Architecture Goal

The finished package should not merely scan SMB. It should produce a structured evidence package that answers:

1. What was tested?
2. What appeared secure?
3. What appeared vulnerable?
4. What was inconclusive?
5. What evidence supports each conclusion?
6. What attack paths are available?
7. What attack paths were blocked?
8. What should a human or future agent do next?

