# Oracle TNS Enumeration Python Package Design

## Title
Oracle TNS Enumeration Package Design

## Purpose
This document describes how to build a Python package that enumerates Oracle TNS services using a decision-tree workflow. The package should collect raw tool output, normalize findings into JSON, and generate human-readable Markdown summaries for later review by a penetration tester or an LLM-assisted analysis workflow.

The design follows these principles:

- Keep functions small and focused on one task.
- Separate flow control from task logic.
- Use registry patterns so new checks, tools, parsers, and report sections can be added without rewriting the core workflow.
- Preserve raw command output exactly as collected.
- Convert important findings into structured JSON.
- Produce Markdown summaries that are useful during manual recon.
- Support external tools such as `nmap`, `odat`, `tnscmd`, and `hydra` through isolated wrappers.

---

## Scope

This package focuses on Oracle Transparent Network Substrate (`TNS`) enumeration.

Primary goals:

1. Detect Oracle TNS services.
2. Enumerate listener information.
3. Discover valid SIDs and service names.
4. Test authentication using default or supplied credentials.
5. Run post-authentication enumeration when credentials are available.
6. Identify exploitation paths and misconfigurations.
7. Save raw and parsed results.
8. Generate Markdown and JSON reports.

Out of scope for the first version:

- Fully automated exploitation.
- Destructive testing.
- Aggressive brute forcing without explicit user configuration.
- Credential spraying across large environments unless explicitly enabled.
- Interactive shells or post-exploitation beyond safe enumeration.

---

## Mental Model

Oracle TNS enumeration follows this structure:

```text
Target Discovery
    ↓
Port / Service Detection
    ↓
Listener Enumeration
    ↓
SID / Service Name Discovery
    ↓
Authentication Testing
    ↓
Post-Auth Enumeration
    ↓
Privilege / Abuse Path Review
    ↓
Report Generation
```

This differs from MySQL and MSSQL because Oracle usually requires discovering or guessing a valid SID or service name before meaningful database interaction can occur.

---

## Recommended Package Name

```text
oracle_tns_enum
```

---

## Directory Layout

```text
oracle_tns_enum/
├── pyproject.toml
├── README.md
├── oracle_tns_enum/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── context.py
│   ├── constants.py
│   ├── decision_tree.py
│   ├── logging_config.py
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── command_runner.py
│   │   ├── filesystem.py
│   │   ├── result.py
│   │   ├── registry.py
│   │   └── validators.py
│   │
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── nmap.py
│   │   ├── odat.py
│   │   ├── hydra.py
│   │   ├── tnscmd.py
│   │   └── sqlplus.py
│   │
│   ├── checks/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── service_detection.py
│   │   ├── listener_enum.py
│   │   ├── sid_enum.py
│   │   ├── auth_enum.py
│   │   ├── post_auth_enum.py
│   │   └── abuse_path_review.py
│   │
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── nmap_parser.py
│   │   ├── odat_parser.py
│   │   ├── hydra_parser.py
│   │   ├── tnscmd_parser.py
│   │   └── sqlplus_parser.py
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── target.py
│   │   ├── finding.py
│   │   ├── credential.py
│   │   ├── oracle_service.py
│   │   ├── artifact.py
│   │   └── report.py
│   │
│   ├── reporters/
│   │   ├── __init__.py
│   │   ├── json_reporter.py
│   │   ├── markdown_reporter.py
│   │   └── section_registry.py
│   │
│   └── wordlists/
│       ├── common_sids.txt
│       ├── common_service_names.txt
│       └── default_oracle_credentials.txt
│
├── tests/
│   ├── test_command_runner.py
│   ├── test_registries.py
│   ├── test_nmap_parser.py
│   ├── test_odat_parser.py
│   ├── test_decision_tree.py
│   └── fixtures/
│       ├── nmap_oracle_tns.txt
│       ├── nmap_sid_brute.txt
│       ├── odat_all.txt
│       └── hydra_oracle.txt
│
└── examples/
    ├── basic_scan.yaml
    ├── authenticated_scan.yaml
    └── aggressive_scan_disabled.yaml
```

---

## External Tools

The package should call external tools through wrapper classes. The wrappers should not parse results directly. They should only build commands, execute commands, and return raw output metadata.

### Required / Supported Tools

| Tool | Purpose | Required for MVP |
|---|---|---|
| `nmap` | Port/service detection and SID brute script | Yes |
| `odat.py` | Oracle database enumeration and module scans | Yes |
| `tnscmd` | Listener interaction and TNS commands | Optional |
| `hydra` | Password guessing against Oracle listener/database | Optional |
| `sqlplus` | Manual SQL authentication and post-auth queries | Optional but useful |

### Tool Installation Notes

The package should not install system tools automatically. It should check whether tools are available and report missing tools clearly.

Example tool validation:

```text
nmap: found
odat.py: found
hydra: missing
sqlplus: missing
```

Missing optional tools should not crash the package. The decision tree should skip checks that depend on unavailable tools unless they are explicitly required.

---

## Output Folder Structure

Each scan should create one output folder per target.

Default folder format:

```text
outputs/
└── <target_ip_or_hostname>/
    ├── scan_metadata.json
    ├── raw/
    │   ├── nmap_service_detection.txt
    │   ├── nmap_sid_brute.txt
    │   ├── odat_all.txt
    │   ├── odat_sidguesser.txt
    │   ├── odat_passwordguesser.txt
    │   ├── hydra_oracle.txt
    │   └── sqlplus_queries.txt
    │
    ├── parsed/
    │   ├── service_detection.json
    │   ├── listener.json
    │   ├── sids.json
    │   ├── credentials.json
    │   ├── users.json
    │   ├── privileges.json
    │   ├── database_objects.json
    │   └── findings.json
    │
    ├── reports/
    │   ├── summary.md
    │   ├── decision_tree_trace.md
    │   ├── findings.md
    │   └── loot_index.md
    │
    └── logs/
        └── run.log
```

---

## Core Data Models

Use dataclasses or Pydantic models. Pydantic is preferred if validation and JSON serialization are important.

### Target

```python
class Target:
    host: str
    port: int = 1521
    protocol: str = "tcp"
    label: str | None = None
```

### CommandResult

```python
class CommandResult:
    tool_name: str
    command: list[str]
    started_at: str
    completed_at: str
    return_code: int
    stdout: str
    stderr: str
    raw_output_path: str | None
```

### Finding

```python
class Finding:
    id: str
    title: str
    severity: str
    category: str
    description: str
    evidence: list[str]
    source_tool: str
    raw_artifact_path: str | None
    recommended_next_steps: list[str]
```

### OracleService

```python
class OracleService:
    host: str
    port: int
    listener_version: str | None
    sids: list[str]
    service_names: list[str]
    requires_authentication: bool | None
```

### Credential

```python
class Credential:
    username: str
    password: str
    sid: str | None
    service_name: str | None
    source: str
    valid: bool
```

### ScanContext

`ScanContext` is the shared state object passed between checks. It should hold target data, discovered artifacts, configuration, and paths.

```python
class ScanContext:
    target: Target
    config: ScanConfig
    output_paths: OutputPaths
    tool_status: dict[str, bool]
    discovered_sids: set[str]
    discovered_service_names: set[str]
    valid_credentials: list[Credential]
    findings: list[Finding]
    decision_trace: list[str]
```

---

## Registry Pattern

Use registries to make the package easy to extend.

### Tool Registry

Purpose: map tool names to tool wrapper classes.

```python
TOOL_REGISTRY = {
    "nmap": NmapTool,
    "odat": OdatTool,
    "hydra": HydraTool,
    "tnscmd": TnsCmdTool,
    "sqlplus": SqlPlusTool,
}
```

### Check Registry

Purpose: define available checks and their execution order.

```python
CHECK_REGISTRY = {
    "service_detection": ServiceDetectionCheck,
    "listener_enum": ListenerEnumerationCheck,
    "sid_enum": SidEnumerationCheck,
    "auth_enum": AuthenticationEnumerationCheck,
    "post_auth_enum": PostAuthenticationEnumerationCheck,
    "abuse_path_review": AbusePathReviewCheck,
}
```

### Parser Registry

Purpose: map tool output types to parser classes.

```python
PARSER_REGISTRY = {
    "nmap_service_detection": NmapServiceDetectionParser,
    "nmap_sid_brute": NmapSidBruteParser,
    "odat_all": OdatAllParser,
    "odat_sidguesser": OdatSidGuesserParser,
    "odat_passwordguesser": OdatPasswordGuesserParser,
    "hydra_oracle": HydraOracleParser,
}
```

### Report Section Registry

Purpose: allow report sections to be added without changing the Markdown reporter core.

```python
REPORT_SECTION_REGISTRY = [
    TargetSummarySection,
    ToolAvailabilitySection,
    ServiceDetectionSection,
    ListenerSection,
    SidSection,
    CredentialSection,
    PostAuthSection,
    FindingsSection,
    RecommendedNextStepsSection,
]
```

---

## Decision Tree Flow Controller

The decision tree should be controlled by one orchestration class. This class is allowed to contain branching logic. Individual checks should not become large `if/else` blocks.

### DecisionTreeRunner Responsibilities

The runner should:

1. Load configuration.
2. Initialize the scan context.
3. Validate tool availability.
4. Execute checks in order.
5. Skip checks when prerequisites are not met.
6. Record each decision in the decision trace.
7. Save raw and parsed outputs.
8. Generate reports.

### Decision Flow

```text
Start
  ↓
Validate target
  ↓
Check tool availability
  ↓
Run service detection
  ↓
Is Oracle TNS detected?
  ├── No → write report and stop
  └── Yes
        ↓
Run listener enumeration
        ↓
Do we have SID/service names?
  ├── Yes → auth testing
  └── No → SID/service discovery
        ↓
Were any SIDs/services discovered?
  ├── No → write report and stop
  └── Yes
        ↓
Run authentication testing
        ↓
Any valid credentials?
  ├── No → write report and stop
  └── Yes
        ↓
Run post-auth enumeration
        ↓
Run abuse path review
        ↓
Generate reports
```

### Example Runner Skeleton

```python
class DecisionTreeRunner:
    def __init__(self, check_registry, reporter_registry):
        self.check_registry = check_registry
        self.reporter_registry = reporter_registry

    def run(self, context: ScanContext) -> ScanContext:
        self._run_check(context, "service_detection")

        if not self._is_oracle_detected(context):
            context.decision_trace.append("Oracle TNS not detected. Stopping scan.")
            return self._finalize(context)

        self._run_check(context, "listener_enum")

        if not self._has_connection_identifiers(context):
            self._run_check(context, "sid_enum")

        if not self._has_connection_identifiers(context):
            context.decision_trace.append("No SID or service name discovered. Stopping scan.")
            return self._finalize(context)

        self._run_check(context, "auth_enum")

        if not context.valid_credentials:
            context.decision_trace.append("No valid credentials discovered. Stopping post-auth checks.")
            return self._finalize(context)

        self._run_check(context, "post_auth_enum")
        self._run_check(context, "abuse_path_review")

        return self._finalize(context)
```

The helper methods such as `_is_oracle_detected` and `_has_connection_identifiers` should only answer one question. They should not run tools or mutate unrelated state.

---

## Check Design

Each check should have the same interface.

```python
class BaseCheck:
    name: str
    required_tools: list[str]

    def can_run(self, context: ScanContext) -> bool:
        raise NotImplementedError

    def run(self, context: ScanContext) -> CheckResult:
        raise NotImplementedError
```

### CheckResult

```python
class CheckResult:
    check_name: str
    status: str
    raw_artifacts: list[Artifact]
    parsed_artifacts: list[Artifact]
    findings: list[Finding]
    notes: list[str]
```

---

## Individual Checks

## 1. ServiceDetectionCheck

### Purpose
Determine whether the target exposes Oracle TNS.

### Tools
- `nmap`

### Commands

```bash
nmap -p1521 -sV <target> --open
```

Optional expanded version:

```bash
nmap -p1521 -sV -sC <target> --open
```

### Responsibilities

- Run the scan.
- Save raw Nmap output.
- Parse port state, service name, and version.
- Add finding if Oracle TNS is detected.

### Should Not Do

- Should not brute force SIDs.
- Should not test credentials.
- Should not make exploitation decisions.

### Parsed JSON Example

```json
{
  "host": "10.129.204.235",
  "port": 1521,
  "state": "open",
  "service": "oracle-tns",
  "version": "Oracle TNS listener 11.2.0.2.0",
  "oracle_detected": true
}
```

---

## 2. ListenerEnumerationCheck

### Purpose
Collect listener-level information when possible.

### Tools
- `odat.py tnscmd`
- `tnscmd`, if installed
- optional `nmap` NSE scripts

### Example Commands

```bash
python3 odat.py tnscmd -s <target> -p 1521 --ping
```

```bash
python3 odat.py tnscmd -s <target> -p 1521 --version
```

If `tnscmd` is available:

```bash
tnscmd10g version -h <target> -p 1521
```

### Responsibilities

- Query listener status/version where possible.
- Save raw output.
- Parse listener information.
- Identify whether listener allows useful unauthenticated interaction.

### Parsed JSON Example

```json
{
  "listener_reachable": true,
  "listener_version": "11.2.0.2.0",
  "unauthenticated_info_leak": true,
  "notes": [
    "Listener responded to version request"
  ]
}
```

---

## 3. SidEnumerationCheck

### Purpose
Discover valid Oracle SIDs or service names.

### Tools
- `nmap`
- `odat.py sidguesser`
- optional `hydra`

### Commands

```bash
nmap -p1521 -sV <target> --open --script oracle-sid-brute
```

```bash
python3 odat.py sidguesser -s <target> -p 1521
```

Optional custom wordlist:

```bash
python3 odat.py sidguesser -s <target> -p 1521 --sids-file wordlists/common_sids.txt
```

### Common SIDs / Service Names

```text
XE
ORCL
PROD
DEV
TEST
UAT
PDB1
CDB1
FREE
DB11G
DB12C
DB19C
```

### Responsibilities

- Run one or more SID/service discovery methods.
- Merge results from different tools.
- Deduplicate identifiers.
- Save discovered SIDs and service names.

### Should Not Do

- Should not test credentials.
- Should not assume a discovered SID is exploitable.

### Parsed JSON Example

```json
{
  "sids": ["XE", "ORCL"],
  "service_names": ["orcl"],
  "sources": {
    "nmap_oracle_sid_brute": ["XE"],
    "odat_sidguesser": ["ORCL", "orcl"]
  }
}
```

---

## 4. AuthenticationEnumerationCheck

### Purpose
Test supplied, default, or discovered credentials against discovered SIDs/service names.

### Tools
- `odat.py passwordguesser`
- optional `hydra`
- optional `sqlplus`

### Inputs

- Discovered SIDs/service names.
- User-supplied credential file.
- Default Oracle credential list.

### Default Credential Seeds

```text
dbsnmp:dbsnmp
system:oracle
sys:oracle
scott:tiger
system:manager
sys:change_on_install
```

### Commands

```bash
python3 odat.py passwordguesser -s <target> -p 1521 -d <SID>
```

With custom credentials:

```bash
python3 odat.py passwordguesser -s <target> -p 1521 -d <SID> --accounts-file wordlists/default_oracle_credentials.txt
```

Hydra example:

```bash
hydra -L users.txt -P passwords.txt -s 1521 <target> oracle-listener
```

### Safety Requirements

Authentication testing should be conservative by default.

Default behavior:

- Try only a small default credential list.
- Do not run large brute-force lists unless `--aggressive` or equivalent config is enabled.
- Respect lockout risk.
- Record attempted credential source.

### Responsibilities

- Build credential attempts from configured sources.
- Execute credential checks.
- Parse valid credentials.
- Save successful and attempted credentials separately.

### Parsed JSON Example

```json
{
  "valid_credentials": [
    {
      "username": "dbsnmp",
      "password": "dbsnmp",
      "sid": "XE",
      "source": "default_credentials",
      "valid": true
    }
  ],
  "attempt_summary": {
    "total_attempts": 6,
    "lockout_safe_mode": true
  }
}
```

---

## 5. PostAuthenticationEnumerationCheck

### Purpose
Use valid credentials to enumerate database details safely.

### Tools
- `odat.py all`
- `odat.py search`
- `sqlplus`

### Example Commands

```bash
python3 odat.py all -s <target> -p 1521 -d <SID> -U <user> -P <password>
```

Possible SQLPlus connection:

```bash
sqlplus <user>/<password>@<target>:1521/<service_name>
```

### Safe Enumeration Queries

The package should store safe SQL queries in a registry.

Examples:

```sql
SELECT username FROM all_users;
```

```sql
SELECT * FROM session_privs;
```

```sql
SELECT owner, table_name FROM all_tables WHERE ROWNUM <= 100;
```

```sql
SELECT privilege FROM user_sys_privs;
```

```sql
SELECT granted_role FROM user_role_privs;
```

### Responsibilities

- Enumerate users.
- Enumerate roles.
- Enumerate privileges.
- Enumerate accessible schemas/tables.
- Identify high-value access.
- Save raw and parsed results.

### Should Not Do

- Should not dump full databases by default.
- Should not modify data.
- Should not execute destructive PL/SQL.

### Parsed JSON Example

```json
{
  "authenticated_as": "dbsnmp",
  "sid": "XE",
  "users": ["SYS", "SYSTEM", "DBSNMP", "APPUSER"],
  "roles": ["CONNECT", "RESOURCE"],
  "privileges": ["CREATE SESSION"],
  "accessible_tables": [
    {
      "owner": "APPUSER",
      "table_name": "CUSTOMERS"
    }
  ]
}
```

---

## 6. AbusePathReviewCheck

### Purpose
Review parsed findings and identify possible next steps.

This check should not run dangerous exploitation automatically. It should classify likely abuse paths based on evidence.

### Abuse Path Categories

| Category | Evidence |
|---|---|
| Default Credentials | Known default account works |
| Weak SID Exposure | SID/service name discovered unauthenticated |
| Excessive Privileges | User has DBA or dangerous system privileges |
| File Access Potential | UTL_FILE, external table access, directory objects |
| Network Access Potential | UTL_HTTP, UTL_TCP, HTTPURITYPE access |
| Code Execution Potential | Java, scheduler, external procedure privileges |
| Credential Reuse Risk | Oracle creds match other service creds |

### Responsibilities

- Read parsed artifacts.
- Convert evidence into findings.
- Recommend next manual checks.
- Flag risky capabilities without automatically exploiting them.

### Parsed JSON Example

```json
{
  "findings": [
    {
      "id": "ORACLE-TNS-DEFAULT-CREDS",
      "title": "Default Oracle credentials accepted",
      "severity": "High",
      "category": "Authentication",
      "evidence": ["dbsnmp:dbsnmp valid for SID XE"],
      "recommended_next_steps": [
        "Validate database privileges for DBSNMP",
        "Check whether credentials are reused on other services",
        "Review Oracle account password policy"
      ]
    }
  ]
}
```

---

## Tool Wrapper Design

Tool wrappers should do only three things:

1. Validate that the tool exists.
2. Build a command.
3. Run the command through `CommandRunner`.

They should not parse output.

### BaseTool

```python
class BaseTool:
    name: str

    def is_available(self) -> bool:
        raise NotImplementedError

    def build_command(self, **kwargs) -> list[str]:
        raise NotImplementedError

    def run(self, **kwargs) -> CommandResult:
        command = self.build_command(**kwargs)
        return self.command_runner.run(command)
```

### NmapTool Methods

```python
class NmapTool(BaseTool):
    def service_detection(self, target: Target) -> CommandResult:
        ...

    def sid_brute(self, target: Target) -> CommandResult:
        ...
```

### OdatTool Methods

```python
class OdatTool(BaseTool):
    def tnscmd_ping(self, target: Target) -> CommandResult:
        ...

    def sid_guesser(self, target: Target, sid_file: str | None = None) -> CommandResult:
        ...

    def password_guesser(self, target: Target, sid: str, accounts_file: str | None = None) -> CommandResult:
        ...

    def all_modules(self, target: Target, sid: str, username: str, password: str) -> CommandResult:
        ...
```

### HydraTool Methods

```python
class HydraTool(BaseTool):
    def oracle_listener_guess(self, target: Target, users_file: str, passwords_file: str) -> CommandResult:
        ...
```

### SqlPlusTool Methods

```python
class SqlPlusTool(BaseTool):
    def run_query(self, connection_string: str, query: str) -> CommandResult:
        ...
```

---

## Parser Design

Parsers should do one thing: transform raw text into structured data.

They should not run tools, write reports, or control the decision tree.

### BaseParser

```python
class BaseParser:
    name: str

    def parse(self, raw_text: str) -> dict:
        raise NotImplementedError
```

### Parser Output Rules

Each parser should return predictable JSON-like dictionaries.

Bad parser behavior:

```python
return "XE found"
```

Good parser behavior:

```python
return {
    "sids": ["XE"],
    "confidence": "high",
    "source": "nmap_oracle_sid_brute"
}
```

---

## Reporter Design

Reporters should consume the `ScanContext` and write output files.

### JSON Reporter

The JSON reporter should generate:

```text
parsed/findings.json
parsed/sids.json
parsed/credentials.json
scan_metadata.json
```

### Markdown Reporter

The Markdown reporter should generate:

```text
reports/summary.md
reports/decision_tree_trace.md
reports/findings.md
reports/loot_index.md
```

### Markdown Summary Template

```markdown
# Oracle TNS Enumeration Summary

## Target

- Host: <host>
- Port: <port>
- Oracle TNS Detected: <true/false>
- Listener Version: <version>

## Tool Availability

| Tool | Available | Notes |
|---|---:|---|
| nmap | Yes | Used for service detection |
| odat | Yes | Used for SID and auth enumeration |
| hydra | No | Skipped password guessing fallback |

## Service Detection

<summary>

## Listener Enumeration

<summary>

## SID / Service Name Discovery

| Identifier | Type | Source |
|---|---|---|
| XE | SID | nmap oracle-sid-brute |

## Authentication Results

| Username | Password | SID/Service | Source | Valid |
|---|---|---|---|---:|
| dbsnmp | dbsnmp | XE | default_credentials | Yes |

## Post-Authentication Enumeration

### Users

<users>

### Roles

<roles>

### Privileges

<privileges>

### Accessible Tables

<tables>

## Findings

<findings>

## Recommended Next Steps

<next steps>
```

---

## Configuration

Use YAML for user-facing configuration.

### Example: Basic Scan

```yaml
target:
  host: 10.129.204.235
  port: 1521

scan:
  aggressive: false
  run_post_auth: true
  save_raw_output: true
  save_json: true
  save_markdown: true

wordlists:
  sid_file: oracle_tns_enum/wordlists/common_sids.txt
  service_name_file: oracle_tns_enum/wordlists/common_service_names.txt
  credentials_file: oracle_tns_enum/wordlists/default_oracle_credentials.txt

tools:
  nmap_path: nmap
  odat_path: /opt/odat/odat.py
  hydra_path: hydra
  sqlplus_path: sqlplus
```

### Example: Authenticated Scan

```yaml
target:
  host: 10.129.204.235
  port: 1521

credentials:
  - username: dbsnmp
    password: dbsnmp
    sid: XE

scan:
  aggressive: false
  run_auth_tests: false
  run_post_auth: true
```

---

## CLI Design

### Basic Usage

```bash
oracle-tns-enum scan --target 10.129.204.235
```

### With Config

```bash
oracle-tns-enum scan --config examples/basic_scan.yaml
```

### With Output Directory

```bash
oracle-tns-enum scan --target 10.129.204.235 --output outputs/
```

### With Supplied Credentials

```bash
oracle-tns-enum scan --target 10.129.204.235 --username dbsnmp --password dbsnmp --sid XE
```

### Aggressive Mode

```bash
oracle-tns-enum scan --target 10.129.204.235 --aggressive
```

Aggressive mode should be explicit because password guessing and heavy module execution can be noisy.

---

## Clean Code Rules

### Function Rules

Each function should do one thing.

Good:

```python
def has_oracle_tns(service_result: dict) -> bool:
    return service_result.get("oracle_detected", False)
```

Bad:

```python
def scan_parse_auth_report_everything(target):
    ...
```

### Flow Control Rule

Complex branching belongs in `DecisionTreeRunner`.

Do not bury decision-tree behavior inside tool wrappers or parsers.

### Registry Rule

When adding a new check:

1. Create a new check class.
2. Add it to `CHECK_REGISTRY`.
3. Add any required parser to `PARSER_REGISTRY`.
4. Add report section if needed.

Do not modify the runner unless the decision tree itself changes.

### Dependency Direction

Preferred dependency direction:

```text
CLI
 ↓
DecisionTreeRunner
 ↓
Checks
 ↓
Tools / Parsers
 ↓
CommandRunner / Filesystem
```

Reporters should read from `ScanContext`; they should not run tools.

---

## SOLID Design Notes

### Single Responsibility Principle

- `CommandRunner` runs commands.
- Tool wrappers build commands.
- Parsers parse raw output.
- Checks coordinate one enumeration step.
- Reporters write reports.
- DecisionTreeRunner controls workflow.

### Open / Closed Principle

The system should be open for extension through registries but closed for constant modification.

Example: adding `tnspoison` support should require a new check and registry entry, not a rewrite of the runner.

### Liskov Substitution Principle

All tools should implement the same `BaseTool` interface.
All checks should implement the same `BaseCheck` interface.
All parsers should implement the same `BaseParser` interface.

### Interface Segregation Principle

Avoid large interfaces such as `OracleTool.do_everything()`.
Prefer small methods:

```python
sid_guesser()
password_guesser()
all_modules()
```

### Dependency Inversion Principle

High-level workflow should depend on abstractions.

For example, `DecisionTreeRunner` should use `BaseCheck`, not concrete `NmapServiceDetectionCheck` directly.

---

## Testing Strategy

### Unit Tests

Test small units independently:

- Command building.
- Tool availability checks.
- Parsers against fixture outputs.
- Registry lookup.
- Decision-tree branching.
- Markdown rendering.

### Integration Tests

Run against controlled lab systems only.

Recommended integration scenarios:

1. Port 1521 closed.
2. Port 1521 open but not Oracle.
3. Oracle detected but no SID found.
4. Oracle detected and SID found.
5. Valid default credential found.
6. Authenticated user has low privileges.
7. Authenticated user has high privileges.

### Fixtures

Store raw sample output in `tests/fixtures/`.

Example:

```text
tests/fixtures/nmap_sid_brute.txt
tests/fixtures/odat_passwordguesser_valid.txt
tests/fixtures/odat_passwordguesser_invalid.txt
```

---

## Example Decision Trace

```markdown
# Decision Tree Trace

1. Target validation completed.
2. Tool validation completed.
3. `nmap` detected TCP/1521 open.
4. Service identified as Oracle TNS listener 11.2.0.2.0.
5. Listener enumeration completed.
6. No service names found from listener output.
7. SID enumeration started.
8. SID `XE` discovered using nmap oracle-sid-brute.
9. Authentication testing started against SID `XE`.
10. Default credential `dbsnmp:dbsnmp` was valid.
11. Post-authentication enumeration started.
12. User and privilege enumeration completed.
13. Abuse path review identified default credential risk.
14. Reports generated.
```

---

## Example Findings Markdown

```markdown
# Findings

## ORACLE-TNS-001: Oracle TNS Listener Exposed

- Severity: Informational
- Category: Service Exposure
- Evidence:
  - TCP/1521 open
  - Service: Oracle TNS listener 11.2.0.2.0

Recommended next steps:

- Confirm whether the listener must be reachable from this network.
- Restrict access to trusted management hosts where possible.

---

## ORACLE-TNS-002: SID Discovered Without Authentication

- Severity: Low
- Category: Information Disclosure
- Evidence:
  - SID `XE` discovered using `oracle-sid-brute`

Recommended next steps:

- Review listener exposure.
- Monitor for repeated SID guessing attempts.

---

## ORACLE-TNS-003: Default Credentials Accepted

- Severity: High
- Category: Authentication
- Evidence:
  - Credential `dbsnmp:dbsnmp` valid for SID `XE`

Recommended next steps:

- Rotate the account password.
- Check whether this credential is reused elsewhere.
- Review Oracle account lockout and password policy.
```

---

## Future Extension Ideas

### New Checks

- `tnspoison_check`
- `password_policy_check`
- `oracle_enterprise_manager_check`
- `dbsnmp_specific_check`
- `plsql_package_capability_check`
- `oracle_directory_object_check`
- `utl_http_network_reachability_check`
- `java_stored_procedure_check`
- `scheduler_job_capability_check`

### New Report Sections

- Credential reuse candidates.
- High-risk PL/SQL packages.
- Exposed Oracle ecosystem services.
- Suggested manual SQL queries.
- Risk-ranked next actions.

### New Output Formats

- SQLite artifact database.
- SARIF-style findings.
- HTML report.
- Neo4j graph import.

---

## MVP Build Order

### Phase 1: Core Framework

1. Create package skeleton.
2. Add config loading.
3. Add command runner.
4. Add filesystem output manager.
5. Add registries.
6. Add models.

### Phase 2: Service + SID Enumeration

1. Add Nmap wrapper.
2. Add service detection check.
3. Add SID brute check.
4. Add parsers.
5. Save raw and parsed output.

### Phase 3: ODAT Integration

1. Add ODAT wrapper.
2. Add listener enumeration.
3. Add ODAT SID guessing.
4. Add ODAT password guessing.
5. Parse useful output.

### Phase 4: Reporting

1. Add JSON reporter.
2. Add Markdown reporter.
3. Add decision trace report.
4. Add findings report.

### Phase 5: Post-Auth Enumeration

1. Add credential model.
2. Add SQLPlus or ODAT authenticated enumeration.
3. Add user/role/privilege parsing.
4. Add abuse path review.

### Phase 6: Hardening + Tests

1. Add fixture-based parser tests.
2. Add decision-tree branch tests.
3. Add CLI tests.
4. Add config validation tests.
5. Add documentation.

---

## Final Design Principle

This package should not try to be one giant Oracle exploitation script.

It should be a clean enumeration framework:

```text
run tool → preserve raw output → parse important facts → update context → decide next step → report clearly
```

That structure makes the package safer, easier to extend, and much more useful for both manual review and LLM-assisted post-processing.
