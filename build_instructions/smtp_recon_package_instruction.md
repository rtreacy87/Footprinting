# SMTP Recon Python Package Architecture

## Purpose

This document defines the architecture and implementation requirements for a Python package that performs comprehensive SMTP reconnaissance during an authorized penetration test or lab assessment.

The package must collect raw SMTP evidence, normalize the results, identify useful attack paths, explicitly record blocked or failed checks, and produce outputs that can be used by both:

1. A future agent deciding what to test next.
2. A human consultant writing a technical report.

The package must follow clean code and SOLID principles. Functions should do one thing well. Flow control should be separated from parsing, data modeling, tool execution, and reporting. Avoid long `if/else` chains by using registries and strategy patterns wherever practical.

---

## Core Recon Objectives

The package should answer the following questions:

1. Is SMTP exposed on the target?
2. Which SMTP ports are open?
3. What banner, hostname, domain, and software information can be collected?
4. Which SMTP commands are allowed?
5. Which authentication methods are advertised?
6. Is STARTTLS available?
7. Is the server vulnerable to user enumeration?
8. Are usernames confirmed, rejected, or ambiguous?
9. Is the server an open relay?
10. Can sender spoofing be performed?
11. What domains, hostnames, routing paths, and organization patterns can be inferred?
12. Which controls appear to be working?
13. Which tests failed, were blocked, or produced inconclusive results?
14. What should a future agent do next?
15. What should a future agent avoid retesting?

---

## Expected Output Directory

The package should create the following directory structure for every target:

---

```text
smtp_recon/
└── <target_ip_or_hostname>/
    ├── metadata/
    │   ├── target.json
    │   ├── scan_context.json
    │   ├── ports_detected.json
    │   └── service_fingerprints.json
    │
    ├── raw/
    │   ├── nmap/
    │   │   ├── smtp_commands.txt
    │   │   ├── smtp_open_relay.txt
    │   │   ├── smtp_enum_users.txt
    │   │   └── full_nmap.xml
    │   ├── manual_sessions/
    │   │   ├── ehlo_session.txt
    │   │   ├── vrfy_session.txt
    │   │   ├── expn_session.txt
    │   │   ├── rcpt_to_session.txt
    │   │   └── starttls_session.txt
    │   ├── swaks/
    │   │   ├── relay_tests.txt
    │   │   ├── spoofing_tests.txt
    │   │   └── auth_tests.txt
    │   └── screenshots_or_artifacts/
    │
    ├── normalized/
    │   ├── smtp_capabilities.json
    │   ├── allowed_commands.json
    │   ├── auth_methods.json
    │   ├── tls_encryption.json
    │   ├── domains.json
    │   ├── hostnames.json
    │   ├── mail_routing.json
    │   ├── users_found.json
    │   ├── users_rejected.json
    │   ├── users_ambiguous.json
    │   └── response_codes.json
    │
    ├── trust_boundary_tests/
    │   ├── open_relay/
    │   │   ├── test_matrix.json
    │   │   ├── successful_relay_attempts.json
    │   │   ├── blocked_relay_attempts.json
    │   │   └── evidence.md
    │   ├── spoofing/
    │   │   ├── spoofing_allowed.json
    │   │   ├── spoofing_blocked.json
    │   │   └── evidence.md
    │   └── internal_vs_external_behavior/
    │       ├── source_ip_assumptions.json
    │       ├── accepted_paths.json
    │       └── blocked_paths.json
    │
    ├── identity_enumeration/
    │   ├── methods_tested.json
    │   ├── vrfy_results.json
    │   ├── expn_results.json
    │   ├── rcpt_to_results.json
    │   ├── confirmed_users.txt
    │   ├── rejected_users.txt
    │   ├── ambiguous_users.txt
    │   └── confidence_scoring.json
    │
    ├── org_intelligence/
    │   ├── inferred_email_formats.json
    │   ├── domains_and_subdomains.json
    │   ├── hostname_patterns.json
    │   ├── possible_departments_or_roles.json
    │   ├── internal_naming_conventions.json
    │   └── org_structure_notes.md
    │
    ├── security_controls/
    │   ├── starttls_supported.json
    │   ├── auth_required.json
    │   ├── relay_restrictions.json
    │   ├── user_enum_restrictions.json
    │   ├── rate_limiting_observed.json
    │   ├── banner_hardening.json
    │   └── controls_that_work.md
    │
    ├── failures_and_dead_ends/
    │   ├── commands_not_supported.json
    │   ├── auth_methods_not_supported.json
    │   ├── enumeration_methods_blocked.json
    │   ├── relay_attempts_blocked.json
    │   ├── tls_failures.json
    │   ├── false_positive_risks.md
    │   └── retest_recommendations.json
    │
    ├── findings/
    │   ├── attack_paths.json
    │   ├── non_attack_paths.json
    │   ├── noteworthy_misconfigurations.json
    │   ├── validated_secure_behaviors.json
    │   └── finding_summary.md
    │
    ├── agent_inputs/
    │   ├── next_actions.json
    │   ├── credential_attack_candidates.json
    │   ├── phishing_or_social_engineering_inputs.json
    │   ├── network_recon_leads.json
    │   └── do_not_retry.json
    │
    └── report/
        ├── executive_summary.md
        ├── technical_summary.md
        ├── evidence_appendix.md
        ├── secure_controls_observed.md
        └── remediation_notes.md
```

---

## Recommended Package Layout

The Python package should be structured as follows:

---

```text
smtp_recon_pkg/
├── pyproject.toml
├── README.md
├── src/
│   └── smtp_recon/
│       ├── __init__.py
│       ├── cli.py
│       ├── config.py
│       ├── logging_config.py
│       │
│       ├── core/
│       │   ├── orchestrator.py
│       │   ├── scan_context.py
│       │   ├── target.py
│       │   ├── result.py
│       │   ├── evidence.py
│       │   └── exceptions.py
│       │
│       ├── executors/
│       │   ├── base.py
│       │   ├── subprocess_executor.py
│       │   ├── smtp_socket_executor.py
│       │   └── timeout_policy.py
│       │
│       ├── tools/
│       │   ├── base.py
│       │   ├── registry.py
│       │   ├── nmap_tool.py
│       │   ├── swaks_tool.py
│       │   ├── openssl_tool.py
│       │   ├── smtp_user_enum_tool.py
│       │   └── manual_smtp_tool.py
│       │
│       ├── checks/
│       │   ├── base.py
│       │   ├── registry.py
│       │   ├── port_detection.py
│       │   ├── banner_grab.py
│       │   ├── ehlo_capabilities.py
│       │   ├── starttls_check.py
│       │   ├── auth_method_check.py
│       │   ├── vrfy_user_enum.py
│       │   ├── expn_user_enum.py
│       │   ├── rcpt_to_user_enum.py
│       │   ├── open_relay_check.py
│       │   ├── spoofing_check.py
│       │   └── header_analysis.py
│       │
│       ├── parsers/
│       │   ├── base.py
│       │   ├── nmap_parser.py
│       │   ├── ehlo_parser.py
│       │   ├── smtp_response_parser.py
│       │   ├── user_enum_parser.py
│       │   ├── relay_parser.py
│       │   ├── tls_parser.py
│       │   └── header_parser.py
│       │
│       ├── models/
│       │   ├── smtp_capability.py
│       │   ├── auth_method.py
│       │   ├── smtp_user.py
│       │   ├── relay_test.py
│       │   ├── tls_result.py
│       │   ├── hostname.py
│       │   ├── domain.py
│       │   ├── finding.py
│       │   ├── control.py
│       │   └── agent_action.py
│       │
│       ├── analyzers/
│       │   ├── capability_analyzer.py
│       │   ├── identity_analyzer.py
│       │   ├── relay_analyzer.py
│       │   ├── spoofing_analyzer.py
│       │   ├── org_intelligence_analyzer.py
│       │   ├── control_analyzer.py
│       │   └── attack_path_analyzer.py
│       │
│       ├── writers/
│       │   ├── output_tree.py
│       │   ├── json_writer.py
│       │   ├── text_writer.py
│       │   ├── markdown_writer.py
│       │   └── evidence_writer.py
│       │
│       ├── report/
│       │   ├── executive_summary.py
│       │   ├── technical_summary.py
│       │   ├── evidence_appendix.py
│       │   ├── secure_controls.py
│       │   └── remediation.py
│       │
│       └── agent/
│           ├── next_action_builder.py
│           ├── credential_candidate_builder.py
│           ├── network_recon_lead_builder.py
│           ├── social_engineering_context_builder.py
│           └── do_not_retry_builder.py
│
└── tests/
    ├── unit/
    ├── integration/
    └── fixtures/
```

---

## Design Principles

### Single Responsibility Principle

Each class and function should have one reason to change.

Examples:

- `NmapTool` only executes Nmap.
- `NmapParser` only parses Nmap output.
- `CapabilityAnalyzer` only interprets normalized SMTP capabilities.
- `MarkdownWriter` only writes markdown files.
- `OpenRelayCheck` only performs open relay tests.

Do not combine execution, parsing, analysis, and writing in the same function.

---

### Open/Closed Principle

The package should be open for extension but closed for modification.

Use registries for:

- Tool adapters
- Recon checks
- Parsers
- Analyzers
- Report sections
- Agent-output builders

Adding a new SMTP check should not require editing a long conditional block in the orchestrator.

Example pattern:

---

```python
CHECK_REGISTRY = {
    "ehlo_capabilities": EhloCapabilitiesCheck,
    "starttls": StartTlsCheck,
    "vrfy_user_enum": VrfyUserEnumCheck,
    "expn_user_enum": ExpnUserEnumCheck,
    "rcpt_to_user_enum": RcptToUserEnumCheck,
    "open_relay": OpenRelayCheck,
    "spoofing": SpoofingCheck,
}
```

---

The orchestrator should load checks from the registry based on configuration.

---

### Liskov Substitution Principle

All check classes should share a stable interface.

Example:

---

```python
class ReconCheck(Protocol):
    name: str

    def run(self, context: ScanContext) -> CheckResult:
        ...
```

---

Any check should be replaceable without changing the orchestrator.

---

### Interface Segregation Principle

Avoid large interfaces that force classes to implement methods they do not need.

Separate interfaces such as:

- `ToolRunner`
- `Parser`
- `Analyzer`
- `Writer`
- `ReportSectionBuilder`
- `AgentOutputBuilder`

---

### Dependency Inversion Principle

High-level orchestration should depend on abstractions, not concrete subprocess calls.

The orchestrator should depend on interfaces like:

- `ReconCheck`
- `EvidenceWriter`
- `OutputWriter`
- `ToolRunner`

This makes the package easier to test and easier to extend.

---

## Execution Flow

The package should run in the following order:

---

```text
1. Create scan context
2. Create target output directory
3. Detect open SMTP-related ports
4. Fingerprint service and banner
5. Run EHLO/HELO capability checks
6. Check STARTTLS and TLS behavior
7. Identify authentication methods
8. Run user enumeration methods
9. Run relay and spoofing tests
10. Parse and normalize raw results
11. Analyze attack paths and blocked paths
12. Build org intelligence
13. Build security-control observations
14. Build agent next-action files
15. Build report markdown files
16. Write final scan summary
```

---

## SMTP Ports to Check

Default candidate ports:

---

```json
{
  "smtp": [25],
  "submission": [587],
  "smtps": [465],
  "alternate_smtp": [2525]
}
```

---

The package should allow users to override ports with CLI arguments.

---

## Required External Tools

The package should support tool adapters for the following external tools.

### Nmap

Purpose:

- Port detection
- Service fingerprinting
- SMTP command enumeration
- Open relay checks
- User enumeration checks where applicable

Recommended scripts:

---

```text
smtp-commands
smtp-open-relay
smtp-enum-users
smtp-vuln-cve2010-4344
smtp-vuln-cve2011-1720
smtp-vuln-cve2011-1764
```

---

The package should not blindly trust Nmap results. All high-risk findings should include raw evidence and, when possible, manual or secondary-tool validation.

---

### swaks

Purpose:

- Open relay testing
- Sender spoofing tests
- Authentication behavior testing
- STARTTLS testing
- Controlled message submission tests

Expected raw output:

---

```text
raw/swaks/relay_tests.txt
raw/swaks/spoofing_tests.txt
raw/swaks/auth_tests.txt
```

---

### openssl

Purpose:

- SMTPS testing on port 465
- STARTTLS inspection where supported
- Certificate collection
- TLS version and cipher evidence

Example command shape:

---

```text
openssl s_client -connect <target>:465
openssl s_client -starttls smtp -connect <target>:587
```

---

### smtp-user-enum

Purpose:

- Automated username enumeration using `VRFY`, `EXPN`, or `RCPT TO`.

The package should support this as optional, because some environments may not have it installed.

---

### Native Python Socket Client

Purpose:

- Manual SMTP conversation reproduction
- EHLO/HELO
- VRFY
- EXPN
- RCPT TO
- STARTTLS behavior checks

This is important because external tools may produce false positives or hide the protocol details needed for reporting.

---

## Check Design

Each check should return a structured `CheckResult`.

---

```python
@dataclass
class CheckResult:
    name: str
    target: str
    port: int
    status: Literal["success", "blocked", "failed", "inconclusive", "skipped"]
    summary: str
    raw_evidence_paths: list[str]
    normalized_output_paths: list[str]
    findings: list[Finding]
    controls_observed: list[ControlObservation]
    errors: list[str]
```

---

Do not throw away failed results. A blocked result is valuable for both agents and reporting.

---

## User Enumeration Requirements

The package should test multiple enumeration methods:

1. `VRFY`
2. `EXPN`
3. `RCPT TO`

Each tested username should be classified as:

- `confirmed`
- `rejected`
- `ambiguous`
- `blocked`
- `error`

The package must handle SMTP response code ambiguity.

For example, response code `252` may indicate that the server cannot verify the user but will accept the message. This should not automatically be treated as confirmed.

Recommended confidence model:

---

```json
{
  "username": "alice",
  "method": "VRFY",
  "response_code": 252,
  "classification": "ambiguous",
  "confidence": 0.35,
  "evidence": "252 2.0.0 alice",
  "notes": "Server accepts ambiguous VRFY responses for tested fake users. Do not treat as confirmed."
}
```

---

The package should include canary usernames such as clearly fake values to detect false-positive behavior.

Example:

---

```text
notarealuser-<random>
aaaaaaaaaaaaaaaaaaaaaaaaaaaa
smtp-recon-canary-<timestamp>
```

---

If fake users and real candidates receive identical responses, mark the method as unreliable.

---

## Open Relay Test Requirements

The open relay test should use a matrix of sender and recipient combinations.

Example matrix:

---

```json
[
  {
    "from": "external@example.com",
    "to": "external@example.net",
    "expected_secure_result": "blocked"
  },
  {
    "from": "internal@target-domain.local",
    "to": "external@example.net",
    "expected_secure_result": "blocked"
  },
  {
    "from": "external@example.com",
    "to": "internal@target-domain.local",
    "expected_secure_result": "accepted_or_blocked_based_on_scope"
  },
  {
    "from": "internal@target-domain.local",
    "to": "internal@target-domain.local",
    "expected_secure_result": "accepted_or_blocked_based_on_scope"
  }
]
```

---

Classify each relay attempt as:

- `accepted`
- `rejected`
- `requires_authentication`
- `blocked_by_policy`
- `inconclusive`
- `not_tested_scope_limited`

Do not send real spam or harmful messages. Use safe, controlled test addresses and clearly marked test content.

---

## Spoofing Test Requirements

Spoofing tests should determine whether the server accepts forged sender identities.

Test cases should include:

1. External sender to internal recipient.
2. Internal-looking sender to internal recipient.
3. Internal-looking sender to external recipient.
4. Known invalid domain sender.

Record whether spoofing is:

- Accepted by SMTP transaction.
- Blocked during SMTP transaction.
- Accepted but likely filtered later.
- Not tested due to scope.

The package should distinguish between protocol acceptance and actual inbox delivery.

---

## Authentication and TLS Requirements

The package should record:

- Whether STARTTLS is advertised.
- Whether STARTTLS succeeds.
- Whether authentication is advertised before STARTTLS.
- Whether authentication is advertised after STARTTLS.
- Which AUTH mechanisms are available.
- Whether plaintext authentication mechanisms are exposed.
- Whether certificates are self-signed, expired, mismatched, or weak.

Output files:

---

```text
normalized/auth_methods.json
normalized/tls_encryption.json
security_controls/starttls_supported.json
security_controls/auth_required.json
failures_and_dead_ends/tls_failures.json
```

---

## Org Intelligence Requirements

The package should extract and infer:

- Domains
- Subdomains
- Hostnames
- Mail server names
- Internal naming conventions
- Possible departments or roles from email addresses
- Email format patterns

Example outputs:

---

```json
{
  "patterns": [
    {
      "pattern": "first.last@domain.com",
      "confidence": 0.8,
      "evidence": ["jane.doe@domain.com", "john.smith@domain.com"]
    },
    {
      "pattern": "first_initial_last@domain.com",
      "confidence": 0.4,
      "evidence": ["jsmith@domain.com"]
    }
  ]
}
```

---

This information should be stored separately from confirmed vulnerabilities because it is supporting intelligence, not necessarily a finding.

---

## Security Controls That Work

The package must explicitly record secure behavior.

Examples:

- `VRFY` disabled.
- `EXPN` disabled.
- Relay attempts blocked.
- Authentication required for submission.
- STARTTLS supported.
- AUTH not advertised until after STARTTLS.
- Banner does not disclose software version.
- Rate limiting observed.

This matters because future agents need to know what not to waste time retesting, and reports should include positive observations when useful.

---

## Failure and Dead-End Requirements

Failures should be first-class outputs.

Examples:

---

```json
{
  "test": "VRFY enumeration",
  "status": "blocked",
  "reason": "Server returned 502 command not implemented",
  "evidence_file": "raw/manual_sessions/vrfy_session.txt",
  "recommendation": "Do not retry VRFY. Try RCPT TO only if in scope."
}
```

---

The `do_not_retry.json` file should summarize blocked or unhelpful paths.

---

## Agent Output Requirements

The package should generate files specifically designed for future automated agents.

### `next_actions.json`

Should contain prioritized follow-up actions.

Example:

---

```json
[
  {
    "priority": "high",
    "action": "Use confirmed SMTP users as candidates for password-spray planning if authorized.",
    "reason": "VRFY confirmed 12 users with high confidence.",
    "evidence": "identity_enumeration/confirmed_users.txt"
  },
  {
    "priority": "medium",
    "action": "Use discovered hostnames for DNS and certificate correlation.",
    "reason": "EHLO banner disclosed mail1.internal.example.com.",
    "evidence": "normalized/hostnames.json"
  }
]
```

---

### `credential_attack_candidates.json`

Should contain usernames and domains that may be useful later, but must not perform credential attacks by default.

---

### `phishing_or_social_engineering_inputs.json`

Should contain email formats, role accounts, and naming patterns. The package should only record data; it should not generate phishing content.

---

### `network_recon_leads.json`

Should contain hostnames, MX-like patterns, internal domains, and mail routing clues.

---

### `do_not_retry.json`

Should contain blocked methods, false-positive risks, and noisy checks that should not be repeated.

---

## Report Output Requirements

The report layer should produce human-readable markdown.

### `executive_summary.md`

Should include:

- High-level risk statement
- Whether user enumeration was possible
- Whether open relay was possible
- Whether spoofing was possible
- Whether encryption/auth controls were present
- Overall business impact

### `technical_summary.md`

Should include:

- Ports tested
- SMTP commands observed
- Authentication methods observed
- User enumeration results
- Relay test results
- Spoofing results
- TLS/STARTTLS details
- Relevant raw evidence links

### `evidence_appendix.md`

Should include:

- Raw command snippets
- Response codes
- Tool output references
- Test matrix details

### `secure_controls_observed.md`

Should include controls that worked.

### `remediation_notes.md`

Should include suggested fixes:

- Disable `VRFY` and `EXPN` where possible.
- Restrict relay to trusted authenticated users and trusted internal ranges only.
- Require authentication for submission.
- Require STARTTLS before authentication.
- Avoid verbose banners.
- Enforce SPF, DKIM, and DMARC where applicable.
- Monitor suspicious SMTP enumeration and relay attempts.

---

## CLI Requirements

The package should expose a CLI.

Example:

---

```text
smtp-recon scan --target 10.129.14.128 --domain inlanefreight.htb --users users.txt --output smtp_recon/
```

---

Recommended options:

---

```text
--target                 Target IP or hostname
--domain                 Known target domain
--ports                  Comma-separated port list
--users                  Username wordlist
--from-address           Controlled sender address for tests
--to-address             Controlled recipient address for tests
--safe-mode              Avoid message submission or relay attempts
--skip-relay             Skip open relay tests
--skip-spoofing          Skip spoofing tests
--skip-user-enum         Skip user enumeration tests
--timeout                Network timeout
--output                 Output root directory
--format                 json, markdown, or both
--verbose                Enable verbose logging
```

---

Safe mode should be enabled by default unless the user explicitly enables relay or spoofing tests.

---

## Configuration File

The package should support a YAML or TOML config file.

Example:

---

```yaml
target: 10.129.14.128
domain: inlanefreight.htb
ports:
  - 25
  - 465
  - 587
checks:
  ehlo_capabilities: true
  starttls: true
  auth_methods: true
  vrfy_user_enum: true
  expn_user_enum: true
  rcpt_to_user_enum: true
  open_relay: false
  spoofing: false
safety:
  safe_mode: true
  max_messages_to_send: 0
  require_explicit_relay_permission: true
output:
  root: smtp_recon
  write_raw: true
  write_json: true
  write_markdown: true
```

---

## Testing Requirements

The package must include unit tests and integration tests.

### Unit Tests

Test:

- SMTP response parsing
- EHLO capability parsing
- AUTH method extraction
- STARTTLS detection
- User classification logic
- Relay result classification
- Output path generation
- JSON serialization
- Report section rendering

### Integration Tests

Use local test services where possible.

Recommended tools:

- Dockerized Postfix
- Dockerized MailHog
- Fake SMTP test server
- Python `aiosmtpd` test server

### Fixture Requirements

Include raw sample outputs for:

- Successful EHLO
- STARTTLS supported
- STARTTLS missing
- VRFY confirmed user
- VRFY rejected user
- VRFY ambiguous `252`
- EXPN disabled
- RCPT TO accepted
- Open relay blocked
- Open relay accepted in test lab
- Self-signed certificate

---

## Data Modeling Guidance

Use dataclasses or Pydantic models for normalized outputs.

Recommended models:

- `Target`
- `ScanContext`
- `PortDetectionResult`
- `SmtpCapability`
- `AuthMethod`
- `TlsResult`
- `SmtpUserResult`
- `RelayAttempt`
- `SpoofingAttempt`
- `DomainObservation`
- `HostnameObservation`
- `ControlObservation`
- `Finding`
- `AgentAction`

Models should be serializable to JSON without custom one-off serialization logic scattered across the package.

---

## Logging Requirements

The package should log:

- Check started
- Check completed
- Tool command executed
- Tool timeout
- Parser errors
- Classification decisions
- Files written

Do not log credentials or sensitive supplied secrets.

---

## Error Handling Requirements

The package should gracefully handle:

- Connection refused
- Timeout
- STARTTLS failure
- Unsupported command
- Tool not installed
- Permission errors writing output
- Invalid target input
- Empty user wordlist
- Ambiguous SMTP responses

Errors should be written to structured outputs, not just printed to the console.

---

## Safety Requirements

The package must be designed for authorized testing only.

Default behavior should be conservative:

- Do not send real emails by default.
- Do not perform brute-force password attacks.
- Do not perform credential stuffing.
- Do not generate phishing content.
- Do not test external recipients unless explicitly configured.
- Do not treat ambiguous user enumeration as confirmed.
- Do not repeatedly retry blocked commands.

The package may collect candidate usernames for later authorized testing, but it should not perform password spraying itself.

---

## Example Finding Object

---

```json
{
  "id": "SMTP-USER-ENUM-VRFY-001",
  "title": "SMTP VRFY User Enumeration Possible",
  "severity": "medium",
  "status": "validated",
  "description": "The SMTP server disclosed valid user accounts through VRFY responses.",
  "impact": "An attacker could build a valid username list for password attacks or social engineering.",
  "evidence": [
    "raw/manual_sessions/vrfy_session.txt",
    "identity_enumeration/confirmed_users.txt"
  ],
  "recommendation": "Disable VRFY or configure the SMTP server to return non-disclosing responses."
}
```

---

## Example Secure Behavior Object

---

```json
{
  "control": "Open relay restriction",
  "status": "working",
  "description": "External-to-external relay attempts were rejected by policy.",
  "evidence": "trust_boundary_tests/open_relay/blocked_relay_attempts.json",
  "report_note": "The SMTP server did not operate as an open relay during testing."
}
```

---

## Example `do_not_retry.json`

---

```json
[
  {
    "method": "EXPN enumeration",
    "reason": "Server returned 502 command not implemented for all test cases.",
    "evidence": "raw/manual_sessions/expn_session.txt",
    "recommendation": "Do not retry EXPN unless server configuration changes."
  },
  {
    "method": "VRFY enumeration",
    "reason": "Server returned identical 252 responses for real candidates and canary users.",
    "evidence": "identity_enumeration/vrfy_results.json",
    "recommendation": "Treat VRFY as unreliable. Prefer RCPT TO behavior only if authorized."
  }
]
```

---

## Implementation Milestones

### Milestone 1: Project Skeleton

Deliver:

- Package layout
- CLI shell
- Config loader
- Output tree builder
- Logging
- Base interfaces

### Milestone 2: Basic SMTP Fingerprinting

Deliver:

- Port detection
- Banner grab
- EHLO capability parsing
- STARTTLS detection
- AUTH method extraction

### Milestone 3: User Enumeration

Deliver:

- VRFY check
- EXPN check
- RCPT TO check
- Canary false-positive detection
- Confidence scoring

### Milestone 4: Trust Boundary Tests

Deliver:

- Open relay test matrix
- Spoofing test matrix
- Safe-mode restrictions
- Blocked/accepted classification

### Milestone 5: Analysis and Reporting

Deliver:

- Attack path analyzer
- Secure control analyzer
- Agent output builders
- Markdown report generation

### Milestone 6: Test Harness

Deliver:

- Unit tests
- Integration tests
- Fixtures
- Mock tool executors

---

## Done Criteria

The package is complete when:

1. It can scan a target SMTP service and create the full output directory.
2. It saves raw evidence for every check.
3. It produces normalized JSON for capabilities, auth, TLS, users, relay, spoofing, hostnames, and domains.
4. It records failed, blocked, skipped, and inconclusive checks.
5. It produces `next_actions.json` and `do_not_retry.json` for future agents.
6. It produces markdown report files for human review.
7. It has unit tests for parsers and classification logic.
8. It uses registries instead of long conditional blocks.
9. It keeps execution, parsing, analysis, and writing separated.
10. It defaults to safe behavior and avoids unauthorized or noisy actions.

---

## Final Architecture Rule

The orchestrator should coordinate the package, not contain the package logic.

Good orchestrator behavior:

---

```text
load config → build context → run registered checks → collect results → run analyzers → write outputs
```

---

Bad orchestrator behavior:

---

```text
run subprocess → parse strings → classify findings → write files → decide next steps inside one giant function
```

---

Keep the system modular, explicit, testable, and easy to extend.
