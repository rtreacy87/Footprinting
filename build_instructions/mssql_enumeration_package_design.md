# MSSQL Enumeration Python Package Design

## Purpose

This document describes how to build a Python package for Microsoft SQL Server (MSSQL) enumeration. The goal is similar to the SNMP and MySQL enumeration packages: connect to the service, pull down as much useful metadata as authorized, normalize it into structured output, and produce human-readable summaries that help a penetration tester quickly identify useful recon findings.

MSSQL should not be treated as “just a database.” It is often a bridge between:

- Application data
- Windows authentication
- Active Directory identities
- Service accounts
- Host-level command execution
- Lateral movement through linked servers

The package should focus on **authorized enumeration**, not exploitation. It should collect evidence and flag risky configurations without automatically performing destructive actions.

---

## High-Level Objectives

The package should answer these questions:

1. What MSSQL services and instances are exposed?
2. What version and configuration is the server running?
3. What authentication methods are available?
4. What databases, schemas, tables, and columns exist?
5. What users, roles, permissions, and server-level privileges exist?
6. Are there dangerous features enabled, such as `xp_cmdshell`?
7. Are there linked servers that may allow pivoting?
8. Are SQL Agent jobs configured?
9. Are there stored credentials, connection strings, secrets, or sensitive tables?
10. What findings should be prioritized by a tester?

---

## Important MSSQL Recon Categories

### 1. Service and Instance Metadata

Collect:

- Target IP / hostname
- TCP port, usually `1433`
- MSSQL instance name
- Server hostname
- SQL Server version
- Product edition
- Whether named pipes are enabled
- Whether encryption is required
- Whether the server uses a self-signed certificate
- Whether the Dedicated Administrator Connection, DAC, is exposed

Useful because this tells the tester what they are dealing with and helps identify version-specific risks.

---

### 2. Authentication Information

Determine:

- Whether Windows Authentication is supported
- Whether SQL Authentication is supported
- Whether mixed mode authentication is enabled
- Whether the `sa` account exists
- Whether weak, blank, or default credentials are accepted, **only if explicitly authorized**
- Which login was used for enumeration
- Whether the login has low privilege or elevated privilege

Important note: credential testing should be configurable and off by default unless the tester provides an approved credential list and authorization.

---

### 3. Database Inventory

Collect:

- Database names
- Database owners
- Creation dates
- Recovery model
- Trustworthy setting
- Read-only status
- Online/offline status
- Compatibility level

Default system databases to recognize:

| Database | Purpose |
|---|---|
| `master` | System-wide SQL Server metadata |
| `model` | Template for new databases |
| `msdb` | SQL Agent jobs, alerts, schedules, backup history |
| `tempdb` | Temporary objects |
| `resource` | Read-only system objects |

For each non-system database, enumerate schemas, tables, views, procedures, and columns.

---

### 4. Tables, Columns, and Sensitive Data Hints

The package should not dump full table contents by default. Instead, it should first collect metadata and classify potentially interesting tables and columns.

Look for table or column names containing:

- `user`
- `account`
- `login`
- `password`
- `passwd`
- `pwd`
- `hash`
- `token`
- `secret`
- `key`
- `apikey`
- `api_key`
- `connection`
- `connstr`
- `credential`
- `session`
- `jwt`
- `oauth`
- `saml`
- `ldap`
- `ad`
- `domain`
- `employee`
- `customer`
- `payment`
- `card`
- `ssn`
- `dob`
- `email`
- `phone`

Optional controlled sampling mode:

- Pull only the first `N` rows from flagged tables
- Redact values by default
- Store hashes/previews instead of raw sensitive values unless explicitly requested
- Clearly mark sampled data as sensitive

Recommended default: metadata-only mode.

---

### 5. Users, Roles, and Permissions

Collect server-level principals:

- SQL logins
- Windows logins
- Windows groups
- Disabled accounts
- Password policy status where available
- Server roles
- Members of privileged roles

Important roles:

- `sysadmin`
- `serveradmin`
- `securityadmin`
- `setupadmin`
- `processadmin`
- `diskadmin`
- `dbcreator`
- `bulkadmin`

Collect database-level principals:

- Database users
- Database roles
- Role memberships
- Explicit grants, denies, and revokes
- Ownership chains

Flag high-value conditions:

- Current user is `sysadmin`
- Current user can impersonate another login
- Current user can alter server configuration
- Current user can create jobs
- Current user owns databases
- Guest access enabled on user databases
- Excessive permissions granted to public role

---

### 6. Execution Paths

MSSQL can sometimes become a path to operating-system-level execution.

Check whether these are enabled or available:

- `xp_cmdshell`
- Ole Automation Procedures
- CLR integration
- SQL Agent jobs
- External scripts
- Ad Hoc Distributed Queries
- `OPENROWSET`
- `BULK INSERT`
- Unsafe assemblies

The package should **detect and report** these features. It should not automatically execute OS commands unless a deliberate `--execute-checks` or similar flag is enabled.

Recommended behavior:

- Safe mode: detect only
- Verification mode: run harmless checks, such as `whoami`, only with explicit authorization
- Exploit mode: out of scope for this package

---

### 7. Linked Servers

Linked servers are one of the most important MSSQL pivot paths.

Collect:

- Linked server names
- Provider names
- Data source
- Product name
- Catalog
- Security context configuration
- Whether RPC is enabled
- Whether RPC Out is enabled
- Whether data access is enabled
- Whether the current login can query the linked server

Flag:

- Linked servers using stored credentials
- Linked servers reachable with elevated privileges
- Linked servers where `rpc out` is enabled
- Chains of linked servers
- Links into higher-value environments

The package should build a graph:

```text
Current MSSQL Instance
        |
        |-- LinkedServerA
        |       |-- LinkedServerB
        |
        |-- LinkedServerC
```

This graph can later be exported to JSON for agent review or visualized with Graphviz.

---

### 8. SQL Agent Jobs

SQL Agent jobs are often overlooked but extremely useful for recon.

Collect from `msdb` when permitted:

- Job names
- Job owners
- Enabled/disabled status
- Schedules
- Job steps
- Subsystems used
- Commands run by job steps
- Proxy accounts
- Last run status
- Last run time

Flag:

- Jobs owned by privileged accounts
- Jobs running PowerShell, CmdExec, SSIS, or external commands
- Jobs containing passwords or connection strings
- Jobs writing to network paths
- Jobs running as service accounts

---

### 9. Credentials and Secrets

Look for credentials in:

- SQL tables
- Stored procedures
- Views
- SQL Agent jobs
- Linked server definitions
- Connection strings
- Application config tables
- Backup metadata
- SSIS packages, if accessible
- SQL Server credentials
- Proxy accounts

Potentially useful queries include metadata searches across object definitions for strings such as:

- `password`
- `pwd`
- `secret`
- `token`
- `apikey`
- `connection string`
- `Data Source=`
- `User ID=`
- `Initial Catalog=`

The package should redact discovered values by default and store enough context for the tester to manually inspect later.

---

## Recommended Tooling

### Tools Highlighted in the Module

| Tool | Purpose |
|---|---|
| `nmap` | Service detection and MSSQL NSE scripts |
| `ms-sql-info` | MSSQL version and instance metadata |
| `ms-sql-empty-password` | Checks for empty SQL passwords |
| `ms-sql-config` | Attempts to enumerate server config |
| `ms-sql-ntlm-info` | Pulls Windows/NTLM host metadata |
| `ms-sql-tables` | Enumerates tables when credentials are available |
| `ms-sql-hasdbaccess` | Checks DB access for provided credentials |
| `ms-sql-dac` | Checks Dedicated Admin Connection exposure |
| `ms-sql-dump-hashes` | Attempts hash dumping when permissions allow |
| Metasploit `mssql_ping` | MSSQL instance discovery |
| Impacket `mssqlclient.py` | Interactive MSSQL client useful for pentesters |

### Additional Tools Worth Supporting

| Tool | Purpose |
|---|---|
| `pyodbc` | Python MSSQL connectivity through ODBC |
| `pymssql` | Python-native MSSQL connectivity option |
| `impacket` | MSSQL client and Windows-auth workflows |
| `ldap3` | Optional AD context enrichment when domain creds are available |
| `BloodHound` / `SharpHound` | Not part of the package, but useful for AD pivot context |
| `PowerUpSQL` | Excellent Windows-side MSSQL post-exploitation and audit toolkit |
| `CrackMapExec` / `NetExec` | Credential validation and lateral movement context |

The Python package should not require every tool. It should support a core Python-only path and optional integrations.

---

## Package Architecture

Suggested package name:

```text
mssql_enum/
```

Suggested structure:

```text
mssql_enum/
├── __init__.py
├── cli.py
├── config.py
├── connection.py
├── models.py
├── scanner.py
├── queries/
│   ├── __init__.py
│   ├── server_info.py
│   ├── databases.py
│   ├── principals.py
│   ├── permissions.py
│   ├── tables.py
│   ├── execution_paths.py
│   ├── linked_servers.py
│   ├── agent_jobs.py
│   └── secrets.py
├── collectors/
│   ├── __init__.py
│   ├── nmap_collector.py
│   ├── sql_collector.py
│   ├── impacket_collector.py
│   └── metasploit_collector.py
├── transforms/
│   ├── __init__.py
│   ├── normalizer.py
│   ├── classifier.py
│   ├── risk_scoring.py
│   └── redact.py
├── outputs/
│   ├── __init__.py
│   ├── json_writer.py
│   ├── markdown_writer.py
│   ├── csv_writer.py
│   └── graph_writer.py
└── report_templates/
    ├── host_summary.md.j2
    ├── database_summary.md.j2
    ├── privilege_summary.md.j2
    ├── linked_server_summary.md.j2
    └── findings_summary.md.j2
```

---

## Execution Flow

### Phase 1: Target Setup

Input options:

```bash
mssql-enum \
  --target 10.129.201.248 \
  --port 1433 \
  --username sa \
  --password 'Password123!' \
  --auth sql \
  --output ./output/mssql/10.129.201.248
```

Support authentication modes:

```text
sql
windows
windows-kerberos
windows-ntlm
trusted-connection
no-auth-discovery
```

---

### Phase 2: Pre-Authentication Discovery

Run safe checks first:

1. TCP connectivity check
2. Optional Nmap scan
3. MSSQL instance discovery
4. Version fingerprinting
5. NTLM metadata collection if exposed
6. Named pipe detection
7. Encryption requirement detection

Output files:

```text
output/<target>/raw/nmap_mssql.xml
output/<target>/raw/service_fingerprint.json
output/<target>/normalized/server_identity.json
```

---

### Phase 3: Authentication Check

Try the configured credentials.

Collect:

- Login success/failure
- Login name
- Effective user
- Server roles
- Database access
- Whether the login is sysadmin

Output:

```text
output/<target>/normalized/auth_context.json
```

Do not perform credential spraying by default.

---

### Phase 4: Server-Level Enumeration

Collect:

- SQL Server version
- Edition
- Hostname
- Instance name
- Server properties
- Configuration values
- Enabled advanced options
- Logins
- Server roles
- Role memberships
- Linked servers
- Dangerous features

Output:

```text
output/<target>/normalized/server_config.json
output/<target>/normalized/server_principals.json
output/<target>/normalized/server_permissions.json
output/<target>/normalized/execution_paths.json
output/<target>/normalized/linked_servers.json
```

---

### Phase 5: Database-Level Enumeration

For each accessible database:

Collect:

- Schemas
- Tables
- Columns
- Views
- Stored procedures
- Database users
- Database roles
- Role memberships
- Explicit permissions
- Sensitive-name matches

Output:

```text
output/<target>/databases/<database_name>/metadata.json
output/<target>/databases/<database_name>/tables.json
output/<target>/databases/<database_name>/columns.json
output/<target>/databases/<database_name>/permissions.json
output/<target>/databases/<database_name>/sensitive_candidates.json
```

---

### Phase 6: SQL Agent Enumeration

If the user can access `msdb`, collect SQL Agent information.

Output:

```text
output/<target>/normalized/sql_agent_jobs.json
output/<target>/reports/sql_agent_jobs.md
```

---

### Phase 7: Secret and Sensitive Object Classification

Run classifiers over metadata, object definitions, and optionally sampled rows.

Classification categories:

```text
credential_candidate
api_secret_candidate
connection_string_candidate
pii_candidate
authentication_table
application_config
job_execution_risk
linked_server_pivot
privilege_escalation_candidate
```

Output:

```text
output/<target>/findings/sensitive_candidates.json
output/<target>/findings/risk_findings.json
```

---

### Phase 8: Report Generation

Generate a human-readable report.

Output:

```text
output/<target>/report.md
output/<target>/summary.md
output/<target>/findings.md
```

The report should include:

1. Executive summary
2. Connection context
3. Server metadata
4. Authentication context
5. Databases discovered
6. High-value tables and columns
7. Users and role findings
8. Dangerous configuration findings
9. Linked server findings
10. SQL Agent job findings
11. Recommended next manual checks
12. Raw artifact index

---

## Suggested Data Model

### ServerIdentity

```json
{
  "target": "10.129.201.248",
  "port": 1433,
  "hostname": "SQL-01",
  "instance_name": "MSSQLSERVER",
  "version": "Microsoft SQL Server 2019",
  "version_number": "15.00.2000.00",
  "named_pipe": "\\\\10.129.201.248\\pipe\\sql\\query",
  "clustered": false
}
```

### AuthContext

```json
{
  "auth_mode": "sql",
  "login": "sa",
  "connected": true,
  "effective_user": "dbo",
  "is_sysadmin": true,
  "accessible_databases": ["master", "msdb", "Employees"]
}
```

### DatabaseMetadata

```json
{
  "database": "Employees",
  "owner": "sa",
  "state": "ONLINE",
  "is_read_only": false,
  "tables": 42,
  "views": 8,
  "procedures": 15,
  "sensitive_candidates": 6
}
```

### Finding

```json
{
  "id": "MSSQL-EXEC-001",
  "severity": "high",
  "category": "execution_path",
  "title": "xp_cmdshell is enabled",
  "description": "The server has xp_cmdshell enabled, which may allow OS command execution if the current login has sufficient privileges.",
  "evidence": {
    "config_name": "xp_cmdshell",
    "value": 1
  },
  "recommended_manual_check": "Verify whether the current login can execute xp_cmdshell using an approved harmless command."
}
```

---

## Important Queries

### Current Login and User

```sql
SELECT
    SYSTEM_USER AS system_user,
    CURRENT_USER AS current_user,
    ORIGINAL_LOGIN() AS original_login,
    SUSER_SNAME() AS suser_sname;
```

### Check Sysadmin

```sql
SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;
```

### Server Version

```sql
SELECT @@VERSION AS version;
```

### Server Properties

```sql
SELECT
    SERVERPROPERTY('MachineName') AS machine_name,
    SERVERPROPERTY('ServerName') AS server_name,
    SERVERPROPERTY('InstanceName') AS instance_name,
    SERVERPROPERTY('Edition') AS edition,
    SERVERPROPERTY('ProductVersion') AS product_version,
    SERVERPROPERTY('ProductLevel') AS product_level;
```

### Databases

```sql
SELECT
    name,
    database_id,
    create_date,
    state_desc,
    recovery_model_desc,
    containment_desc,
    is_read_only,
    is_trustworthy_on
FROM sys.databases
ORDER BY name;
```

### Server Logins

```sql
SELECT
    name,
    type_desc,
    is_disabled,
    create_date,
    modify_date,
    default_database_name
FROM sys.server_principals
WHERE type IN ('S', 'U', 'G')
ORDER BY name;
```

### Server Role Memberships

```sql
SELECT
    roles.name AS role_name,
    members.name AS member_name,
    members.type_desc AS member_type
FROM sys.server_role_members srm
JOIN sys.server_principals roles
    ON srm.role_principal_id = roles.principal_id
JOIN sys.server_principals members
    ON srm.member_principal_id = members.principal_id
ORDER BY roles.name, members.name;
```

### Configuration Values

```sql
SELECT
    name,
    value,
    value_in_use,
    description,
    is_dynamic,
    is_advanced
FROM sys.configurations
ORDER BY name;
```

### Execution-Related Configuration

```sql
SELECT
    name,
    value,
    value_in_use
FROM sys.configurations
WHERE name IN (
    'xp_cmdshell',
    'Ole Automation Procedures',
    'clr enabled',
    'Ad Hoc Distributed Queries',
    'external scripts enabled'
);
```

### Linked Servers

```sql
SELECT
    name,
    product,
    provider,
    data_source,
    catalog,
    is_linked,
    is_remote_login_enabled,
    is_rpc_out_enabled,
    is_data_access_enabled
FROM sys.servers
WHERE is_linked = 1;
```

### Database Tables and Columns

```sql
SELECT
    TABLE_CATALOG,
    TABLE_SCHEMA,
    TABLE_NAME,
    COLUMN_NAME,
    DATA_TYPE,
    CHARACTER_MAXIMUM_LENGTH,
    IS_NULLABLE
FROM INFORMATION_SCHEMA.COLUMNS
ORDER BY TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION;
```

### Stored Procedure / View Definition Search

```sql
SELECT
    OBJECT_SCHEMA_NAME(object_id) AS schema_name,
    OBJECT_NAME(object_id) AS object_name,
    definition
FROM sys.sql_modules
WHERE definition LIKE '%password%'
   OR definition LIKE '%secret%'
   OR definition LIKE '%token%'
   OR definition LIKE '%connection%';
```

### SQL Agent Jobs

```sql
SELECT
    j.name AS job_name,
    j.enabled,
    SUSER_SNAME(j.owner_sid) AS owner_name,
    j.date_created,
    j.date_modified
FROM msdb.dbo.sysjobs j
ORDER BY j.name;
```

### SQL Agent Job Steps

```sql
SELECT
    j.name AS job_name,
    s.step_id,
    s.step_name,
    s.subsystem,
    s.command,
    s.database_name,
    s.proxy_id
FROM msdb.dbo.sysjobs j
JOIN msdb.dbo.sysjobsteps s
    ON j.job_id = s.job_id
ORDER BY j.name, s.step_id;
```

---

## Output Folder Structure

Each target should get its own output folder.

```text
output/
└── 10.129.201.248/
    ├── raw/
    │   ├── nmap_mssql.xml
    │   ├── nmap_mssql.txt
    │   └── tool_logs/
    ├── normalized/
    │   ├── server_identity.json
    │   ├── auth_context.json
    │   ├── server_config.json
    │   ├── server_principals.json
    │   ├── server_permissions.json
    │   ├── execution_paths.json
    │   ├── linked_servers.json
    │   └── sql_agent_jobs.json
    ├── databases/
    │   └── Employees/
    │       ├── metadata.json
    │       ├── tables.json
    │       ├── columns.json
    │       ├── permissions.json
    │       └── sensitive_candidates.json
    ├── findings/
    │   ├── risk_findings.json
    │   ├── sensitive_candidates.json
    │   └── linked_server_graph.json
    └── reports/
        ├── summary.md
        ├── findings.md
        ├── databases.md
        ├── privileges.md
        ├── linked_servers.md
        └── report.md
```

---

## Risk Scoring

Suggested scoring categories:

| Severity | Meaning |
|---|---|
| Critical | Likely direct path to host/domain compromise |
| High | Strong privilege escalation, command execution, or credential exposure path |
| Medium | Useful recon or misconfiguration requiring additional conditions |
| Low | Informational finding |

Examples:

| Finding | Severity |
|---|---|
| Current user is sysadmin | Critical |
| `xp_cmdshell` enabled and executable | Critical |
| Linked server with RPC Out enabled | High |
| SQL Agent job runs PowerShell as privileged owner | High |
| Sensitive credential-like table found | High |
| Named pipes enabled | Medium |
| Self-signed certificate | Medium |
| Version disclosed | Low |

---

## CLI Design

Example commands:

### Safe metadata enumeration

```bash
mssql-enum scan \
  --target 10.129.201.248 \
  --port 1433 \
  --safe \
  --output ./output
```

### Authenticated enumeration

```bash
mssql-enum enum \
  --target 10.129.201.248 \
  --port 1433 \
  --auth sql \
  --username sa \
  --password 'Password123!' \
  --output ./output
```

### Windows authentication

```bash
mssql-enum enum \
  --target 10.129.201.248 \
  --auth windows \
  --domain INLANEFREIGHT \
  --username svc_sql \
  --password 'Password123!' \
  --output ./output
```

### Metadata plus sensitive-name classification

```bash
mssql-enum enum \
  --target 10.129.201.248 \
  --auth sql \
  --username app_user \
  --password 'Password123!' \
  --classify-sensitive \
  --output ./output
```

### Explicit sampling mode

```bash
mssql-enum enum \
  --target 10.129.201.248 \
  --auth sql \
  --username app_user \
  --password 'Password123!' \
  --classify-sensitive \
  --sample-flagged-tables \
  --sample-size 5 \
  --redact-values \
  --output ./output
```

---

## Safe Defaults

The package should default to safe behavior:

- Do not brute-force credentials
- Do not dump full tables
- Do not execute OS commands
- Do not enable disabled features
- Do not modify server configuration
- Do not create SQL Agent jobs
- Do not write to databases
- Do not run destructive queries
- Redact sensitive values in reports
- Store raw sensitive artifacts separately, if collection is explicitly enabled

---

## Agent-Friendly Summary Output

A short summary file should be generated for LLM/agent review.

Example:

```markdown
# MSSQL Enumeration Summary: 10.129.201.248

## Identity

- Hostname: SQL-01
- Instance: MSSQLSERVER
- Version: Microsoft SQL Server 2019 RTM
- Port: 1433
- Named Pipe: \\10.129.201.248\pipe\sql\query

## Auth Context

- Auth mode: SQL
- Login: sa
- Effective user: dbo
- Sysadmin: yes

## High-Priority Findings

1. Current login is sysadmin.
2. xp_cmdshell is enabled.
3. Linked server `HR-SQL-02` has RPC Out enabled.
4. SQL Agent job `DailyExport` runs PowerShell and is owned by a privileged account.
5. Database `Employees` contains credential-like columns: `password_hash`, `api_token`.

## Recommended Manual Follow-Up

- Verify whether OS command execution is permitted under the engagement rules.
- Inspect linked server security context.
- Review SQL Agent job commands for embedded credentials.
- Review flagged credential-like tables with data owner approval.
```

---

## Development Milestones

### Milestone 1: Basic Discovery

- CLI skeleton
- TCP connectivity check
- Nmap wrapper
- Service fingerprint parser
- Markdown summary output

### Milestone 2: Authenticated SQL Enumeration

- SQL connection module
- Current user and role checks
- Database inventory
- Table and column inventory
- JSON output

### Milestone 3: Privilege and Misconfiguration Checks

- Server roles
- Database roles
- Permission extraction
- Execution path checks
- Risk scoring

### Milestone 4: Linked Server and SQL Agent Enumeration

- Linked server collection
- Linked server graph output
- SQL Agent jobs and steps
- Job-risk classifier

### Milestone 5: Sensitive Object Classification

- Sensitive table/column classifier
- Stored procedure definition search
- Optional redacted sampling
- Agent-friendly summary

---

## Final Mental Model

For MSSQL enumeration, the package should not only ask:

> What databases exist?

It should ask:

> What data, credentials, execution paths, privileges, and pivot opportunities does this MSSQL instance expose?

The useful output is not a raw dump. The useful output is a structured map of:

```text
Service Identity
    -> Auth Context
    -> Databases
    -> Sensitive Objects
    -> Users and Roles
    -> Dangerous Configurations
    -> Execution Paths
    -> Linked Servers
    -> Prioritized Findings
```

That is the information a penetration tester needs to decide what to investigate next.
