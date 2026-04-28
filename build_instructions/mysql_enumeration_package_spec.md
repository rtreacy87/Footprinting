# MySQL Enumeration Package Specification

## Purpose

Build a Python package that safely enumerates a MySQL or MariaDB service in the same spirit as the SNMP enumeration workflow: collect as much structured information as possible, normalize it into human-readable output, and produce machine-readable artifacts that can be reviewed later by a human or LLM.

The package should prioritize metadata first:

- service identity and version
- authentication result
- server variables and security-relevant configuration
- databases and schemas
- tables, columns, indexes, and row counts
- users, hosts, roles, and permissions
- file read/write capability indicators
- optional table extraction when authorized and technically feasible

The package should avoid destructive actions. It should not modify records, create users, write files, drop tables, alter privileges, or run exploit modules unless a later explicit `--exploit` mode is added.

---

## Expected Output Folder

Default output folder:

```text
output/mysql/<target_identifier>/
```

The `<target_identifier>` should default to the target IP address. If the user supplies a hostname or label, use that instead.

Suggested structure:

```text
output/mysql/10.129.14.128/
├── metadata/
│   ├── service.json
│   ├── server_variables.json
│   ├── server_status.json
│   ├── plugins.json
│   └── security_findings.json
├── access/
│   ├── authentication.json
│   ├── current_user.json
│   ├── users.json
│   ├── roles.json
│   ├── grants.json
│   └── privilege_summary.md
├── schema/
│   ├── databases.json
│   ├── tables.json
│   ├── columns.json
│   ├── indexes.json
│   ├── routines.json
│   ├── triggers.json
│   └── schema_summary.md
├── data/
│   ├── extracted_tables/
│   │   └── <database>/<table>.csv
│   ├── samples/
│   │   └── <database>/<table>.json
│   └── extraction_manifest.json
├── raw/
│   ├── nmap_mysql.xml
│   ├── nmap_mysql.txt
│   └── mysql_query_log.jsonl
├── reports/
│   ├── summary.md
│   ├── findings.md
│   └── llm_review_context.md
└── run_metadata.json
```

---

## Package Goals

The package should answer these questions:

1. Is MySQL/MariaDB reachable?
2. What version and authentication plugin is exposed?
3. Can we authenticate with supplied credentials?
4. What user are we authenticated as?
5. What databases can this account see?
6. What tables, columns, indexes, triggers, routines, and views exist?
7. What users and roles exist, if visible?
8. What grants and privileges does the current user have?
9. Does the current user have dangerous privileges such as `FILE`, `SUPER`, `PROCESS`, `CREATE USER`, `GRANT OPTION`, or broad `ALL PRIVILEGES`?
10. Are configuration values dangerous or useful for later testing?
11. Can table data be safely sampled or exported?
12. What findings should a pentester review first?

---

## Tools and Libraries

### External Tools

#### 1. `nmap`

Use first for discovery and fingerprinting.

Recommended command:

```bash
nmap -sV -sC -p3306 --script mysql-info,mysql-empty-password,mysql-enum,mysql-users,mysql-variables <target> -oA output/mysql/<target>/raw/nmap_mysql
```

Notes:

- Treat NSE output as untrusted until confirmed manually.
- The module notes that Nmap MySQL script output can produce false positives, especially around empty passwords.
- Store both normal and XML outputs.

#### 2. MySQL/MariaDB client binaries

Optional fallback tools:

```bash
mysql -h <target> -P <port> -u <user> -p
mysqladmin -h <target> -P <port> -u <user> -p status
mysqlshow -h <target> -P <port> -u <user> -p
```

The Python package should not require these for normal operation, but can record equivalent commands in the report.

---

### Python Libraries

Recommended core dependencies:

```text
pymysql
cryptography
pydantic
rich
typer
python-dotenv
jinja2
pandas
```

Optional:

```text
mysql-connector-python
lxml
pyyaml
```

Use `pymysql` as the default connector because it is pure Python and easy to install. Support `mysql-connector-python` later if needed.

---

## Execution Modes

### 1. Discovery Mode

No credentials required.

Goal:

- Confirm port state.
- Fingerprint service.
- Capture banner/version/auth plugin if exposed.
- Run safe Nmap MySQL NSE scripts.

Command example:

```bash
mysql-enum discover --target 10.129.14.128 --port 3306
```

Outputs:

```text
metadata/service.json
raw/nmap_mysql.xml
raw/nmap_mysql.txt
reports/summary.md
```

---

### 2. Authenticated Metadata Mode

Requires credentials or socket access.

Goal:

- Connect to the database.
- Identify the current user and connection context.
- Enumerate metadata from `information_schema`, `mysql`, `performance_schema`, and `sys` where allowed.

Command example:

```bash
mysql-enum metadata --target 10.129.14.128 --username root --password-file ./creds.txt
```

Outputs:

```text
access/current_user.json
access/grants.json
schema/databases.json
schema/tables.json
schema/columns.json
schema/schema_summary.md
```

---

### 3. Sample Mode

Requires credentials.

Goal:

- Pull small samples from accessible tables.
- Avoid dumping everything by default.
- Help identify sensitive tables and useful pivot data.

Command example:

```bash
mysql-enum sample --target 10.129.14.128 --username app --password-file ./creds.txt --rows 20
```

Default behavior:

- Sample only non-system databases.
- Limit to 20 rows per table.
- Skip very large binary columns unless `--include-binary` is set.
- Redact likely secrets by default in Markdown reports, but preserve raw output if `--preserve-sensitive` is explicitly set.

---

### 4. Extract Mode

Requires credentials and explicit user opt-in.

Goal:

- Export full accessible tables or selected tables.
- Save data in CSV, JSONL, or Parquet.

Command example:

```bash
mysql-enum extract --target 10.129.14.128 --username app --password-file ./creds.txt --database wordpress --table wp_users
```

Default behavior:

- Require database and table selection.
- Do not dump every database unless `--all-accessible-tables` is explicitly provided.
- Paginate large tables.
- Maintain an extraction manifest with row counts, timestamps, hashes, and query text.

---

## Enumeration Workflow

## Phase 0: Input Validation and Run Setup

Collect:

- target IP or hostname
- port, default `3306`
- username/password, optional
- SSL mode, optional
- output directory
- scope label
- row sampling limit
- timeout
- maximum table extraction size

Create:

```text
run_metadata.json
```

Include:

```json
{
  "target": "10.129.14.128",
  "port": 3306,
  "started_at": "<timestamp>",
  "mode": "metadata",
  "package_version": "0.1.0",
  "safe_mode": true
}
```

---

## Phase 1: Network and Service Discovery

### Step 1.1: TCP Reachability

Attempt a TCP connection to the target and port.

Record:

- reachable: true/false
- latency
- timeout/error

### Step 1.2: Nmap Fingerprinting

Run Nmap if available.

Recommended scripts:

```text
mysql-info
mysql-empty-password
mysql-enum
mysql-users
mysql-variables
```

Record:

- service name
- version
- protocol
- capabilities
- authentication plugin
- script output
- warnings or errors

Important: Nmap results should be treated as hints. The package should confirm findings through direct MySQL queries whenever possible.

---

## Phase 2: Authentication

### Step 2.1: Credential Handling

Supported credential sources:

- command-line username and password
- password file
- environment variables
- `.env` file
- interactive prompt

Avoid writing plaintext credentials to output files.

Store only:

```json
{
  "username": "root",
  "password_supplied": true,
  "auth_success": true,
  "auth_error": null
}
```

### Step 2.2: Connection Attempt

Use a read-only client connection where possible.

Recommended session settings:

```sql
SET SESSION sql_log_bin = 0;
SET SESSION group_concat_max_len = 1000000;
```

Note: `sql_log_bin` may require privileges and can fail. Failure should not stop enumeration.

### Step 2.3: Confirm Identity

Run:

```sql
SELECT USER() AS login_user, CURRENT_USER() AS effective_user;
SELECT DATABASE() AS current_database;
SELECT @@hostname AS server_hostname;
SELECT @@version AS version;
SELECT @@version_comment AS version_comment;
```

Save:

```text
access/current_user.json
metadata/service.json
```

---

## Phase 3: Server Metadata

### Step 3.1: Version and Build Metadata

Queries:

```sql
SELECT VERSION();
SHOW VARIABLES LIKE 'version%';
SHOW VARIABLES LIKE 'hostname';
SHOW VARIABLES LIKE 'port';
SHOW VARIABLES LIKE 'socket';
SHOW VARIABLES LIKE 'datadir';
SHOW VARIABLES LIKE 'basedir';
```

Look for:

- MySQL vs MariaDB
- OS/distribution hints
- server hostname
- data directory
- socket path
- version-specific vulnerabilities

### Step 3.2: Security-Relevant Variables

Queries:

```sql
SHOW VARIABLES WHERE Variable_name IN (
  'secure_file_priv',
  'local_infile',
  'sql_warnings',
  'log_error',
  'general_log',
  'general_log_file',
  'slow_query_log',
  'slow_query_log_file',
  'plugin_dir',
  'skip_name_resolve',
  'require_secure_transport',
  'have_ssl',
  'ssl_ca',
  'ssl_cert',
  'ssl_key'
);
```

Flag:

- `local_infile = ON`
- `secure_file_priv` empty or overly permissive
- `general_log = ON` and log path visible
- `require_secure_transport = OFF`
- SSL unavailable or unused
- readable plugin directory

### Step 3.3: Server Status

Queries:

```sql
SHOW STATUS;
SHOW GLOBAL STATUS;
```

Store raw results, but summarize only useful fields:

- uptime
- connections
- threads
- aborted connections
- SSL usage

---

## Phase 4: Database and Schema Enumeration

### Step 4.1: List Databases

Queries:

```sql
SHOW DATABASES;

SELECT schema_name, default_character_set_name, default_collation_name
FROM information_schema.schemata
ORDER BY schema_name;
```

Classify databases:

```text
system:
  - information_schema
  - mysql
  - performance_schema
  - sys
application:
  - everything else
```

### Step 4.2: List Tables

Queries:

```sql
SELECT
  table_schema,
  table_name,
  table_type,
  engine,
  table_rows,
  data_length,
  index_length,
  create_time,
  update_time,
  table_collation
FROM information_schema.tables
ORDER BY table_schema, table_name;
```

Flag:

- non-system databases
- tables with names like `user`, `users`, `account`, `accounts`, `auth`, `login`, `credential`, `token`, `session`, `api_key`, `password`, `secret`, `config`, `settings`, `admin`
- unexpectedly large tables
- recently updated tables

### Step 4.3: List Columns

Queries:

```sql
SELECT
  table_schema,
  table_name,
  column_name,
  ordinal_position,
  column_default,
  is_nullable,
  data_type,
  column_type,
  character_maximum_length,
  column_key,
  extra,
  privileges,
  column_comment
FROM information_schema.columns
ORDER BY table_schema, table_name, ordinal_position;
```

Flag sensitive column names:

```text
password
passwd
pass_hash
hash
salt
token
api_key
secret
private_key
email
phone
ssn
dob
address
session
cookie
reset
mfa
otp
role
is_admin
```

### Step 4.4: Indexes and Keys

Queries:

```sql
SELECT
  table_schema,
  table_name,
  index_name,
  non_unique,
  seq_in_index,
  column_name,
  cardinality,
  index_type
FROM information_schema.statistics
ORDER BY table_schema, table_name, index_name, seq_in_index;
```

Use this to identify:

- primary keys
- usernames/emails as unique identifiers
- foreign key relationships
- join paths between tables

### Step 4.5: Views, Routines, Triggers, Events

Queries:

```sql
SELECT * FROM information_schema.views;
SELECT routine_schema, routine_name, routine_type, security_type, definer FROM information_schema.routines;
SELECT trigger_schema, trigger_name, event_object_table, action_timing, event_manipulation, definer FROM information_schema.triggers;
SELECT event_schema, event_name, definer, status, event_type FROM information_schema.events;
```

Flag:

- `SQL SECURITY DEFINER`
- definers that no longer exist
- routines that access files, execute dynamic SQL, or handle credentials
- triggers on sensitive tables

---

## Phase 5: User, Role, and Permission Enumeration

## Step 5.1: Current User Grants

Queries:

```sql
SHOW GRANTS;
SHOW GRANTS FOR CURRENT_USER();
```

Parse grants into structured JSON:

```json
{
  "principal": "app@%",
  "scope": "wordpress.*",
  "privileges": ["SELECT", "INSERT", "UPDATE"],
  "grant_option": false
}
```

### Step 5.2: MySQL Users

Try:

```sql
SELECT user, host, account_locked, password_expired, plugin
FROM mysql.user
ORDER BY user, host;
```

Fallback for older versions:

```sql
SELECT user, host
FROM mysql.user
ORDER BY user, host;
```

If permission denied, record:

```json
{
  "mysql_user_table_visible": false,
  "error": "permission denied"
}
```

Flag:

- `root` with remote host `%`
- empty usernames
- wildcard hosts `%`
- accounts without password metadata
- old authentication plugins
- locked or expired accounts
- shared application accounts

### Step 5.3: Privilege Tables

Try:

```sql
SELECT * FROM mysql.user;
SELECT * FROM mysql.db;
SELECT * FROM mysql.tables_priv;
SELECT * FROM mysql.columns_priv;
SELECT * FROM mysql.procs_priv;
```

Do not fail if denied.

Summarize permissions by:

- global privileges
- database privileges
- table privileges
- column privileges
- routine privileges

### Step 5.4: Roles

For MySQL 8+:

```sql
SELECT * FROM mysql.role_edges;
SELECT * FROM mysql.default_roles;
```

Also try:

```sql
SHOW GRANTS FOR '<user>'@'<host>';
```

Only run per-user grant checks if the current user has permission.

---

## Phase 6: Dangerous Capability Checks

This phase should test capability through metadata and safe probes, not destructive actions.

### Check 6.1: FILE Privilege

Use grants first.

Flag if grants include:

```text
FILE
ALL PRIVILEGES
```

Safe probe:

```sql
SELECT @@secure_file_priv;
```

Do not write test files by default.

### Check 6.2: LOAD_FILE Read Capability

Optional safe read test:

```sql
SELECT LOAD_FILE('/etc/hostname');
```

Only run if `--test-file-read` is enabled.

Record:

- attempted path
- success true/false
- bytes returned
- redacted content preview

### Check 6.3: OUTFILE Write Capability

Do not run by default.

Only assess from:

- `FILE` privilege
- `secure_file_priv`
- writable path assumptions

If future active mode is added, require explicit flag:

```bash
--test-file-write --write-test-path /tmp/mysql_enum_test.txt
```

### Check 6.4: Process Visibility

Queries:

```sql
SHOW PROCESSLIST;
SELECT * FROM information_schema.processlist;
```

Flag if visible:

- other users' queries
- credentials in queries
- application database names
- long-running admin tasks

### Check 6.5: Logging Visibility

Queries:

```sql
SHOW VARIABLES LIKE 'general_log%';
SHOW VARIABLES LIKE 'slow_query_log%';
SHOW VARIABLES LIKE 'log_error';
```

Flag:

- logs enabled
- paths readable or web-accessible
- logs inside application directories

---

## Phase 7: Data Sampling

Sampling should be careful, bounded, and review-friendly.

### Step 7.1: Select Candidate Tables

Prioritize tables using table and column names.

High-value table name patterns:

```text
user
users
account
accounts
admin
admins
auth
login
credential
credentials
password
passwords
token
tokens
session
sessions
api
apikey
api_key
secret
secrets
config
configuration
settings
customer
customers
employee
employees
person
people
profile
profiles
payment
invoice
orders
```

High-value column name patterns:

```text
username
user_name
email
password
passwd
hash
password_hash
salt
token
access_token
refresh_token
api_key
secret
role
admin
is_admin
last_login
reset_token
mfa
otp
```

### Step 7.2: Generate Safe Sample Queries

For each selected table:

```sql
SELECT * FROM `<database>`.`<table>` LIMIT <sample_limit>;
```

Rules:

- Use backtick escaping for identifiers.
- Do not string-format raw user input into SQL.
- Validate database and table names against enumerated metadata.
- Skip binary/blob columns by default or truncate them.

### Step 7.3: Store Samples

Save as:

```text
data/samples/<database>/<table>.json
```

Each sample file should include:

```json
{
  "database": "wordpress",
  "table": "wp_users",
  "sample_limit": 20,
  "columns": [],
  "rows": [],
  "redactions_applied": true
}
```

---

## Phase 8: Full Table Extraction

Only run when explicitly requested.

### Step 8.1: Confirm Table Scope

Require one of:

```bash
--database wordpress --table wp_users
--table-list tables.txt
--all-accessible-tables
```

### Step 8.2: Estimate Size

Before extraction:

```sql
SELECT COUNT(*) FROM `<database>`.`<table>`;
```

Also use `information_schema.tables.table_rows` as a rough estimate.

If row count exceeds threshold, require:

```bash
--force-large-extract
```

### Step 8.3: Paginated Extraction

Use primary key pagination when possible.

Fallback:

```sql
SELECT * FROM `<database>`.`<table>` LIMIT <limit> OFFSET <offset>;
```

Preferred for primary key:

```sql
SELECT *
FROM `<database>`.`<table>`
WHERE `<pk>` > <last_pk>
ORDER BY `<pk>`
LIMIT <page_size>;
```

### Step 8.4: Manifest

Write:

```text
data/extraction_manifest.json
```

Include:

- database
- table
- rows exported
- columns exported
- started/finished timestamps
- file path
- SHA256 hash
- query strategy
- errors

---

## Phase 9: Findings Engine

The package should convert raw metadata into pentester-friendly findings.

### Finding Categories

#### Critical

- Authenticated as root or DBA-equivalent account
- Remote root account visible, especially `root@%`
- Current user has `FILE`, `SUPER`, `CREATE USER`, or `GRANT OPTION`
- Sensitive tables are readable
- Password hashes or API tokens discovered
- `secure_file_priv` allows dangerous read/write paths

#### High

- User table visible
- Broad wildcard host access
- Weak authentication plugin
- No TLS required
- Application user has access to multiple unrelated databases
- Process list exposes other users' queries

#### Medium

- Database version exposed
- Logging paths exposed
- Excessive metadata visibility
- Large number of accessible schemas

#### Informational

- Service reachable on 3306
- MySQL/MariaDB version
- Accessible system schemas
- Table counts and schema map

---

## Phase 10: LLM Review Context

Create a compact Markdown file designed for later LLM review:

```text
reports/llm_review_context.md
```

Include:

```markdown
# MySQL Enumeration Review Context

## Target
- Host:
- Port:
- Version:
- Authenticated as:

## Access Summary
- Databases visible:
- Tables visible:
- Grants:
- Dangerous privileges:

## High-Value Tables
| Database | Table | Reason | Rows | Sample Available |

## Sensitive Columns
| Database | Table | Column | Reason |

## Security-Relevant Variables
| Variable | Value | Concern |

## Recommended Next Steps
```

The goal is to give an LLM enough structured context to explain what matters without making it parse thousands of raw rows.

---

## Data Models

### TargetConfig

```python
class TargetConfig(BaseModel):
    target: str
    port: int = 3306
    username: str | None = None
    password: SecretStr | None = None
    database: str | None = None
    ssl_mode: str = "preferred"
    timeout_seconds: int = 10
    output_dir: Path
    safe_mode: bool = True
```

### QueryResult

```python
class QueryResult(BaseModel):
    query_name: str
    sql: str
    success: bool
    rows: list[dict] = []
    error: str | None = None
    started_at: datetime
    finished_at: datetime
```

### Finding

```python
class Finding(BaseModel):
    severity: Literal["critical", "high", "medium", "low", "info"]
    title: str
    description: str
    evidence: dict
    recommendation: str | None = None
```

---

## Package Layout

```text
mysql_enum/
├── __init__.py
├── cli.py
├── config.py
├── discovery.py
├── connection.py
├── queries.py
├── collectors/
│   ├── service.py
│   ├── users.py
│   ├── privileges.py
│   ├── schema.py
│   ├── variables.py
│   ├── routines.py
│   └── data.py
├── analyzers/
│   ├── findings.py
│   ├── sensitive_columns.py
│   ├── privilege_risk.py
│   └── table_classifier.py
├── output/
│   ├── writers.py
│   ├── markdown.py
│   ├── json_writer.py
│   └── csv_writer.py
└── utils/
    ├── identifiers.py
    ├── redaction.py
    ├── hashing.py
    └── nmap.py
```

---

## Query Order

The package should execute queries in this order:

1. TCP reachability
2. Nmap fingerprinting
3. MySQL connection test
4. identity queries
5. version and server variables
6. current user grants
7. database list
8. table list
9. column list
10. indexes and constraints
11. views, routines, triggers, events
12. users and roles, if permitted
13. privilege tables, if permitted
14. process list, if permitted
15. security findings generation
16. table sampling, if enabled
17. table extraction, if enabled
18. Markdown report generation

This ordering matters because each phase improves the next one. For example, column enumeration lets the package decide which tables are worth sampling.

---

## Report Content

### `reports/summary.md`

Should include:

- target and connection info
- service version
- authentication result
- current user
- visible databases
- table count by database
- high-value tables
- dangerous privileges
- security-relevant variables
- recommended next steps

### `reports/findings.md`

Should include findings grouped by severity.

Example:

```markdown
## High: Application user can read authentication table

The user `app@%` can read `wordpress.wp_users`, which contains likely password hashes and user email addresses.

Evidence:

- Database: wordpress
- Table: wp_users
- Sensitive columns: user_login, user_pass, user_email

Recommended next step:

Review password hashing format, test for credential reuse only within scope, and restrict database privileges to least privilege.
```

---

## Redaction Rules

By default, Markdown reports should redact secrets.

Redact values for columns matching:

```text
password
passwd
hash
salt
token
secret
api_key
private_key
session
cookie
```

Example redaction:

```text
$2y$10$abc123... -> <redacted:hash:sha256=...>
```

Raw exports should also redact by default unless:

```bash
--preserve-sensitive
```

When preserving sensitive values, the package should clearly mark the output folder as sensitive.

---

## Error Handling

Every collector should be failure-tolerant.

Example:

If `SELECT * FROM mysql.user` fails, continue with:

```sql
SHOW GRANTS;
SELECT USER(), CURRENT_USER();
```

Store the failed query and error in:

```text
raw/mysql_query_log.jsonl
```

Do not stop the run unless:

- target is unreachable
- authentication fails in a mode requiring authentication
- output directory cannot be created

---

## Safety Boundaries

Default safe mode should prohibit:

- `INSERT`
- `UPDATE`
- `DELETE`
- `DROP`
- `ALTER`
- `CREATE USER`
- `GRANT`
- `REVOKE`
- `INTO OUTFILE`
- `LOAD DATA LOCAL INFILE`
- UDF creation
- plugin installation
- writing test files

Optional probes requiring explicit flags:

```bash
--test-file-read
--test-file-write
--preserve-sensitive
--all-accessible-tables
--force-large-extract
```

---

## Minimal CLI Design

```bash
mysql-enum discover --target 10.129.14.128

mysql-enum metadata \
  --target 10.129.14.128 \
  --username root \
  --password-file ./password.txt

mysql-enum sample \
  --target 10.129.14.128 \
  --username app \
  --password-file ./password.txt \
  --rows 20

mysql-enum extract \
  --target 10.129.14.128 \
  --username app \
  --password-file ./password.txt \
  --database wordpress \
  --table wp_users
```

---

## Minimum Viable Product

MVP should implement:

1. CLI with `discover`, `metadata`, and `sample`
2. TCP reachability check
3. optional Nmap execution
4. MySQL connection using PyMySQL
5. identity queries
6. database/table/column enumeration
7. current user grants
8. sensitive table and column classifier
9. JSON output
10. Markdown summary report

Defer until version 2:

- full extraction
- role graph visualization
- privilege graph visualization
- CVE matching
- LLM report scoring
- automated credential testing
- file read/write probes

---

## Example Finding Logic

```python
if grant.includes("FILE"):
    add_finding(
        severity="critical",
        title="Current MySQL user has FILE privilege",
        description="The FILE privilege may allow reading files with LOAD_FILE or writing files with INTO OUTFILE depending on secure_file_priv and filesystem permissions.",
        evidence={"grant": grant.raw},
    )

if table.name.lower() in HIGH_VALUE_TABLE_NAMES:
    add_finding(
        severity="high",
        title="High-value table visible",
        description=f"The table {table.schema}.{table.name} appears likely to contain authentication, session, configuration, or user data.",
        evidence={"table": table.model_dump()},
    )
```

---

## Pentester Review Checklist

After running the package, review:

- Can we authenticate?
- Are we root or DBA-equivalent?
- What databases are visible?
- Are application databases visible?
- Are user/auth/config tables visible?
- Are password hashes, tokens, or API keys visible?
- Does the user have dangerous privileges?
- Is `secure_file_priv` restrictive?
- Is `local_infile` enabled?
- Are logs enabled and readable?
- Are wildcard hosts or remote root users present?
- Is TLS required?
- Are there routines/triggers running as privileged definers?
- Can this database access lead to application access, host access, or lateral movement?

---

## Design Philosophy

This package should behave like a careful junior pentester with good notes:

1. Look first.
2. Confirm what tools report.
3. Collect metadata before data.
4. Prefer schema and permissions over brute force.
5. Pull samples before dumps.
6. Write everything down.
7. Make the output easy for a human or LLM to review.
