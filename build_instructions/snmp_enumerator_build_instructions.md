# SNMP Enumerator Build Instructions

## Purpose

Build a Python-based SNMP enumeration helper that collects SNMP data from an authorized target, separates the output into useful sections, converts raw OID/value data into human-readable JSON and Markdown, and writes the results into a reusable evidence folder.

This is intended for penetration testing, lab work, and defensive validation where the tester is authorized to query SNMP.

## Design Goal

SNMP can expose a very large amount of structured host information. The script should not simply dump raw `snmpwalk` output and leave the tester to manually inspect it. Instead, it should:

1. Identify whether SNMP is reachable.
2. Discover or accept a community string.
3. Pull targeted SNMP branches.
4. Save the raw evidence.
5. Parse the output into sections.
6. Normalize the findings into JSON.
7. Generate a Markdown summary.
8. Highlight items useful for later attack-path analysis.

The default identifier for each target should be the target IP address. If the user provides a hostname, asset tag, or custom name, use that as an additional label, but keep the IP address as the default folder key.

---

# Tool Order

## 1. `nmap`

Use first to confirm whether UDP/161 is open or likely open.

Example:

```bash
sudo nmap -sU -p161 --open -sV <target_ip>
```

Optional NSE scripts:

```bash
sudo nmap -sU -p161 --script snmp-info,snmp-sysdescr <target_ip>
```

Purpose:

- Confirm SNMP is reachable.
- Capture basic service/version clues.
- Avoid wasting time running full collection against a closed service.

---

## 2. `onesixtyone`

Use when the community string is unknown.

Example:

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <target_ip>
```

Purpose:

- Discover valid SNMP community strings.
- Default check should include common strings such as `public` and `private`.

Script behavior:

- If the user provides `--community`, skip brute-forcing.
- If no community is provided, run `onesixtyone` with the configured wordlist.
- Store discovered community strings in `communities.json`.

---

## 3. `snmpwalk`

Use after a community string is known.

Run targeted walks first instead of immediately walking the entire tree.

Recommended collection order:

```bash
snmpwalk -v2c -c <community> <target_ip> 1.3.6.1.2.1.1      # system
snmpwalk -v2c -c <community> <target_ip> 1.3.6.1.2.1.2      # interfaces
snmpwalk -v2c -c <community> <target_ip> 1.3.6.1.2.1.4      # IP/network
snmpwalk -v2c -c <community> <target_ip> 1.3.6.1.2.1.6      # TCP
snmpwalk -v2c -c <community> <target_ip> 1.3.6.1.2.1.7      # UDP
snmpwalk -v2c -c <community> <target_ip> 1.3.6.1.2.1.25     # host resources
```

Optional full walk:

```bash
snmpwalk -v2c -c <community> <target_ip> .1
```

Purpose:

- Pull raw SNMP data.
- Preserve evidence.
- Feed parser with deterministic sections.

---

## 4. `braa`

Use optionally after a community string is known when faster OID brute forcing is useful.

Example:

```bash
braa <community>@<target_ip>:.1.3.6.*
```

Purpose:

- Fast OID enumeration.
- Useful as a secondary collection method.
- Should not replace `snmpwalk` for structured parsing.

---

## 5. Python Parser

Use Python after raw collection.

Python responsibilities:

- Create output folders.
- Run tools safely with timeouts.
- Parse raw SNMP lines.
- Map known OIDs to friendly names.
- Split results into categories.
- Write JSON and Markdown outputs.
- Generate a triage report.

Recommended Python libraries:

```text
argparse
subprocess
pathlib
json
re
datetime
ipaddress
shutil
```

Optional libraries:

```text
rich        # nicer terminal output
pydantic    # structured models
jinja2      # markdown templating
```

---

# Script Inputs

The script should accept:

```bash
python3 snmp_enum.py <target_ip> \
  --community public \
  --version 2c \
  --output ./loot/snmp \
  --label optional-hostname \
  --full-walk \
  --wordlist /usr/share/seclists/Discovery/SNMP/snmp.txt
```

## Required Argument

| Argument | Description |
|---|---|
| `target_ip` | Target IP address. This should be the default asset identifier. |

## Optional Arguments

| Argument | Description |
|---|---|
| `--community` | Known SNMP community string. Defaults to discovery mode if omitted. |
| `--version` | SNMP version. Default: `2c`. |
| `--output` | Base output folder. Default: `./snmp-output`. |
| `--label` | Optional human-readable host label. |
| `--wordlist` | Community string wordlist for `onesixtyone`. |
| `--full-walk` | Also collect `.1` full SNMP tree. |
| `--timeout` | Command timeout in seconds. |
| `--no-braa` | Skip optional `braa` collection. |
| `--markdown-only` | Regenerate Markdown from existing JSON. |

---

# Output Folder Structure

The final output should be a folder keyed by the target IP address.

Example:

```text
snmp-output/
└── 10.129.14.128/
    ├── metadata.json
    ├── communities.json
    ├── raw/
    │   ├── nmap_snmp.txt
    │   ├── onesixtyone.txt
    │   ├── snmpwalk_system.raw
    │   ├── snmpwalk_interfaces.raw
    │   ├── snmpwalk_network.raw
    │   ├── snmpwalk_tcp.raw
    │   ├── snmpwalk_udp.raw
    │   ├── snmpwalk_host_resources.raw
    │   ├── snmpwalk_full.raw
    │   └── braa.raw
    ├── json/
    │   ├── system.json
    │   ├── interfaces.json
    │   ├── network.json
    │   ├── tcp.json
    │   ├── udp.json
    │   ├── processes.json
    │   ├── installed_software.json
    │   ├── storage.json
    │   ├── users_contacts.json
    │   ├── suspicious_strings.json
    │   └── all_findings.json
    ├── markdown/
    │   ├── README.md
    │   ├── system.md
    │   ├── network.md
    │   ├── services.md
    │   ├── software.md
    │   ├── suspicious_findings.md
    │   └── attack_paths.md
    └── wordlists/
        ├── usernames.txt
        ├── hostnames.txt
        ├── domains.txt
        ├── emails.txt
        └── ips.txt
```

---

# SNMP Sections to Collect

## System Identity

OID branch:

```text
1.3.6.1.2.1.1
```

Extract:

- System description
- Hostname
- Contact
- Location
- Uptime
- SNMP services value

Useful fields:

```json
{
  "ip": "10.129.14.128",
  "hostname": "htb",
  "sys_descr": "Linux htb 5.11.0-34-generic ...",
  "sys_contact": "mrb3n@inlanefreight.htb",
  "sys_location": "Sitting on the Dock of the Bay",
  "uptime": "10:12:46.78"
}
```

Pentest value:

- OS fingerprinting
- Kernel/version clues
- Email/user discovery
- Host naming patterns

---

## Network Interfaces

OID branch:

```text
1.3.6.1.2.1.2
```

Extract:

- Interface names
- MAC addresses
- Interface status
- MTU
- Speed

Pentest value:

- Identify physical/virtual interfaces.
- Detect VPN, Docker, bridge, tunnel, or management interfaces.
- Identify possible internal network paths.

---

## IP and Routing Information

OID branch:

```text
1.3.6.1.2.1.4
```

Extract:

- IP addresses
- Netmasks
- Routes
- Forwarding status

Pentest value:

- Discover internal IPs.
- Identify hidden subnets.
- Find possible pivot paths.

---

## TCP Information

OID branch:

```text
1.3.6.1.2.1.6
```

Extract:

- TCP listeners
- Established connections
- Local/remote addresses
- Local/remote ports

Pentest value:

- Identify services not exposed externally.
- Identify internal connections.
- Find localhost-only services worth checking after foothold.

---

## UDP Information

OID branch:

```text
1.3.6.1.2.1.7
```

Extract:

- UDP listeners
- Local addresses
- Local ports

Pentest value:

- Identify DNS, SNMP, NTP, syslog, or custom UDP services.

---

## Host Resources

OID branch:

```text
1.3.6.1.2.1.25
```

Split into:

```text
1.3.6.1.2.1.25.1    host info
1.3.6.1.2.1.25.2    storage
1.3.6.1.2.1.25.3    devices
1.3.6.1.2.1.25.4    running processes
1.3.6.1.2.1.25.5    process performance
1.3.6.1.2.1.25.6    installed software
1.3.6.1.2.1.25.7    installed software details
```

Extract:

- Boot parameters
- Running processes
- Process command-line arguments
- Installed software/packages
- Storage/mount points
- Device information

Pentest value:

- Process names can reveal services.
- Command-line arguments may expose config paths or credentials.
- Installed packages can be used for CVE research.
- Mount points can reveal backups, shares, or sensitive paths.

---

# Human-Readable Transformation Rules

## Raw Line Format

Common `snmpwalk` line:

```text
iso.3.6.1.2.1.1.5.0 = STRING: "htb"
```

Normalize to:

```json
{
  "oid": "1.3.6.1.2.1.1.5.0",
  "name": "sysName",
  "type": "STRING",
  "value": "htb",
  "section": "system_identity"
}
```

## OID Name Mapping

Create a Python dictionary for common OIDs:

```python
OID_MAP = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
    "1.3.6.1.2.1.1.4.0": "sysContact",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
    "1.3.6.1.2.1.25.1.4.0": "hrSystemInitialLoadParameters",
    "1.3.6.1.2.1.25.4.2.1.2": "hrSWRunName",
    "1.3.6.1.2.1.25.4.2.1.4": "hrSWRunPath",
    "1.3.6.1.2.1.25.4.2.1.5": "hrSWRunParameters",
    "1.3.6.1.2.1.25.6.3.1.2": "hrSWInstalledName"
}
```

## Section Mapping

```python
SECTION_MAP = {
    "1.3.6.1.2.1.1": "system_identity",
    "1.3.6.1.2.1.2": "network_interfaces",
    "1.3.6.1.2.1.4": "ip_networking",
    "1.3.6.1.2.1.6": "tcp",
    "1.3.6.1.2.1.7": "udp",
    "1.3.6.1.2.1.25.1": "host_info",
    "1.3.6.1.2.1.25.2": "storage",
    "1.3.6.1.2.1.25.3": "devices",
    "1.3.6.1.2.1.25.4": "processes",
    "1.3.6.1.2.1.25.6": "installed_software"
}
```

---

# Suspicious Finding Rules

The parser should create `suspicious_strings.json` and `suspicious_findings.md` by searching extracted values for high-value patterns.

## Credential-Like Keywords

Flag values containing:

```text
password
passwd
pwd
secret
token
apikey
api_key
key
credential
cred
login
auth
private
rsa
id_rsa
```

## Useful Path Keywords

Flag values containing:

```text
/home/
/root/
/etc/
/var/www/
/opt/
/backup
/backups
/config
/conf
.env
.yaml
.yml
.json
.ini
```

## Service Keywords

Flag values containing:

```text
ssh
sshd
apache
nginx
mysql
mariadb
postgres
redis
mongodb
ftp
proftpd
vsftpd
smb
samba
nfs
cron
jenkins
docker
kubernetes
```

## Identity Patterns

Extract into wordlists:

```text
emails
usernames
hostnames
domains
IP addresses
```

Examples:

- `mrb3n@inlanefreight.htb` → email + username + domain
- `Linux htb 5.11.0-34-generic` → hostname + OS/kernel version
- `10.129.14.128` → IP inventory

---

# JSON Output Schema

## `metadata.json`

```json
{
  "target_ip": "10.129.14.128",
  "label": "optional-hostname",
  "collection_time": "2026-04-27T18:30:00Z",
  "snmp_version": "2c",
  "community_used": "public",
  "tools_used": ["nmap", "onesixtyone", "snmpwalk", "braa", "python"],
  "output_version": "0.1.0"
}
```

## `all_findings.json`

```json
{
  "asset": {
    "ip": "10.129.14.128",
    "label": "optional-hostname",
    "hostname": "htb"
  },
  "system_identity": {},
  "network_interfaces": [],
  "ip_networking": [],
  "tcp": [],
  "udp": [],
  "processes": [],
  "installed_software": [],
  "storage": [],
  "users_contacts": [],
  "suspicious_strings": [],
  "potential_attack_paths": []
}
```

---

# Markdown Report Requirements

## `README.md`

The top-level report should include:

```markdown
# SNMP Enumeration Report: 10.129.14.128

## Asset Summary

| Field | Value |
|---|---|
| IP | 10.129.14.128 |
| Hostname | htb |
| OS | Linux 5.11.0-34-generic |
| Contact | mrb3n@inlanefreight.htb |
| Location | Sitting on the Dock of the Bay |

## High-Value Findings

- SNMP exposed OS/kernel information.
- SNMP exposed a possible user/email: `mrb3n@inlanefreight.htb`.
- SNMP exposed installed software packages.
- SNMP exposed boot parameters.

## Recommended Next Steps

1. Add discovered usernames/emails to the engagement wordlist.
2. Check exposed software versions for known vulnerabilities.
3. Review TCP/UDP listeners for hidden services.
4. Investigate process command-line arguments for config paths or credentials.
5. Check whether SNMP write access is possible only if authorized and in scope.
```

## `attack_paths.md`

Create a report focused on what the tester can do next:

```markdown
# Potential Attack Paths

## 1. Username Reuse

Evidence:

- `mrb3n@inlanefreight.htb`

Use:

- Try username `mrb3n` against authorized login services such as SSH, SMB, IMAP, or web portals.

## 2. Version-Based Research

Evidence:

- `Linux htb 5.11.0-34-generic`
- Installed package list exposed by SNMP.

Use:

- Check kernel and package versions against known vulnerabilities.

## 3. Internal Network Discovery

Evidence:

- IP addresses and routes found in SNMP network branches.

Use:

- Add discovered subnets to internal recon plan.
```

---

# Python Script Structure

Recommended file layout:

```text
snmp-agent/
├── snmp_enum.py
├── oid_maps.py
├── parsers.py
├── render_markdown.py
├── requirements.txt
└── README.md
```

## `snmp_enum.py`

Responsibilities:

- Parse CLI arguments.
- Create output folders.
- Check required tools with `shutil.which()`.
- Run `nmap`, `onesixtyone`, `snmpwalk`, and optionally `braa`.
- Save raw output.
- Call parser.
- Call Markdown renderer.

## `parsers.py`

Responsibilities:

- Parse raw `snmpwalk` lines.
- Normalize OIDs.
- Map OIDs to names and sections.
- Extract identity values.
- Extract suspicious strings.
- Generate wordlists.

## `oid_maps.py`

Responsibilities:

- Store OID-to-name mappings.
- Store section mappings.
- Store friendly descriptions for high-value OID branches.

## `render_markdown.py`

Responsibilities:

- Convert parsed JSON into readable Markdown.
- Generate `README.md`.
- Generate one Markdown file per section.
- Generate `attack_paths.md`.

---

# Pseudocode

```python
def main():
    args = parse_args()
    asset_dir = create_asset_folder(args.output, args.target_ip)

    check_tools(["nmap", "snmpwalk"])

    run_nmap(args.target_ip, asset_dir)

    if args.community:
        communities = [args.community]
    else:
        check_tools(["onesixtyone"])
        communities = discover_communities(args.target_ip, args.wordlist, asset_dir)

    for community in communities:
        collect_snmp_sections(args.target_ip, community, asset_dir)

        if args.full_walk:
            collect_full_walk(args.target_ip, community, asset_dir)

        if not args.no_braa:
            run_braa(args.target_ip, community, asset_dir)

    parsed = parse_raw_outputs(asset_dir)
    enrich_findings(parsed)
    write_json_outputs(parsed, asset_dir)
    write_wordlists(parsed, asset_dir)
    render_markdown(parsed, asset_dir)
```

---

# Collection Safety

The script should avoid aggressive behavior by default.

Default behavior:

- No write operations.
- No SNMP `set` operations.
- No exploit execution.
- No password spraying against discovered usernames.
- No automatic CVE exploitation.

The script may identify possible write access indicators, but it should only report them.

Example safe finding:

```text
Possible read-write community string detected or suspected. Manual validation required and must be in scope.
```

---

# LLM Review Stage

The LLM should not receive raw SNMP output by default.

Instead, give it:

```text
metadata.json
all_findings.json
suspicious_strings.json
attack_paths.md
```

Suggested LLM prompt:

```text
You are reviewing structured SNMP enumeration results from an authorized penetration test.
Identify high-value findings, likely attack paths, missing follow-up checks, and any false-positive risks.
Do not invent facts. Base conclusions only on the provided JSON and Markdown.
Return a concise Markdown report with evidence and next steps.
```

Recommended model role:

- Analyst, not parser.
- Prioritize evidence.
- Map findings to next actions.
- Keep uncertainty visible.

---

# Definition of Done

The project is complete when the script can:

1. Accept a target IP address.
2. Confirm SNMP availability.
3. Discover or use a community string.
4. Pull raw SNMP data by section.
5. Save raw evidence.
6. Parse OIDs into human-readable names.
7. Split output into system, network, process, software, storage, and suspicious finding sections.
8. Generate JSON outputs.
9. Generate Markdown reports.
10. Generate reusable wordlists.
11. Store everything under a target-IP-based folder.

---

# MVP Scope

For the first working version, implement only:

```text
nmap check
community input via --community
snmpwalk collection
raw output saving
basic parser
JSON export
README.md report
wordlist extraction
```

Then add:

```text
onesixtyone discovery
braa collection
full walk option
LLM analyst handoff
advanced attack-path scoring
```

---

# Example Final Command

```bash
python3 snmp_enum.py 10.129.14.128 --community public --output ./snmp-output --full-walk
```

Expected result:

```text
./snmp-output/10.129.14.128/
```

This folder should contain everything needed to reuse the SNMP evidence later during the penetration test.
