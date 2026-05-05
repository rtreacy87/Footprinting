DNS Recon Python Package Specification
Purpose

Build a modular Python package for DNS reconnaissance that gathers, normalizes, analyzes, and reports DNS-derived infrastructure intelligence.

DNS recon should identify:

Domains and subdomains
Name servers
Mail servers
TXT metadata
CNAME relationships
Reverse DNS records
Zone transfer exposure
Recursion exposure
Version disclosure
Cloud/SaaS indicators
Potential pivot targets for later recon modules

DNS is valuable because it can reveal not only hostnames and IP addresses, but also mail servers, name servers, TXT records, aliases, and infrastructure relationships.

Core Recon Philosophy

The package must track both:

What worked
What explicitly failed

Failures are important because enumeration is not only about what is visible, but also what is not visible and why.

Example:

Zone transfer failed against ns1.company.com
Recursion denied by ns2.company.com
version.bind query returned no result
Subdomain brute force found no wildcard behavior

These are useful for agents, reporting, and future package improvement.

Package Goals

The package should:

Perform passive and active DNS enumeration
Preserve raw command outputs
Parse results into structured JSON
Normalize all discovered domains, IPs, and records
Identify misconfigurations
Generate pivot targets for other recon modules
Produce human-readable markdown reports
Produce machine-readable JSON summaries
Follow clean code and SOLID principles
Recommended External Tools

The package should support wrappers around:

Tool	Purpose
dig	Primary DNS query tool
host	Simple DNS lookup and reverse lookup
nslookup	Secondary DNS query support
nmap	DNS NSE scripts, service detection
dnsenum	DNS enumeration and brute forcing
fierce	DNS scanning and zone transfer attempts
amass	Passive and active subdomain enumeration
subfinder	Passive subdomain enumeration
massdns	High-volume DNS resolving

nmap should be treated as a supporting tool, not the primary DNS tool.

Output Directory Structure
dns_recon/
├── metadata/
│   ├── target.json
│   ├── scan_config.json
│   └── timestamps.json
├── raw/
│   ├── dig/
│   │   ├── A.txt
│   │   ├── AAAA.txt
│   │   ├── MX.txt
│   │   ├── NS.txt
│   │   ├── TXT.txt
│   │   ├── SOA.txt
│   │   └── ANY.txt
│   ├── host/
│   ├── nslookup/
│   ├── nmap/
│   │   └── dns_scripts.txt
│   ├── amass/
│   ├── dnsenum/
│   └── zone_transfer/
│       └── axfr_attempts.txt
├── parsed/
│   ├── records/
│   │   ├── A.json
│   │   ├── AAAA.json
│   │   ├── MX.json
│   │   ├── NS.json
│   │   ├── TXT.json
│   │   ├── SOA.json
│   │   ├── CNAME.json
│   │   └── PTR.json
│   ├── subdomains/
│   │   ├── discovered.json
│   │   ├── passive.json
│   │   ├── brute_force.json
│   │   └── resolved.json
│   ├── name_servers/
│   │   └── resolved.json
│   └── reverse_dns/
│       └── ptr_sweep.json
├── attempts/
│   ├── zone_transfer/
│   │   ├── attempts.json
│   │   └── summary.json
│   ├── recursion/
│   │   └── recursion_check.json
│   ├── version_disclosure/
│   │   └── version_bind.json
│   ├── wildcard_detection/
│   │   └── wildcard_check.json
│   └── failed_queries/
│       └── failed_queries.json
├── analysis/
│   ├── infrastructure_map.json
│   ├── service_map.json
│   ├── trust_relationships.json
│   ├── potential_targets.json
│   ├── anomalies.json
│   └── risk_notes.json
├── pivots/
│   ├── smtp_targets.json
│   ├── web_targets.json
│   ├── vpn_targets.json
│   ├── cloud_assets.json
│   ├── internal_hosts.json
│   └── next_module_targets.json
└── summary/
    ├── findings.md
    ├── attack_paths.md
    ├── secure_findings.md
    └── quick_view.json
Recommended Python Package Structure
dns_recon_package/
├── pyproject.toml
├── README.md
├── src/
│   └── dns_recon/
│       ├── __init__.py
│       ├── cli.py
│       ├── config.py
│       ├── models/
│       │   ├── target.py
│       │   ├── dns_record.py
│       │   ├── attempt.py
│       │   ├── finding.py
│       │   └── pivot.py
│       ├── runners/
│       │   ├── base.py
│       │   ├── dig_runner.py
│       │   ├── host_runner.py
│       │   ├── nslookup_runner.py
│       │   ├── nmap_runner.py
│       │   ├── amass_runner.py
│       │   └── dnsenum_runner.py
│       ├── parsers/
│       │   ├── base.py
│       │   ├── dig_parser.py
│       │   ├── nmap_parser.py
│       │   ├── amass_parser.py
│       │   └── zone_transfer_parser.py
│       ├── services/
│       │   ├── baseline_service.py
│       │   ├── record_query_service.py
│       │   ├── subdomain_service.py
│       │   ├── zone_transfer_service.py
│       │   ├── recursion_service.py
│       │   ├── reverse_dns_service.py
│       │   └── analysis_service.py
│       ├── registries/
│       │   ├── runner_registry.py
│       │   ├── parser_registry.py
│       │   └── record_type_registry.py
│       ├── writers/
│       │   ├── raw_writer.py
│       │   ├── json_writer.py
│       │   ├── markdown_writer.py
│       │   └── summary_writer.py
│       └── reporting/
│           ├── findings_report.py
│           ├── attack_paths_report.py
│           └── secure_findings_report.py
└── tests/
    ├── test_parsers/
    ├── test_services/
    ├── test_registries/
    └── test_writers/
SOLID Design Requirements
Single Responsibility

Each class should do one thing.

Good:

DigRunner executes dig commands.
DigParser parses dig output.
JsonWriter writes parsed JSON.
ZoneTransferService coordinates zone transfer checks.

Bad:

DnsReconManager runs tools, parses output, writes files, and generates reports.
Registry Pattern Requirement

Use registries instead of long if/else chains.

Example:

record_type_registry = {
    "A": ARecordHandler,
    "AAAA": AAAARecordHandler,
    "MX": MXRecordHandler,
    "TXT": TXTRecordHandler,
    "NS": NSRecordHandler,
    "SOA": SOARecordHandler,
    "CNAME": CNAMERecordHandler,
    "PTR": PTRRecordHandler,
}

This makes it easy to add new DNS record types later.

Recon Flow
Phase 1: Initialize Target

Inputs:

domain
optional target DNS server
optional IP range
optional wordlist
scan mode: passive, active, full

Outputs:

metadata/target.json
metadata/scan_config.json
metadata/timestamps.json
Phase 2: Baseline DNS Records

Query:

A
AAAA
MX
NS
TXT
SOA
CNAME
ANY

Save:

raw/dig/
parsed/records/

Purpose:

Identify IPs
Identify mail servers
Identify name servers
Identify TXT metadata
Identify cloud and SaaS references
Phase 3: Name Server Enumeration

For each discovered name server:

Resolve IP
Query directly
Compare responses
Attempt safe metadata queries

Save:

parsed/name_servers/resolved.json
analysis/infrastructure_map.json
Phase 4: Zone Transfer Testing

For each name server:

dig axfr domain.com @nameserver

Track:

Success
Failure
Error
Timeout
Refused
Partial response

Save:

raw/zone_transfer/
attempts/zone_transfer/
parsed/records/

Important: failed zone transfers must be written to disk.

Phase 5: Recursion Check

Check whether the DNS server allows recursion for external clients.

Save:

attempts/recursion/recursion_check.json

Classify:

allowed
denied
timeout
unknown
Phase 6: Version Disclosure

Try:

dig CH TXT version.bind @server

Save:

attempts/version_disclosure/version_bind.json

Classify:

version_disclosed
not_disclosed
refused
timeout
Phase 7: Subdomain Enumeration

Use passive and active sources.

Passive:

amass passive
subfinder
crt.sh-compatible adapters

Active:

dnsenum
fierce
massdns
custom wordlist resolver

Save:

parsed/subdomains/passive.json
parsed/subdomains/brute_force.json
parsed/subdomains/discovered.json
parsed/subdomains/resolved.json
Phase 8: Wildcard Detection

Before trusting brute force results, test wildcard DNS.

Generate random names:

random-abc123.domain.com
random-def456.domain.com

If random names resolve, classify wildcard behavior.

Save:

attempts/wildcard_detection/wildcard_check.json
Phase 9: Reverse DNS

If IP ranges are provided or inferred:

PTR lookup for each IP

Save:

parsed/reverse_dns/ptr_sweep.json
Phase 10: Analysis

Generate:

analysis/infrastructure_map.json
analysis/service_map.json
analysis/trust_relationships.json
analysis/potential_targets.json
analysis/anomalies.json
analysis/risk_notes.json

Look for:

Internal IP leakage
Dev/staging/test subdomains
Cloud storage references
Mail infrastructure
VPN portals
Admin portals
Unusual TXT records
Unexpected CNAMEs
Exposed version data
Open recursion
Successful zone transfer
Pivot Generation

Generate targets for other modules:

pivots/smtp_targets.json
pivots/web_targets.json
pivots/vpn_targets.json
pivots/cloud_assets.json
pivots/internal_hosts.json
pivots/next_module_targets.json

Example:

{
  "smtp_targets": [
    {
      "hostname": "mail.company.com",
      "source": "MX record",
      "recommended_module": "smtp_recon"
    }
  ],
  "web_targets": [
    {
      "hostname": "dev.company.com",
      "source": "subdomain enumeration",
      "recommended_module": "web_recon"
    }
  ]
}
Reporting Outputs
findings.md

Should include:

# DNS Recon Findings

## Target
## Scope
## Records Found
## Subdomains Found
## Name Servers
## Mail Servers
## Misconfigurations
## Notable Metadata
## Recommended Next Steps
attack_paths.md

Should include:

# DNS-Derived Attack Paths

## Path 1: MX Record to SMTP Recon
mail.company.com was discovered through MX records.

## Path 2: Dev Subdomain to Web Recon
dev.company.com was discovered during subdomain enumeration.

## Path 3: Zone Transfer Exposure
Zone transfer succeeded against ns1.company.com.
secure_findings.md

Should include controls that appeared properly restricted:

# Secure Findings

- Zone transfer denied by ns1.company.com
- Recursion denied by ns1.company.com
- version.bind query did not disclose version
- No wildcard DNS behavior detected

This is important for both reporting and package quality improvement.

Finding Severity Guidance
Finding	Severity
Successful zone transfer	High
Open recursion	Medium / High
Internal IP leakage	Medium
Version disclosure	Low / Medium
Dev/staging exposure	Contextual
Cloud storage CNAME	Contextual
Sensitive TXT record	Medium / High
Mail infrastructure exposure	Informational / Contextual
CLI Requirements

Example command:

dns-recon --domain company.com --mode full --wordlist ./wordlists/subdomains.txt --output ./dns_recon

Supported options:

--domain
--dns-server
--ip-range
--wordlist
--mode passive|active|full
--output
--timeout
--threads
--tools dig,nmap,amass,dnsenum
--safe
--verbose
Testing Requirements

Tests should cover:

Parsing A records
Parsing MX records
Parsing TXT records
Parsing NS records
Parsing SOA records
Parsing failed zone transfer output
Parsing successful zone transfer output
Handling timeouts
Handling empty output
Wildcard detection logic
Pivot generation logic
Markdown report generation
Design Constraints

The package must:

Avoid hardcoded tool logic in orchestration code
Use dependency injection where practical
Use registries for tools, parsers, and record handlers
Preserve raw outputs
Never overwrite previous scan results unless explicitly configured
Validate all JSON outputs
Log failed attempts
Separate execution, parsing, analysis, and writing
Final Package Objective

At the end of a DNS recon run, another agent or pentester should be able to answer:

What domains and subdomains exist?
What DNS records were found?
What name servers are authoritative?
Were zone transfers allowed?
Was recursion allowed?
Were versions disclosed?
What mail, web, VPN, cloud, or internal assets were discovered?
What did we test that did not work?
What should we enumerate next?

The package should turn DNS data into a structured infrastructure map and a set of actionable next-step targets.
