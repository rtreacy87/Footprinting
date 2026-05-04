# NFS Recon Output Structure (Final Design)

## Purpose
This document defines the **standardized output structure** for NFS reconnaissance.
It aligns with existing FTP/SMB enumeration systems and is designed for:

- Agent-based decision making
- Human-readable reporting
- Full auditability (what worked AND what failed)

---

## Design Principles

- Capture **everything tested**, not just successes
- Separate **raw data** from **parsed insights**
- Preserve **execution history**
- Enable **future pivoting decisions**
- Maintain consistency across protocols (FTP, SMB, NFS)

---

## Top-Level Structure

nfs_recon/
└── <target_ip>/
    ├── discovery/
    ├── enumeration/
    ├── access_checks/
    ├── mount_attempts/
    ├── data_extraction/
    ├── permissions/
    ├── pivoting/
    ├── vulnerabilities/
    ├── logs/
    └── summary/

---

## 1. discovery/

### Purpose:
Identify NFS presence and supporting services

### Files:
- nmap_raw.txt
- nmap_parsed.json
- rpcinfo_raw.txt
- rpcinfo_parsed.json

### Key Data:
- Open ports (111, 2049)
- RPC services (mountd, nfs)

---

## 2. enumeration/

### Purpose:
Identify exported shares and exposure level

### Files:
- showmount_raw.txt
- showmount_parsed.json
- nfs_scripts_raw.txt
- exports.json

### Example:
{
  "exports": [
    {
      "path": "/mnt/nfs",
      "allowed_hosts": "10.0.0.0/24"
    }
  ]
}

---

## 3. access_checks/

### Purpose:
Quick validation before mounting

### Files:
- access_tests.json

### Tracks:
- Export visibility
- RPC accessibility
- Version compatibility

---

## 4. mount_attempts/ (Critical)

### Purpose:
Track ALL mount attempts (success + failure)

mount_attempts/
├── attempt_1/
│   ├── command.txt
│   ├── stdout.txt
│   ├── stderr.txt
│   ├── result.json
│   └── classification.json

---

### Example result.json:
{
  "status": "failed",
  "error": "access denied",
  "version": "v4"
}

### Example classification.json:
{
  "failure_type": "ACCESS_DENIED",
  "reason": "IP restriction",
  "next_step": "pivot_required"
}

---

## 5. data_extraction/ (If Mounted)

### Purpose:
Capture accessible data

### Files:
- file_tree.txt
- sensitive_files.json
- credentials.json

### Focus:
- SSH keys
- Config files
- Credentials

---

## 6. permissions/

### Purpose:
Analyze access capabilities

### Files:
- permissions_raw.txt
- uid_gid_map.json
- write_access.json
- root_squash_check.json

---

### Example:
{
  "writable": true,
  "root_squash": false,
  "risk": "high"
}

---

## 7. pivoting/

### Purpose:
Define trust boundaries and next steps

### Files:
- trust_boundary.json
- allowed_networks.json
- pivot_recommendations.json

---

### Example:
{
  "allowed_subnet": "10.0.0.0/24",
  "pivot_required": true
}

---

## 8. vulnerabilities/

### Purpose:
Track findings (even if not immediately exploitable)

### Files:
- findings.json
- misconfigurations.json

---

### Example:
{
  "issues": [
    {
      "type": "no_root_squash",
      "severity": "critical",
      "exploitable": false,
      "requires_pivot": true
    }
  ]
}

---

## 9. logs/

### Purpose:
Full execution trace

### Files:
- execution.log
- errors.log

---

## 10. summary/

### Purpose:
Final structured output

### Files:

#### attack_paths.json
{
  "direct_access": false,
  "pivot_required": true
}

#### test_coverage.json
{
  "tests_performed": [
    "nmap",
    "rpcinfo",
    "showmount",
    "mount_v3",
    "mount_v4"
  ],
  "tests_successful": ["showmount"],
  "tests_failed": ["mount_v3", "mount_v4"]
}

#### findings.md
Human-readable summary

---

## Final Output States

Each target should resolve to:

- Exploitable Now
- Exploitable After Pivot
- Limited Value

---

## Key Insight

This structure does not just store results.

It builds a:
→ **Complete decision history of the NFS attack surface**

Which enables:
- Smarter automation
- Faster pivoting
- Better reporting
