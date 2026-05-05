# SMTP Reconnaissance Report

**Target:** `10.129.42.195`  
**Domain:** `N/A`  
**Scanned:** 2026-05-05 01:25 UTC  
**Safe Mode:** Yes  

---

## Summary

- Open SMTP ports: [25]
- Checks run: 10
- Total findings: 8
- Critical: 2
- High: 1
- Medium: 2

---

## Check Results

### [+] port_detection

**Status:** success  
**Summary:** Open SMTP ports: [25]  

### [+] banner_grab

**Status:** success  
**Summary:** Captured banners from ports: [25]  

### [+] ehlo_capabilities

**Status:** success  
**Summary:** EHLO capabilities collected from ports: [25]  

### [+] starttls

**Status:** success  
**Summary:** STARTTLS supported on ports: [25]  

### [?] auth_methods

**Status:** inconclusive  
**Summary:** AUTH methods found: []  

### [+] vrfy_user_enum

**Status:** success  
**Summary:** VRFY: 0 confirmed users out of 101 tested on port 25  

### [+] expn_user_enum

**Status:** success  
**Summary:** EXPN: 0 confirmed out of 101 tested on port 25  

### [!] rcpt_to_user_enum

**Status:** failed  
**Summary:** Unhandled exception: cannot access local variable 'port' where it is not associated with a value  
**Errors:**
- `cannot access local variable 'port' where it is not associated with a value`

### [+] open_relay

**Status:** success  
**Summary:** Open relay: DETECTED (4 scenarios tested)  

### [+] spoofing

**Status:** success  
**Summary:** Spoofing: 2/4 forged MAIL FROM accepted  

---

## Findings

### [CRITICAL] OPEN RELAY detected on port 25

**Category:** open_relay  
**Port:** 25  

Port 25 accepted RCPT TO from an external sender to an external recipient — this is a fully open relay.

**Evidence:**
```
MAIL FROM:<attacker@external-pentest.invalid> => 250
RCPT TO:<victim@external-pentest.invalid> => 250
```

**Remediation:** Restrict relay to authenticated users or internal networks only. Review mynetworks and relay_domains configuration.

---

### [CRITICAL] Open relay confirmed

**Category:** open_relay  
**Port:** N/A  

Relay: 1/4 accepted. Spoofing: 2/4 MAIL FROM accepted.

---

### [HIGH] Spoofed MAIL FROM accepted on port 25

**Category:** spoofing  
**Port:** 25  

Server accepted MAIL FROM:<no-reply@paypal.com> without authentication. Forged well-known brand address

**Evidence:**
```
MAIL FROM:<no-reply@paypal.com> => 250
RCPT TO:<test@test.local> => 250
```

**Remediation:** Implement SPF, DKIM, and DMARC. Configure the server to reject spoofed sender addresses.

---

### [MEDIUM] Spoofed MAIL FROM accepted on port 25

**Category:** spoofing  
**Port:** 25  

Server accepted MAIL FROM:<postmaster@example.com> without authentication. Forged postmaster at external domain

**Evidence:**
```
MAIL FROM:<postmaster@example.com> => 250
RCPT TO:<test@test.local> => 250
```

**Remediation:** Implement SPF, DKIM, and DMARC. Configure the server to reject spoofed sender addresses.

---

### [MEDIUM] VRFY capability advertised on port 25

**Category:** user_enumeration  
**Port:** 25  

Server explicitly advertises VRFY support.

---

### [INFO] SMTP Banner on port 25

**Category:** information_disclosure  
**Port:** 25  

SMTP service identified on port 25

**Evidence:**
```
220 InFreight ESMTP v2.11
```

---

### [INFO] EXPN command blocked

**Category:** security_control  
**Port:** 25  

Server has disabled the EXPN command.

**Evidence:**
```
Response code: 502
```

---

### [INFO] PIPELINING enabled on port 25

**Category:** capability  
**Port:** 25  

PIPELINING allows batched commands; can speed up enumeration.

---

## Attack Paths

### 1. [HIGH] Exploit open relay for phishing or spam

**Rationale:** Server accepts external→external relay. Attacker can send mail as any address.  
**Prerequisites:** open relay confirmed
**Tool hint:**
```
swaks --to victim@target.com --from spoof@trusted.com --server <target>
```

### 2. [HIGH] Exploit open relay for phishing or spam

**Rationale:** Server accepts external→external relay. Attacker can send mail as any address.  
**Prerequisites:** open relay confirmed
**Tool hint:**
```
swaks --to victim@target.com --from spoof@trusted.com --server <target>
```

### 3. [HIGH] Send phishing email with spoofed internal sender

**Rationale:** Server accepts forged MAIL FROM without SPF/DMARC enforcement.  
**Prerequisites:** spoofing accepted on MAIL FROM
**Tool hint:**
```
swaks --from admin@target.com --to victim@target.com --server <target>
```

### 4. [HIGH] Send phishing email with spoofed internal sender

**Rationale:** Server accepts forged MAIL FROM without SPF/DMARC enforcement.  
**Prerequisites:** spoofing accepted on MAIL FROM
**Tool hint:**
```
swaks --from admin@target.com --to victim@target.com --server <target>
```
