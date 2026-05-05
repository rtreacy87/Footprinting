# DNS Recon Findings

## Target
- Domain: `inlanefreight.htb`

## Records Found

### A
- `ns.inlanefreight.htb` → `127.0.0.1`
- `app.inlanefreight.htb` → `10.129.18.15`
- `dev.inlanefreight.htb` → `10.12.0.1`
- `internal.inlanefreight.htb` → `10.129.1.6`
- `mail1.inlanefreight.htb` → `10.129.18.201`
- `ns.inlanefreight.htb` → `127.0.0.1`

### NS
- `inlanefreight.htb` → `ns.inlanefreight.htb`
- `inlanefreight.htb` → `ns.inlanefreight.htb`

### SOA
- `inlanefreight.htb` → `inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800`
- `inlanefreight.htb` → `inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800`
- `inlanefreight.htb` → `inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800`
- `inlanefreight.htb` → `inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800`
- `inlanefreight.htb` → `inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800`
- `inlanefreight.htb` → `inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800`
- `inlanefreight.htb` → `inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800`

### TXT
- `inlanefreight.htb` → `"atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"`
- `inlanefreight.htb` → `"v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"`
- `inlanefreight.htb` → `"MS=ms97310371"`
- `inlanefreight.htb` → `MS=ms97310371`
- `inlanefreight.htb` → `atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU`
- `inlanefreight.htb` → `v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all`

## Name Servers

- `ns.inlanefreight.htb`
- `ns.inlanefreight.htb`

## Mail Servers


## Subdomains Found


## Misconfigurations

### Zone Transfer Allowed [HIGH]
DNS zone transfer (AXFR) succeeded against 10.129.1.83.
**Evidence:**
- `AXFR inlanefreight.htb @10.129.1.83`
**Recommendation:** Restrict AXFR to trusted slave servers only.

## Notable Metadata

- **Dev/Staging Subdomain Exposed** (contextual): dev.inlanefreight.htb (10.12.0.1) appears to be a dev/staging host.

## Recommended Next Steps

- Investigate zone transfer exposure immediately
- Enumerate mail servers via smtp_recon
- Web-probe any discovered subdomains
- Run SMB/LDAP enumeration against internal hosts