# DNS-Derived Attack Paths

## Path 1: Zone Transfer Exposure
Zone transfer succeeded against `10.129.1.83`.
This exposes the full zone contents and reveals internal infrastructure.

## Path 2: Dev Subdomain to Web Recon
`dev.inlanefreight.htb` (A record (dev label)) appears to be a web-accessible target.
IP: 10.12.0.1 — Recommended next module: `web_recon`

## Path 3: Internal Host to Network Recon
`internal.inlanefreight.htb` (10.129.1.6) appears to be an internal host.
Recommended next module: `smb_enum or nmap`
