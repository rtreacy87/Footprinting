# DNS-Derived Attack Paths

## Path 1: Zone Transfer Exposure
Zone transfer succeeded against `10.129.1.83`.
This exposes the full zone contents and reveals internal infrastructure.

## Path 2: Zone Transfer Exposure
Zone transfer succeeded against `10.129.1.83`.
This exposes the full zone contents and reveals internal infrastructure.

## Path 3: Dev Subdomain to Web Recon
`dev.inlanefreight.htb` (A record (dev label)) appears to be a web-accessible target.
IP: 10.12.0.1 — Recommended next module: `web_recon`

## Path 4: Internal Host to Network Recon
`internal.inlanefreight.htb` (10.129.1.6) appears to be an internal host.
Recommended next module: `smb_enum or nmap`

## Path 5: Internal Host to Network Recon
`dc1.internal.inlanefreight.htb` (10.129.34.16) appears to be an internal host.
Recommended next module: `smb_enum or nmap`

## Path 6: Internal Host to Network Recon
`dc2.internal.inlanefreight.htb` (10.129.34.11) appears to be an internal host.
Recommended next module: `smb_enum or nmap`

## Path 7: Internal Host to Network Recon
`mail1.internal.inlanefreight.htb` (10.129.18.200) appears to be an internal host.
Recommended next module: `smb_enum or nmap`

## Path 8: Internal Host to Network Recon
`ns.internal.inlanefreight.htb` (127.0.0.1) appears to be an internal host.
Recommended next module: `smb_enum or nmap`

## Path 9: Internal Host to Network Recon
`vpn.internal.inlanefreight.htb` (10.129.1.6) appears to be an internal host.
Recommended next module: `smb_enum or nmap`

## Path 10: Internal Host to Network Recon
`ws1.internal.inlanefreight.htb` (10.129.1.34) appears to be an internal host.
Recommended next module: `smb_enum or nmap`

## Path 11: Internal Host to Network Recon
`ws2.internal.inlanefreight.htb` (10.129.1.35) appears to be an internal host.
Recommended next module: `smb_enum or nmap`

## Path 12: Internal Host to Network Recon
`wsus.internal.inlanefreight.htb` (10.129.18.2) appears to be an internal host.
Recommended next module: `smb_enum or nmap`
