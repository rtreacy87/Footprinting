# NFS Recon — 10.129.202.5

## Discovery

- Port 111: open
- Port 2049: open
- NFS detected: True
- RPC services: 23 found

## Exports

- `/var/nfs` — allowed: `10.0.0.0/8`
- `/mnt/nfsshare` — allowed: `10.0.0.0/8`

## Mount Attempts

- Attempt 1: `/var/nfs` NFSv4 — FAILED (unknown)
- Attempt 2: `/var/nfs` NFSv3 — FAILED (unknown)
- Attempt 3: `/var/nfs` NFSv2 — FAILED (unknown)
- Attempt 4: `/mnt/nfsshare` NFSv4 — FAILED (unknown)
- Attempt 5: `/mnt/nfsshare` NFSv3 — FAILED (unknown)
- Attempt 6: `/mnt/nfsshare` NFSv2 — FAILED (unknown)

## Vulnerabilities

- No vulnerabilities identified

## Attack Paths

- Direct access: False
- Pivot required: True
