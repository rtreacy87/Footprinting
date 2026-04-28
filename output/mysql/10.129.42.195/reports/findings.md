# MySQL Enumeration Findings

## Critical

### Current user has dangerous privileges: FILE, SUPER, PROCESS, CREATE USER, GRANT OPTION

These privileges may allow file read/write, user creation, or full server control.

**Recommendation:** Audit and revoke unnecessary privileges.

### Current user has FILE privilege

FILE privilege may allow reading files with LOAD_FILE or writing with INTO OUTFILE.

**Recommendation:** Revoke FILE privilege unless explicitly required.

## High

### User 'robin' has wildcard host '%'

Wildcard host allows connections from any IP.

## Medium

### TLS not required (require_secure_transport=OFF)

Connections may be made without encryption.

**Recommendation:** Enable require_secure_transport=ON.

## Info

### MySQL service authenticated successfully

Connected as robin@10.10.14.8 on NIX02
