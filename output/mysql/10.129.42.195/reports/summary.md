# MySQL Enumeration Summary

## Target
- **Host:** 10.129.42.195
- **Port:** 3306
- **Version:** 8.0.27-0ubuntu0.20.04.1
- **Server hostname:** NIX02
- **Authenticated as:** robin@10.10.14.8
- **Effective user:** robin@%

## Databases
- Total visible: 5
- Application databases: 5
  - `customers`
  - `information_schema`
  - `mysql`
  - `performance_schema`
  - `sys`

## Tables
- Application tables visible: 1

## Grants
- `GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, RELOAD, SHUTDOWN, PROCESS, FILE, REFERENCES, INDEX, ALTER, SHOW DATABASES, SUPER, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, REPLICATION SLAVE, REPLICATION CLIENT, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, CREATE USER, EVENT, TRIGGER, CREATE TABLESPACE, CREATE ROLE, DROP ROLE ON *.* TO `robin`@`%` WITH GRANT OPTION`
- `GRANT APPLICATION_PASSWORD_ADMIN,AUDIT_ADMIN,AUTHENTICATION_POLICY_ADMIN,BACKUP_ADMIN,BINLOG_ADMIN,BINLOG_ENCRYPTION_ADMIN,CLONE_ADMIN,CONNECTION_ADMIN,ENCRYPTION_KEY_ADMIN,FLUSH_OPTIMIZER_COSTS,FLUSH_STATUS,FLUSH_TABLES,FLUSH_USER_RESOURCES,GROUP_REPLICATION_ADMIN,GROUP_REPLICATION_STREAM,INNODB_REDO_LOG_ARCHIVE,INNODB_REDO_LOG_ENABLE,PASSWORDLESS_USER_ADMIN,PERSIST_RO_VARIABLES_ADMIN,REPLICATION_APPLIER,REPLICATION_SLAVE_ADMIN,RESOURCE_GROUP_ADMIN,RESOURCE_GROUP_USER,ROLE_ADMIN,SERVICE_CONNECTION_ADMIN,SESSION_VARIABLES_ADMIN,SET_USER_ID,SHOW_ROUTINE,SYSTEM_USER,SYSTEM_VARIABLES_ADMIN,TABLE_ENCRYPTION_ADMIN,XA_RECOVER_ADMIN ON *.* TO `robin`@`%` WITH GRANT OPTION`

## Security-Relevant Variables
- `general_log` = `OFF`
- `general_log_file` = `/var/lib/mysql/NIX02.log`
- `have_ssl` = `YES`
- `local_infile` = `OFF`
- `log_error` = `/var/log/mysql/error.log`
- `plugin_dir` = `/usr/lib/mysql/plugin/`
- `require_secure_transport` = `OFF`
- `secure_file_priv` = `/var/lib/mysql-files/`
- `skip_name_resolve` = `OFF`
- `slow_query_log` = `OFF`
- `slow_query_log_file` = `/var/lib/mysql/NIX02-slow.log`
- `sql_warnings` = `OFF`
- `ssl_ca` = `ca.pem`
- `ssl_cert` = `server-cert.pem`
- `ssl_key` = `server-key.pem`

## Findings
- **[CRITICAL]** Current user has dangerous privileges: FILE, SUPER, PROCESS, CREATE USER, GRANT OPTION
- **[CRITICAL]** Current user has FILE privilege
- **[HIGH]** User 'robin' has wildcard host '%'
- **[MEDIUM]** TLS not required (require_secure_transport=OFF)
- **[INFO]** MySQL service authenticated successfully