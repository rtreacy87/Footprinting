# Exact OID → friendly name (scalars and table column prefixes)
OID_MAP = {
    "1.3.6.1.2.1.1.1.0":       "sysDescr",
    "1.3.6.1.2.1.1.2.0":       "sysObjectID",
    "1.3.6.1.2.1.1.3.0":       "sysUpTime",
    "1.3.6.1.2.1.1.4.0":       "sysContact",
    "1.3.6.1.2.1.1.5.0":       "sysName",
    "1.3.6.1.2.1.1.6.0":       "sysLocation",
    "1.3.6.1.2.1.1.7.0":       "sysServices",
    "1.3.6.1.2.1.25.1.4.0":    "hrSystemInitialLoadParameters",
    "1.3.6.1.2.1.25.1.5.0":    "hrSystemNumUsers",
    "1.3.6.1.2.1.25.1.6.0":    "hrSystemProcesses",
    "1.3.6.1.2.1.25.4.2.1.2":  "hrSWRunName",
    "1.3.6.1.2.1.25.4.2.1.4":  "hrSWRunPath",
    "1.3.6.1.2.1.25.4.2.1.5":  "hrSWRunParameters",
    "1.3.6.1.2.1.25.6.3.1.2":  "hrSWInstalledName",
}

# Ordered longest-first so first match wins
SECTION_PREFIXES = [
    ("1.3.6.1.2.1.25.6", "installed_software"),
    ("1.3.6.1.2.1.25.4", "processes"),
    ("1.3.6.1.2.1.25.3", "devices"),
    ("1.3.6.1.2.1.25.2", "storage"),
    ("1.3.6.1.2.1.25.1", "host_info"),
    ("1.3.6.1.2.1.25",   "host_resources"),
    ("1.3.6.1.2.1.7",    "udp"),
    ("1.3.6.1.2.1.6",    "tcp"),
    ("1.3.6.1.2.1.4",    "ip_networking"),
    ("1.3.6.1.2.1.2",    "network_interfaces"),
    ("1.3.6.1.2.1.1",    "system_identity"),
]

SECTION_TITLES = {
    "system_identity":    "System Identity",
    "network_interfaces": "Network Interfaces",
    "ip_networking":      "IP and Routing",
    "tcp":                "TCP Information",
    "udp":                "UDP Information",
    "host_info":          "Host Info",
    "storage":            "Storage",
    "devices":            "Devices",
    "processes":          "Running Processes",
    "installed_software": "Installed Software",
    "host_resources":     "Host Resources",
    "other":              "Other",
}

CREDENTIAL_KEYWORDS = frozenset({
    "password", "passwd", "pwd", "secret", "token", "apikey",
    "api_key", "key", "credential", "cred", "login", "auth",
    "private", "rsa", "id_rsa",
})

PATH_KEYWORDS = frozenset({
    "/home/", "/root/", "/etc/", "/var/www/", "/opt/",
    "/backup", "/backups", "/config", "/conf",
    ".env", ".yaml", ".yml", ".json", ".ini",
})

SERVICE_KEYWORDS = frozenset({
    "ssh", "sshd", "apache", "nginx", "mysql", "mariadb",
    "postgres", "redis", "mongodb", "ftp", "proftpd", "vsftpd",
    "smb", "samba", "nfs", "cron", "jenkins", "docker", "kubernetes",
})
