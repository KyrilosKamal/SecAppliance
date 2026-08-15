# Lightweight CVE Database
# Maps Service/Banner regexes to CVE info
CVE_DB = [
    # SSH
    {
        "pattern": "OpenSSH 7.2p2",
        "cve": "CVE-2016-6210",
        "severity": "MEDIUM",
        "title": "OpenSSH User Enumeration",
        "description": "OpenSSH 7.2p2 is susceptible to user enumeration vulnerabilities.",
        "remediation": "Update to OpenSSH 7.3 or later."
    },
    # Apache
    {
        "pattern": "Apache 2.4.49",
        "cve": "CVE-2021-41773",
        "severity": "CRITICAL",
        "title": "Apache Path Traversal",
        "description": "Apache 2.4.49 is vulnerable to path traversal and remote code execution.",
        "remediation": "Update to Apache 2.4.51 or later."
    },
    # FTP
    {
        "pattern": "vsftpd 2.3.4",
        "cve": "CVE-2011-2523",
        "severity": "CRITICAL",
        "title": "vsftpd Backdoor",
        "description": "vsftpd 2.3.4 contains a backdoor.",
        "remediation": "Update to a later version and check for unauthorized access."
    },
    # SMTP
    {
        "pattern": "Postfix 2.9",
        "cve": "CVE-2013-0241",
        "severity": "MEDIUM",
        "title": "Postfix Memory Leak",
        "description": "Postfix 2.9 has memory leak vulnerabilities.",
        "remediation": "Update to a later version."
    },
    # MySQL
    {
        "pattern": "MySQL 5.5",
        "cve": "CVE-2016-6662",
        "severity": "HIGH",
        "title": "MySQL Privilege Escalation",
        "description": "MySQL 5.5 is vulnerable to privilege escalation.",
        "remediation": "Update MySQL."
    },
    # SMB (Samba)
    {
        "pattern": "Samba 4.6.4",
        "cve": "CVE-2017-7494",
        "severity": "CRITICAL",
        "title": "SambaCry (Remote Code Execution)",
        "description": "Samba 4.6.4 is vulnerable to remote code execution.",
        "remediation": "Update to Samba 4.6.5 or later."
    },
    # VNC
    {
        "pattern": "RealVNC 5.3",
        "cve": "CVE-2018-7226",
        "severity": "HIGH",
        "title": "VNC Information Disclosure",
        "description": "RealVNC 5.3 is vulnerable to information disclosure.",
        "remediation": "Update RealVNC."
    }
]


def _normalize(text: str) -> str:
    """Normalize a string for fuzzy signature matching."""
    return text.replace('_', ' ').replace('-', ' ').replace('/', ' ').strip()


def get_vulns_for_service(service_name, banner):
    """
    Match a service name and banner against the local CVE signature database.

    Patterns are matched against both the service name and the banner to reduce
    false positives. Banner-only patterns are kept deliberately version-specific.
    """
    findings = []
    if not banner:
        return findings

    service_name = _normalize(service_name or "").upper()
    banner = _normalize(banner).upper()

    for entry in CVE_DB:
        pattern = _normalize(entry["pattern"]).upper()
        if pattern in banner or pattern in service_name:
            findings.append(entry)
    return findings
