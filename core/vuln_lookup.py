# Lightweight CVE Database
# Maps Service/Banner regexes to CVE info
CVE_DB = [
    {
        "pattern": "OpenSSH 7.2p2",
        "cve": "CVE-2016-6210",
        "severity": "MEDIUM",
        "title": "OpenSSH User Enumeration",
        "description": "OpenSSH 7.2p2 is susceptible to user enumeration vulnerabilities.",
        "remediation": "Update to OpenSSH 7.3 or later."
    },
    {
        "pattern": "Apache 2.4.49",
        "cve": "CVE-2021-41773",
        "severity": "CRITICAL",
        "title": "Apache Path Traversal",
        "description": "Apache 2.4.49 is vulnerable to path traversal and remote code execution.",
        "remediation": "Update to Apache 2.4.51 or later."
    }
]

def get_vulns_for_service(service_name, banner):
    findings = []
    for entry in CVE_DB:
        if entry["pattern"] in banner:
            findings.append(entry)
    return findings
