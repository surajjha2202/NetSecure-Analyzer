from __future__ import annotations

import re
from typing import Any


def _empty_security_parameters() -> dict[str, dict[str, Any]]:
    return {
        "management": {},
        "authentication": {},
        "remote_access": {},
        "crypto": {},
        "logging": {},
        "access_control": {},
        "firewall": {},
        "interfaces": {},
        "routing": {},
        "monitoring": {},
    }


def parse_extreme(content: str) -> dict[str, Any]:
    if not content or not content.strip():
        raise ValueError("Configuration cannot be empty")

    security_parameters = _empty_security_parameters()

    hostname = None
    aaa_configured = None
    ssh_enabled = None
    telnet_enabled = None
    password_encryption = None
    local_logging = None
    remote_syslog = None

    standard_acls = 0
    extended_acls = 0
    interfaces = 0
    static_routes = 0

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        # ---------------------------------------------------------
        # HOSTNAME
        # ---------------------------------------------------------
        match = re.match(
            r"^configure\s+snmp\s+sysName\s+(.+)$",
            line,
            re.IGNORECASE,
        )
        if match:
            hostname = match.group(1).strip().strip('"')
            continue

        # ---------------------------------------------------------
        # AAA / USER AUTHENTICATION
        # ---------------------------------------------------------
        if re.match(
            r"^(create|configure)\s+account\b",
            line,
            re.IGNORECASE,
        ):
            aaa_configured = True
            continue

        if re.search(
            r"\bnetwork-login\b|\bnetlogin\b|\bauthentication\b",
            line,
            re.IGNORECASE,
        ):
            aaa_configured = True
            continue

        # ---------------------------------------------------------
        # SSH
        # ---------------------------------------------------------
        if re.match(
            r"^enable\s+ssh2\b",
            line,
            re.IGNORECASE,
        ):
            ssh_enabled = True
            continue

        if re.match(
            r"^disable\s+ssh2\b",
            line,
            re.IGNORECASE,
        ):
            ssh_enabled = False
            continue

        # ---------------------------------------------------------
        # TELNET
        # ---------------------------------------------------------
        if re.match(
            r"^enable\s+telnet\b",
            line,
            re.IGNORECASE,
        ):
            telnet_enabled = True
            continue

        if re.match(
            r"^disable\s+telnet\b",
            line,
            re.IGNORECASE,
        ):
            telnet_enabled = False
            continue

        # ---------------------------------------------------------
        # PASSWORD / CRYPTO
        # ---------------------------------------------------------
        if re.search(
            r"\bencrypted\b|\bpassword\s+encrypted\b",
            line,
            re.IGNORECASE,
        ):
            password_encryption = True
            continue

        # ---------------------------------------------------------
        # LOCAL LOGGING
        # ---------------------------------------------------------
        if re.match(
            r"^enable\s+log\b",
            line,
            re.IGNORECASE,
        ):
            local_logging = True
            continue

        # ---------------------------------------------------------
        # REMOTE SYSLOG
        # ---------------------------------------------------------
        if re.match(
            r"^configure\s+syslog\s+add\b",
            line,
            re.IGNORECASE,
        ):
            remote_syslog = True
            continue

        if re.search(
            r"\bsyslog\b",
            line,
            re.IGNORECASE,
        ):
            remote_syslog = True
            continue

        # ---------------------------------------------------------
        # ACL / NETWORK POLICY
        # ---------------------------------------------------------
        if re.match(
            r"^(create|configure)\s+access-list\b",
            line,
            re.IGNORECASE,
        ):
            extended_acls += 1
            continue

        if re.match(
            r"^configure\s+policy\b",
            line,
            re.IGNORECASE,
        ):
            standard_acls += 1
            continue

        # ---------------------------------------------------------
        # INTERFACES / VLAN
        # ---------------------------------------------------------
        if re.match(
            r"^configure\s+vlan\s+\S+",
            line,
            re.IGNORECASE,
        ):
            interfaces += 1
            continue

        if re.match(
            r"^enable\s+ports?\s+\S+",
            line,
            re.IGNORECASE,
        ):
            interfaces += 1
            continue

        # ---------------------------------------------------------
        # STATIC ROUTES
        # ---------------------------------------------------------
        if re.match(
            r"^configure\s+iproute\b",
            line,
            re.IGNORECASE,
        ):
            static_routes += 1
            continue

        # ---------------------------------------------------------
        # LOGGING / MONITORING
        # ---------------------------------------------------------
        if re.search(
            r"\bconfigure\s+log\b|\benable\s+log\b",
            line,
            re.IGNORECASE,
        ):
            local_logging = True
            continue

    security_parameters["management"]["hostname"] = hostname

    security_parameters["authentication"]["aaa_new_model"] = aaa_configured

    security_parameters["remote_access"]["ssh_enabled"] = ssh_enabled
    security_parameters["remote_access"]["telnet_enabled"] = telnet_enabled

    security_parameters["crypto"]["password_encryption"] = password_encryption

    security_parameters["logging"]["local_buffered_logging"] = local_logging
    security_parameters["logging"]["remote_syslog"] = remote_syslog

    security_parameters["access_control"]["standard_acls"] = standard_acls
    security_parameters["access_control"]["extended_acls"] = extended_acls

    security_parameters["interfaces"]["count"] = interfaces

    security_parameters["routing"]["static_routes"] = static_routes

    security_parameters["monitoring"]["logging_configured"] = (
        local_logging is True or remote_syslog is True
    )

    return {
        "vendor": "Extreme Networks",
        "confidence": 0.95,
        "parser": {
            "type": "vendor_specific",
            "name": "extreme_exos",
            "status": "PARSED",
        },
        "security_parameters": security_parameters,
        "unknown_lines": [],
    }