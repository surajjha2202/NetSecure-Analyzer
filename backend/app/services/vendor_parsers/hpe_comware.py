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


def parse_hpe_comware(content: str) -> dict[str, Any]:
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

    lines = content.splitlines()

    for raw_line in lines:
        line = raw_line.strip()

        if not line:
            continue

        # Ignore comments
        if line.startswith("#"):
            continue

        # ---------------------------------------------------------
        # HOSTNAME
        # ---------------------------------------------------------
        match = re.match(r"^sysname\s+(.+)$", line, re.IGNORECASE)
        if match:
            hostname = match.group(1).strip()
            continue

        # ---------------------------------------------------------
        # AAA / AUTHENTICATION
        # ---------------------------------------------------------
        if re.match(r"^aaa$", line, re.IGNORECASE):
            aaa_configured = True
            continue

        if re.match(
            r"^(local-user|domain|authentication-scheme|authorization-scheme)\b",
            line,
            re.IGNORECASE,
        ):
            aaa_configured = True
            continue

        # ---------------------------------------------------------
        # SSH
        # ---------------------------------------------------------
        if re.match(
            r"^ssh\s+server\s+enable$",
            line,
            re.IGNORECASE,
        ):
            ssh_enabled = True
            continue

        if re.match(
            r"^undo\s+ssh\s+server\s+enable$",
            line,
            re.IGNORECASE,
        ):
            ssh_enabled = False
            continue

        # ---------------------------------------------------------
        # TELNET
        # ---------------------------------------------------------
        if re.match(
            r"^telnet\s+server\s+enable$",
            line,
            re.IGNORECASE,
        ):
            telnet_enabled = True
            continue

        if re.match(
            r"^undo\s+telnet\s+server\s+enable$",
            line,
            re.IGNORECASE,
        ):
            telnet_enabled = False
            continue

        # ---------------------------------------------------------
        # PASSWORD / CRYPTO
        # ---------------------------------------------------------
        if re.search(
            r"\bpassword-recovery\b|\bpassword\s+irreversible\b|\bcipher\b",
            line,
            re.IGNORECASE,
        ):
            password_encryption = True
            continue

        # ---------------------------------------------------------
        # LOCAL LOGGING
        # ---------------------------------------------------------
        if re.match(
            r"^info-center\s+enable$",
            line,
            re.IGNORECASE,
        ):
            local_logging = True
            continue

        if re.match(
            r"^info-center\s+loghost\b",
            line,
            re.IGNORECASE,
        ):
            remote_syslog = True
            continue

        # ---------------------------------------------------------
        # REMOTE SYSLOG
        # ---------------------------------------------------------
        if re.search(
            r"\binfo-center\s+loghost\b",
            line,
            re.IGNORECASE,
        ):
            remote_syslog = True
            continue

        # ---------------------------------------------------------
        # ACL
        # ---------------------------------------------------------
        match = re.match(
            r"^acl\s+(?:number\s+)?(\d+)",
            line,
            re.IGNORECASE,
        )

        if match:
            acl_number = int(match.group(1))

            if 2000 <= acl_number <= 2999:
                standard_acls += 1
            elif 3000 <= acl_number <= 3999:
                extended_acls += 1

            continue

        # ---------------------------------------------------------
        # INTERFACES
        # ---------------------------------------------------------
        if re.match(
            r"^(interface|interface\s+bridge-aggregation)\b",
            line,
            re.IGNORECASE,
        ):
            interfaces += 1
            continue

        # ---------------------------------------------------------
        # STATIC ROUTES
        # ---------------------------------------------------------
        if re.match(
            r"^ip\s+route-static\b",
            line,
            re.IGNORECASE,
        ):
            static_routes += 1
            continue

        # ---------------------------------------------------------
        # MONITORING / LOGGING
        # ---------------------------------------------------------
        if re.search(
            r"\binfo-center\b",
            line,
            re.IGNORECASE,
        ):
            local_logging = True
            continue

    # -------------------------------------------------------------
    # NORMALIZE SECURITY BASELINE MODEL
    # -------------------------------------------------------------

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
        "vendor": "HPE",
        "confidence": 0.95,
        "parser": {
            "type": "vendor_specific",
            "name": "hp_comware",
            "status": "PARSED",
        },
        "security_parameters": security_parameters,
        "unknown_lines": [],
    }