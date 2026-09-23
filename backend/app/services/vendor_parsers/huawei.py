from __future__ import annotations

import re
from typing import Any


def _empty_security_parameters() -> dict[str, Any]:
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


def parse_huawei(content: str) -> dict[str, Any]:
    """
    Parse common Huawei VRP configuration syntax into the
    normalized Security Baseline Model.
    """

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

    interfaces = 0
    standard_acls = 0
    extended_acls = 0
    static_routes = 0

    current_context: str | None = None

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        # ---------------------------------------------------------
        # Hostname
        # ---------------------------------------------------------

        match = re.match(
            r"^sysname\s+(\S+)",
            line,
            re.IGNORECASE,
        )

        if match:
            hostname = match.group(1)
            continue

        # ---------------------------------------------------------
        # AAA
        # ---------------------------------------------------------

        if re.match(
            r"^aaa$",
            line,
            re.IGNORECASE,
        ):
            aaa_configured = True
            current_context = "aaa"
            continue

        if current_context == "aaa":
            if re.search(
                r"\bpassword\s+irreversible-cipher\b",
                line,
                re.IGNORECASE,
            ):
                password_encryption = True
                aaa_configured = True
                continue

            if re.match(
                r"^(local-user|authentication-scheme|authorization-scheme)\b",
                line,
                re.IGNORECASE,
            ):
                aaa_configured = True
                continue

        # ---------------------------------------------------------
        # SSH
        # ---------------------------------------------------------

        if re.search(
            r"stelnet\s+server\s+enable",
            line,
            re.IGNORECASE,
        ):
            ssh_enabled = True
            continue

        if re.search(
            r"undo\s+stelnet\s+server\s+enable",
            line,
            re.IGNORECASE,
        ):
            ssh_enabled = False
            continue

        # ---------------------------------------------------------
        # Telnet
        # ---------------------------------------------------------

        if re.match(
            r"^undo\s+telnet\s+server\s+enable$",
            line,
            re.IGNORECASE,
        ):
            telnet_enabled = False
            continue

        if re.match(
            r"^telnet\s+server\s+enable$",
            line,
            re.IGNORECASE,
        ):
            telnet_enabled = True
            continue

        # ---------------------------------------------------------
        # Password encryption / irreversible password handling
        # ---------------------------------------------------------

        if re.search(
            r"irreversible-cipher",
            line,
            re.IGNORECASE,
        ):
            password_encryption = True
            continue

        # ---------------------------------------------------------
        # Logging
        # ---------------------------------------------------------

        if re.match(
            r"^info-center\s+enable$",
            line,
            re.IGNORECASE,
        ):
            local_logging = True
            continue

        # ---------------------------------------------------------
        # Remote syslog
        # ---------------------------------------------------------

        if re.match(
            r"^info-center\s+loghost\s+\d{1,3}(?:\.\d{1,3}){3}",
            line,
            re.IGNORECASE,
        ):
            remote_syslog = True
            continue

        # ---------------------------------------------------------
        # Interface
        # ---------------------------------------------------------

        if re.match(
            r"^interface\s+\S+",
            line,
            re.IGNORECASE,
        ):
            interfaces += 1
            current_context = "interface"
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
            else:
                extended_acls += 1

            current_context = "acl"
            continue

        # ---------------------------------------------------------
        # Static routes
        # ---------------------------------------------------------

        if re.match(
            r"^ip\s+route-static\s+\S+",
            line,
            re.IGNORECASE,
        ):
            static_routes += 1
            continue

        # ---------------------------------------------------------
        # Context exit
        # ---------------------------------------------------------

        if line.lower() in {
            "quit",
            "return",
        }:
            current_context = None

    # -------------------------------------------------------------
    # Build normalized Security Baseline Model
    # -------------------------------------------------------------

    if hostname is not None:
        security_parameters["management"][
            "hostname"
        ] = hostname

    if aaa_configured is not None:
        security_parameters["authentication"][
            "aaa_new_model"
        ] = aaa_configured

    if ssh_enabled is not None:
        security_parameters["remote_access"][
            "ssh_enabled"
        ] = ssh_enabled

    if telnet_enabled is not None:
        security_parameters["remote_access"][
            "telnet_enabled"
        ] = telnet_enabled

    if password_encryption is not None:
        security_parameters["crypto"][
            "password_encryption"
        ] = password_encryption

    if local_logging is not None:
        security_parameters["logging"][
            "local_buffered_logging"
        ] = local_logging

    if remote_syslog is not None:
        security_parameters["logging"][
            "remote_syslog"
        ] = remote_syslog

    security_parameters["access_control"][
        "standard_acls"
    ] = standard_acls

    security_parameters["access_control"][
        "extended_acls"
    ] = extended_acls

    security_parameters["interfaces"][
        "count"
    ] = interfaces

    security_parameters["routing"][
        "static_routes"
    ] = static_routes

    if (
        local_logging is not None
        or remote_syslog is not None
    ):
        security_parameters["monitoring"][
            "logging_configured"
        ] = bool(
            local_logging
            or remote_syslog
        )

    return {
        "vendor": "Huawei",
        "confidence": 0.95,
        "parser": {
            "type": "vendor_specific",
            "name": "huawei_vrp",
            "status": "PARSED",
        },
        "security_parameters": security_parameters,
        "unknown_lines": [],
    }