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


def parse_arista(content: str) -> dict[str, Any]:
    """
    Parse common Arista EOS configuration syntax into the
    normalized Security Baseline Model.
    """

    security_parameters = _empty_security_parameters()

    hostname = None
    aaa_configured = None
    ssh_enabled = None
    telnet_enabled = None
    local_logging = None
    remote_syslog = None
    password_encryption = None

    interfaces = 0
    standard_acls = 0
    extended_acls = 0
    static_routes = 0

    current_context: str | None = None

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("!"):
            continue

        # ---------------------------------------------------------
        # Hostname
        # ---------------------------------------------------------

        match = re.match(
            r"^hostname\s+(\S+)",
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
            r"^aaa\s+new-model$",
            line,
            re.IGNORECASE,
        ):
            aaa_configured = True
            continue

        if re.match(
            r"^aaa\s+authentication",
            line,
            re.IGNORECASE,
        ):
            aaa_configured = True
            continue

        # ---------------------------------------------------------
        # SSH
        # ---------------------------------------------------------

        if re.match(
            r"^ip\s+ssh\s+version\s+\d+",
            line,
            re.IGNORECASE,
        ):
            ssh_enabled = True
            continue

        if re.match(
            r"^management\s+ssh",
            line,
            re.IGNORECASE,
        ):
            ssh_enabled = True
            continue

        # ---------------------------------------------------------
        # Telnet
        # ---------------------------------------------------------

        if re.match(
            r"^transport\s+input\s+telnet",
            line,
            re.IGNORECASE,
        ):
            telnet_enabled = True
            continue

        if re.match(
            r"^transport\s+input\s+(?:ssh|none)",
            line,
            re.IGNORECASE,
        ):
            telnet_enabled = False
            continue

        # ---------------------------------------------------------
        # Password encryption
        # ---------------------------------------------------------

        if re.match(
            r"^service\s+password-encryption$",
            line,
            re.IGNORECASE,
        ):
            password_encryption = True
            continue

        # ---------------------------------------------------------
        # Local logging
        # ---------------------------------------------------------

        if re.match(
            r"^logging\s+buffered",
            line,
            re.IGNORECASE,
        ):
            local_logging = True
            continue

        # ---------------------------------------------------------
        # Remote syslog
        # ---------------------------------------------------------

        if re.match(
            r"^logging\s+\d{1,3}(?:\.\d{1,3}){3}",
            line,
            re.IGNORECASE,
        ):
            remote_syslog = True
            continue

        # ---------------------------------------------------------
        # Interfaces
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
        # Standard ACL
        # ---------------------------------------------------------

        if re.match(
            r"^ip\s+access-list\s+standard\s+\S+",
            line,
            re.IGNORECASE,
        ):
            standard_acls += 1
            current_context = "standard_acl"
            continue

        # ---------------------------------------------------------
        # Extended ACL
        # ---------------------------------------------------------

        if re.match(
            r"^ip\s+access-list\s+extended\s+\S+",
            line,
            re.IGNORECASE,
        ):
            extended_acls += 1
            current_context = "extended_acl"
            continue

        # ---------------------------------------------------------
        # Static routes
        # ---------------------------------------------------------

        if re.match(
            r"^ip\s+route\s+\S+",
            line,
            re.IGNORECASE,
        ):
            static_routes += 1
            continue

        # ---------------------------------------------------------
        # Context exit
        # ---------------------------------------------------------

        if line == "exit":
            current_context = None

    # -------------------------------------------------------------
    # Build normalized Security Baseline Model
    # -------------------------------------------------------------

    if hostname is not None:
        security_parameters["management"]["hostname"] = hostname

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

    if local_logging is not None:
        security_parameters["logging"][
            "local_buffered_logging"
        ] = local_logging

    if remote_syslog is not None:
        security_parameters["logging"][
            "remote_syslog"
        ] = remote_syslog

    if password_encryption is not None:
        security_parameters["crypto"][
            "password_encryption"
        ] = password_encryption

    security_parameters["access_control"][
        "standard_acls"
    ] = standard_acls

    security_parameters["access_control"][
        "extended_acls"
    ] = extended_acls

    security_parameters["interfaces"]["count"] = interfaces

    security_parameters["routing"][
        "static_routes"
    ] = static_routes

    if local_logging is not None or remote_syslog is not None:
        security_parameters["monitoring"][
            "logging_configured"
        ] = bool(local_logging or remote_syslog)

    return {
        "vendor": "Arista",
        "confidence": 0.95,
        "parser": {
            "type": "vendor_specific",
            "name": "arista_eos",
            "status": "PARSED",
        },
        "security_parameters": security_parameters,
        "unknown_lines": [],
    }