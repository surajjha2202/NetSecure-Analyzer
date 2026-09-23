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


def parse_nokia(content: str) -> dict[str, Any]:
    """
    Parse common Nokia SR OS configuration syntax into the
    normalized Security Baseline Model.

    Covers common SR OS areas:
    - system identity
    - AAA/authentication
    - SSH/Telnet
    - logging
    - filters
    - interfaces
    - static routing
    """

    if not content or not content.strip():
        raise ValueError("Configuration cannot be empty")

    security_parameters = _empty_security_parameters()

    hostname = None
    aaa_configured = None
    ssh_enabled = None
    telnet_enabled = None
    local_logging = None
    remote_syslog = None

    interfaces = 0
    firewall_filters = 0
    static_routes = 0

    current_context: list[str] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        # ---------------------------------------------------------
        # Context handling
        # ---------------------------------------------------------

        if line == "exit":
            if current_context:
                current_context.pop()
            continue

        # Nokia SR OS uses "exit all" to return to top level.
        if line == "exit all":
            current_context.clear()
            continue

        # ---------------------------------------------------------
        # System configuration
        # ---------------------------------------------------------

        if line == "configure system":
            current_context = ["system"]
            continue

        if current_context == ["system"]:
            match = re.match(
                r"name\s+(.+)",
                line,
                re.IGNORECASE,
            )

            if match:
                hostname = match.group(1).strip().strip('"')
                continue

        # ---------------------------------------------------------
        # AAA / authentication
        # ---------------------------------------------------------

        if line.startswith("configure system security"):
            current_context = [
                "system",
                "security",
            ]
            aaa_configured = True
            continue

        if current_context[:2] == [
            "system",
            "security",
        ]:
            if re.search(
                r"\b(authentication|authorization|accounting)\b",
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
            r"^no\s+ssh\s+server\s+enable$",
            line,
            re.IGNORECASE,
        ):
            ssh_enabled = False
            continue

        # ---------------------------------------------------------
        # Telnet
        # ---------------------------------------------------------

        if re.match(
            r"^telnet\s+server\s+enable$",
            line,
            re.IGNORECASE,
        ):
            telnet_enabled = True
            continue

        if re.match(
            r"^no\s+telnet\s+server\s+enable$",
            line,
            re.IGNORECASE,
        ):
            telnet_enabled = False
            continue

        # ---------------------------------------------------------
        # Logging
        # ---------------------------------------------------------

        if re.match(
            r"^configure\s+log",
            line,
            re.IGNORECASE,
        ):
            local_logging = True
            current_context = ["log"]
            continue

        if re.search(
            r"syslog",
            line,
            re.IGNORECASE,
        ):
            remote_syslog = True
            continue

        if re.search(
            r"(log-id|log-id\s+\d+)",
            line,
            re.IGNORECASE,
        ):
            local_logging = True
            continue

        # ---------------------------------------------------------
        # Interfaces
        # ---------------------------------------------------------

        if re.match(
            r"^configure\s+router\s+interface\s+\S+",
            line,
            re.IGNORECASE,
        ):
            interfaces += 1
            current_context = ["router", "interface"]
            continue

        # ---------------------------------------------------------
        # IP filter / firewall filters
        # ---------------------------------------------------------

        if re.match(
            r"^configure\s+filter\s+ip-filter\s+\S+",
            line,
            re.IGNORECASE,
        ):
            firewall_filters += 1
            current_context = [
                "filter",
                "ip-filter",
            ]
            continue

        # ---------------------------------------------------------
        # Static routes
        # ---------------------------------------------------------

        if re.match(
            r"^static-route\s+\S+",
            line,
            re.IGNORECASE,
        ):
            static_routes += 1
            continue

        if re.match(
            r"^route\s+\S+",
            line,
            re.IGNORECASE,
        ):
            static_routes += 1
            continue

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
    ] = firewall_filters

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
        "vendor": "Nokia",
        "confidence": 0.95,
        "parser": {
            "type": "vendor_specific",
            "name": "nokia_sros",
            "status": "PARSED",
        },
        "security_parameters": security_parameters,
        "unknown_lines": [],
    }