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


def parse_mikrotik(content: str) -> dict[str, Any]:
    """
    Parse common MikroTik RouterOS export syntax into the
    normalized Security Baseline Model.

    Supports common RouterOS configuration sections for:
    - system identity
    - users/authentication
    - SSH/Telnet services
    - logging
    - firewall filters
    - interfaces
    - IP routes
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

    firewall_rules = 0
    interfaces = 0
    static_routes = 0

    current_section: str | None = None

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        # ---------------------------------------------------------
        # Section detection
        # ---------------------------------------------------------

        if line.startswith("/"):
            current_section = line.lower()
            continue

        # ---------------------------------------------------------
        # System identity / hostname
        # ---------------------------------------------------------

        if current_section == "/system identity":
            match = re.search(
                r'name\s*=\s*"([^"]+)"',
                line,
                re.IGNORECASE,
            )

            if match:
                hostname = match.group(1).strip()
                continue

        # ---------------------------------------------------------
        # Users / authentication
        # ---------------------------------------------------------

        if current_section == "/user":
            match = re.search(
                r'name\s*=\s*"([^"]+)"',
                line,
                re.IGNORECASE,
            )

            if match:
                aaa_configured = True
                continue

        # ---------------------------------------------------------
        # SSH / Telnet services
        # ---------------------------------------------------------

        if current_section == "/ip service":

            ssh_match = re.search(
                r"^\s*set\s+ssh\s+.*disabled=(yes|no)",
                line,
                re.IGNORECASE,
            )

            if ssh_match:
                ssh_enabled = (
                    ssh_match.group(1).lower() == "no"
                )
                continue

            telnet_match = re.search(
                r"^\s*set\s+telnet\s+.*disabled=(yes|no)",
                line,
                re.IGNORECASE,
            )

            if telnet_match:
                telnet_enabled = (
                    telnet_match.group(1).lower() == "no"
                )
                continue
        # ---------------------------------------------------------
        # Logging
        # ---------------------------------------------------------

        if current_section == "/system logging":

            action_match = re.search(
                r'action=(\S+)',
                line,
                re.IGNORECASE,
            )

            topics_match = re.search(
                r'topics=([^\s]+)',
                line,
                re.IGNORECASE,
            )

            if action_match:
                action = action_match.group(1).lower()

                if action in {
                    "memory",
                    "disk",
                    "echo",
                }:
                    local_logging = True

                elif action in {
                    "remote",
                }:
                    remote_syslog = True

            if topics_match:
                local_logging = True

            continue

        # ---------------------------------------------------------
        # Firewall filter rules
        # ---------------------------------------------------------

        if current_section in {
            "/ip firewall filter",
            "/ipv6 firewall filter",
        }:
            if re.search(
                r'(chain|action|protocol|src-address|dst-address)=',
                line,
                re.IGNORECASE,
            ):
                firewall_rules += 1

            continue

        # ---------------------------------------------------------
        # Interfaces
        # ---------------------------------------------------------

        if current_section in {
            "/interface",
            "/interface ethernet",
            "/interface bridge",
            "/interface vlan",
            "/interface wireless",
        }:
            if re.search(
                r'name=',
                line,
                re.IGNORECASE,
            ):
                interfaces += 1

            continue

        # ---------------------------------------------------------
        # Static routes
        # ---------------------------------------------------------

        if current_section in {
            "/ip route",
            "/ipv6 route",
        }:
            if re.search(
                r'(dst-address|gateway)=',
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
    ] = firewall_rules

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
        "vendor": "MikroTik",
        "confidence": 0.95,
        "parser": {
            "type": "vendor_specific",
            "name": "mikrotik_routeros",
            "status": "PARSED",
        },
        "security_parameters": security_parameters,
        "unknown_lines": [],
    }