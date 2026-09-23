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


def parse_juniper(content: str) -> dict[str, Any]:
    """
    Parse common Juniper Junos configuration syntax into the
    normalized Security Baseline Model.
    """

    security_parameters = _empty_security_parameters()

    hostname = None
    ssh_enabled = None
    telnet_enabled = None
    local_logging = None
    remote_syslog = None
    aaa_configured = None
    interfaces = 0
    firewall_filters = 0
    static_routes = 0

    lines = content.splitlines()

    in_system = False
    in_services = False
    in_syslog = False
    in_security = False
    in_firewall = False
    in_interfaces = False
    in_routing_options = False

    brace_depth = 0

    for raw_line in lines:
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        # ---------------------------------------------------------
        # Track major Junos configuration hierarchy
        # ---------------------------------------------------------

        if line.startswith("system {"):
            in_system = True
            in_services = False
            in_security = False
            in_firewall = False
            in_interfaces = False
            in_routing_options = False

        elif line.startswith("services {"):
            in_services = True

        elif line.startswith("security {"):
            in_security = True
            in_system = False
            in_services = False

        elif line.startswith("firewall {"):
            in_firewall = True
            in_security = False

        elif line.startswith("interfaces {"):
            in_interfaces = True
            in_firewall = False

        elif line.startswith("routing-options {"):
            in_routing_options = True

        # ---------------------------------------------------------
        # Hostname
        # ---------------------------------------------------------

        match = re.match(r"host-name\s+([^\s;]+)\s*;", line, re.IGNORECASE)
        if match:
            hostname = match.group(1)
            continue

        # ---------------------------------------------------------
        # SSH
        # ---------------------------------------------------------

        if re.match(r"ssh\s*;", line, re.IGNORECASE):
            ssh_enabled = True
            continue

        if re.match(r"no-ssh\s*;", line, re.IGNORECASE):
            ssh_enabled = False
            continue

        # ---------------------------------------------------------
        # Telnet
        # ---------------------------------------------------------

        if re.match(r"telnet\s*;", line, re.IGNORECASE):
            telnet_enabled = True
            continue

        if re.match(r"no-telnet\s*;", line, re.IGNORECASE):
            telnet_enabled = False
            continue

        # ---------------------------------------------------------
        # Authentication
        # ---------------------------------------------------------

        if re.match(
            r"authentication-order\s+\[.*\]\s*;",
            line,
            re.IGNORECASE,
        ):
            aaa_configured = True
            continue

        if re.match(
            r"authentication-order\s+\S+\s*;",
            line,
            re.IGNORECASE,
        ):
            aaa_configured = True
            continue

        # ---------------------------------------------------------
        # Local logging
        # ---------------------------------------------------------

        if re.match(
            r"file\s+\S+\s*\{",
            line,
            re.IGNORECASE,
        ):
            local_logging = True
            continue

        # ---------------------------------------------------------
        # Remote syslog
        # ---------------------------------------------------------

        if re.match(
            r"host\s+\S+\s*\{",
            line,
            re.IGNORECASE,
        ):
            remote_syslog = True
            continue

        # ---------------------------------------------------------
        # Firewall filters
        # ---------------------------------------------------------

        if in_firewall and re.match(
            r"[A-Za-z0-9_.-]+\s*\{",
            line,
        ):
            firewall_filters += 1

        # ---------------------------------------------------------
        # Interfaces
        # ---------------------------------------------------------

        if in_interfaces and re.match(
            r"[A-Za-z0-9/_.:-]+\s*\{",
            line,
        ):
            interfaces += 1

        # ---------------------------------------------------------
        # Static routes
        # ---------------------------------------------------------

        if in_routing_options and re.match(
            r"static\s*\{",
            line,
            re.IGNORECASE,
        ):
            static_routes += 1

        # ---------------------------------------------------------
        # Brace tracking
        # ---------------------------------------------------------

        brace_depth += line.count("{")
        brace_depth -= line.count("}")

        if brace_depth <= 0:
            if line == "}":
                in_system = False
                in_services = False
                in_syslog = False
                in_security = False
                in_firewall = False
                in_interfaces = False
                in_routing_options = False

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

    security_parameters["access_control"][
        "standard_acls"
    ] = firewall_filters

    security_parameters["interfaces"]["count"] = interfaces

    security_parameters["routing"][
        "static_routes"
    ] = static_routes

    if local_logging is not None or remote_syslog is not None:
        security_parameters["monitoring"][
            "logging_configured"
        ] = bool(local_logging or remote_syslog)

    return {
        "vendor": "Juniper",
        "confidence": 0.95,
        "parser": {
            "type": "vendor_specific",
            "name": "juniper_junos",
            "status": "PARSED",
        },
        "security_parameters": security_parameters,
        "unknown_lines": [],
    }