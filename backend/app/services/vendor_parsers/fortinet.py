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


def parse_fortinet(content: str) -> dict[str, Any]:
    """
    Parse common Fortinet/FortiGate configuration syntax into the
    normalized Security Baseline Model.
    """

    security_parameters = _empty_security_parameters()

    hostname = None
    ssh_enabled = None
    telnet_enabled = None
    local_logging = None
    remote_syslog = None
    password_encryption = None
    standard_acls = 0
    interfaces = 0
    static_routes = 0

    current_section: str | None = None
    current_edit: str | None = None

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        # ---------------------------------------------------------
        # Global configuration
        # ---------------------------------------------------------

        match = re.match(r'^set hostname\s+"?([^"]+)"?$', line, re.IGNORECASE)
        if match:
            hostname = match.group(1).strip()
            continue

        # ---------------------------------------------------------
        # Configuration sections
        # ---------------------------------------------------------

        match = re.match(r'^config\s+(.+)$', line, re.IGNORECASE)
        if match:
            current_section = match.group(1).strip().lower()
            current_edit = None
            continue

        if line.lower() == "end":
            current_section = None
            current_edit = None
            continue

        match = re.match(r'^edit\s+"?([^"]+)"?$', line, re.IGNORECASE)
        if match:
            current_edit = match.group(1).strip()

            if current_section == "firewall policy":
                standard_acls += 1

            elif current_section == "system interface":
                interfaces += 1

            elif current_section == "router static":
                static_routes += 1

            continue

        if line.lower() == "next":
            current_edit = None
            continue

        # ---------------------------------------------------------
        # System settings
        # ---------------------------------------------------------

        if current_section == "system global":
            if re.search(r'\bhostname\b', line, re.IGNORECASE):
                match = re.search(r'set hostname\s+"?([^"]+)"?', line, re.IGNORECASE)
                if match:
                    hostname = match.group(1).strip()

        # ---------------------------------------------------------
        # SSH / Telnet
        # ---------------------------------------------------------

        if current_section == "system global":
            if re.search(r'set admin-ssh-port\s+\d+', line, re.IGNORECASE):
                ssh_enabled = True

            if re.search(r'set admin-telnet\s+enable', line, re.IGNORECASE):
                telnet_enabled = True

            if re.search(r'set admin-telnet\s+disable', line, re.IGNORECASE):
                telnet_enabled = False

        # ---------------------------------------------------------
        # Local logging
        # ---------------------------------------------------------

        if current_section == "log memory setting":
            if re.search(r'set status\s+enable', line, re.IGNORECASE):
                local_logging = True

            if re.search(r'set status\s+disable', line, re.IGNORECASE):
                local_logging = False

        # ---------------------------------------------------------
        # Remote syslog
        # ---------------------------------------------------------

        if current_section == "log syslogd setting":
            if re.search(r'set status\s+enable', line, re.IGNORECASE):
                remote_syslog = True

            if re.search(r'set status\s+disable', line, re.IGNORECASE):
                remote_syslog = False





    # -------------------------------------------------------------
    # Build normalized Security Baseline Model
    # -------------------------------------------------------------

    if hostname is not None:
        security_parameters["management"]["hostname"] = hostname

    if ssh_enabled is not None:
        security_parameters["remote_access"]["ssh_enabled"] = ssh_enabled

    if telnet_enabled is not None:
        security_parameters["remote_access"]["telnet_enabled"] = telnet_enabled

    if local_logging is not None:
        security_parameters["logging"]["local_buffered_logging"] = local_logging

    if remote_syslog is not None:
        security_parameters["logging"]["remote_syslog"] = remote_syslog

    if password_encryption is not None:
        security_parameters["crypto"]["password_encryption"] = password_encryption

    security_parameters["access_control"]["standard_acls"] = standard_acls
    security_parameters["interfaces"]["count"] = interfaces
    security_parameters["routing"]["static_routes"] = static_routes

    if local_logging is not None or remote_syslog is not None:
        security_parameters["monitoring"]["logging_configured"] = bool(
            local_logging or remote_syslog
        )

    return {
        "vendor": "Fortinet",
        "confidence": 0.95,
        "parser": {
            "type": "vendor_specific",
            "name": "fortinet",
            "status": "PARSED",
        },
        "security_parameters": security_parameters,
        "unknown_lines": [],
    }
