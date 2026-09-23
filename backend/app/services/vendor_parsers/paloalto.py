from __future__ import annotations

import re
import xml.etree.ElementTree as ET
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


def _find_text(root: ET.Element, path: str) -> str | None:
    element = root.find(path)
    if element is None or element.text is None:
        return None

    value = element.text.strip()
    return value or None


def _count_entries(element: ET.Element | None) -> int:
    if element is None:
        return 0

    return sum(
        1
        for child in element
        if child.tag == "entry"
    )


def _parse_panos_set_configuration(content: str) -> dict[str, Any]:
    """
    Parse PAN-OS CLI `set` configuration syntax.

    Example:
        set deviceconfig system hostname PA-TEST
        set network interface ethernet ethernet1/1 layer3 ip 192.168.1.1/24
    """

    security_parameters = _empty_security_parameters()
    unknown_lines: list[str] = []

    lines = [
        line.strip()
        for line in content.splitlines()
        if line.strip()
    ]

    recognized = 0

    for line in lines:
        if not line.startswith("set "):
            unknown_lines.append(line)
            continue

        # ---------------------------------------------------------
        # Hostname
        # ---------------------------------------------------------

        match = re.match(
            r"^set\s+deviceconfig\s+system\s+hostname\s+(.+)$",
            line,
            re.IGNORECASE,
        )

        if match:
            security_parameters["management"]["hostname"] = (
                match.group(1).strip()
            )
            recognized += 1
            continue

        # ---------------------------------------------------------
        # SSH
        # ---------------------------------------------------------

        if re.match(
            r"^set\s+deviceconfig\s+system\s+service\s+disable-ssh\b",
            line,
            re.IGNORECASE,
        ):
            security_parameters["remote_access"]["ssh_enabled"] = False
            recognized += 1
            continue

        if re.match(
            r"^set\s+deviceconfig\s+system\s+service\s+ssh\b",
            line,
            re.IGNORECASE,
        ):
            security_parameters["remote_access"]["ssh_enabled"] = True
            recognized += 1
            continue

        # ---------------------------------------------------------
        # Telnet
        # ---------------------------------------------------------

        if re.match(
            r"^set\s+deviceconfig\s+system\s+service\s+disable-telnet\b",
            line,
            re.IGNORECASE,
        ):
            security_parameters["remote_access"]["telnet_enabled"] = False
            recognized += 1
            continue

        if re.match(
            r"^set\s+deviceconfig\s+system\s+service\s+telnet\b",
            line,
            re.IGNORECASE,
        ):
            security_parameters["remote_access"]["telnet_enabled"] = True
            recognized += 1
            continue

        # ---------------------------------------------------------
        # Ethernet interfaces
        # ---------------------------------------------------------

        match = re.match(
            r"^set\s+network\s+interface\s+ethernet\s+(\S+)\b",
            line,
            re.IGNORECASE,
        )

        if match:
            interface_name = match.group(1)

            interfaces = security_parameters["interfaces"]

            if "names" not in interfaces:
                interfaces["names"] = []

            if interface_name not in interfaces["names"]:
                interfaces["names"].append(interface_name)

            interfaces["count"] = len(interfaces["names"])

            recognized += 1
            continue

        # ---------------------------------------------------------
        # Static routes
        # ---------------------------------------------------------

        if re.match(
            r"^set\s+network\s+virtual-router\s+\S+\s+routing-table\s+ip\s+static-route\b",
            line,
            re.IGNORECASE,
        ):
            routing = security_parameters["routing"]

            routing["static_routes"] = (
                int(routing.get("static_routes", 0)) + 1
            )

            recognized += 1
            continue

        # ---------------------------------------------------------
        # Security policy rules
        # ---------------------------------------------------------

        if re.match(
            r"^set\s+rulebase\s+security\s+rules\s+\S+\b",
            line,
            re.IGNORECASE,
        ):
            access_control = security_parameters["access_control"]

            access_control["standard_acls"] = (
                int(access_control.get("standard_acls", 0)) + 1
            )

            recognized += 1
            continue

        # ---------------------------------------------------------
        # Syslog
        # ---------------------------------------------------------

        if re.match(
            r"^set\s+(?:shared|deviceconfig)\s+log-settings\b",
            line,
            re.IGNORECASE,
        ):
            security_parameters["logging"]["remote_syslog"] = True
            security_parameters["monitoring"]["logging_configured"] = True

            recognized += 1
            continue

        # ---------------------------------------------------------
        # Authentication
        # ---------------------------------------------------------

        if re.match(
            r"^set\s+deviceconfig\s+system\s+type\s+static\b",
            line,
            re.IGNORECASE,
        ):
            recognized += 1
            continue

        unknown_lines.append(line)

    if security_parameters["interfaces"].get("count") is None:
        security_parameters["interfaces"]["count"] = 0

    logging = security_parameters["logging"]

    if logging.get("local_buffered_logging") is True:
        security_parameters["monitoring"]["logging_configured"] = True

    if logging.get("remote_syslog") is True:
        security_parameters["monitoring"]["logging_configured"] = True

    return {
        "vendor": "Palo Alto Networks",
        "confidence": 0.95 if recognized > 0 else 0.0,
        "parser": {
            "type": "vendor_specific",
            "name": "paloalto_panos",
            "status": "PARSED" if recognized > 0 else "PARSE_ERROR",
        },
        "security_parameters": security_parameters,
        "unknown_lines": unknown_lines,
    }


def _parse_panos_xml_configuration(content: str) -> dict[str, Any]:
    """
    Parse a Palo Alto PAN-OS XML configuration.
    """

    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        return {
            "vendor": "Palo Alto Networks",
            "confidence": 0.0,
            "parser": {
                "type": "vendor_specific",
                "name": "paloalto_panos",
                "status": "PARSE_ERROR",
            },
            "security_parameters": _empty_security_parameters(),
            "unknown_lines": [],
            "error": f"Invalid PAN-OS XML: {exc}",
        }

    security_parameters = _empty_security_parameters()

    # -------------------------------------------------------------
    # Locate device entry
    # -------------------------------------------------------------

    device_entry = root.find(
        "./devices/entry"
    )

    if device_entry is None:
        device_entry = root.find(
            ".//devices/entry"
        )

    # -------------------------------------------------------------
    # Hostname
    # -------------------------------------------------------------

    hostname = None

    if device_entry is not None:
        hostname = _find_text(
            device_entry,
            "./deviceconfig/system/hostname",
        )

    if hostname is not None:
        security_parameters["management"][
            "hostname"
        ] = hostname

    # -------------------------------------------------------------
    # Management services
    # -------------------------------------------------------------

    ssh_enabled = None
    telnet_enabled = None

    if device_entry is not None:
        system = device_entry.find(
            "./deviceconfig/system"
        )

        if system is not None:
            service = system.find("service")

            if service is not None:
                disable_ssh = _find_text(
                    service,
                    "disable-ssh",
                )

                if disable_ssh is not None:
                    ssh_enabled = (
                        disable_ssh.lower() == "no"
                    )

                disable_telnet = _find_text(
                    service,
                    "disable-telnet",
                )

                if disable_telnet is not None:
                    telnet_enabled = (
                        disable_telnet.lower() == "no"
                    )

    if ssh_enabled is not None:
        security_parameters["remote_access"][
            "ssh_enabled"
        ] = ssh_enabled

    if telnet_enabled is not None:
        security_parameters["remote_access"][
            "telnet_enabled"
        ] = telnet_enabled

    # -------------------------------------------------------------
    # Interfaces
    # -------------------------------------------------------------

    interfaces_count = 0

    if device_entry is not None:
        ethernet = device_entry.find(
            "./network/interface/ethernet"
        )

        if ethernet is not None:
            interfaces_count = _count_entries(
                ethernet
            )

    security_parameters["interfaces"][
        "count"
    ] = interfaces_count

    # -------------------------------------------------------------
    # Static routes
    # -------------------------------------------------------------

    static_routes_count = 0

    if device_entry is not None:
        static_route = device_entry.find(
            "./network/virtual-router/entry/"
            "routing-table/ip/static-route"
        )

        if static_route is not None:
            static_routes_count = _count_entries(
                static_route
            )

    security_parameters["routing"][
        "static_routes"
    ] = static_routes_count

    # -------------------------------------------------------------
    # Security policies
    # -------------------------------------------------------------

    security_policies_count = 0

    if device_entry is not None:
        security_rules = device_entry.find(
            "./rulebase/security/rules"
        )

        if security_rules is not None:
            security_policies_count = _count_entries(
                security_rules
            )

    security_parameters["access_control"][
        "standard_acls"
    ] = security_policies_count

    # -------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------

    local_logging = None
    remote_syslog = None

    if device_entry is not None:
        log_settings = device_entry.find(
            "./deviceconfig/system/log-settings"
        )

        if log_settings is not None:
            local_logging = True

        shared_log_settings = device_entry.find(
            "./shared/log-settings"
        )

        if shared_log_settings is not None:
            syslog = shared_log_settings.find(
                ".//syslog"
            )

            if syslog is not None:
                remote_syslog = True

    if local_logging is not None:
        security_parameters["logging"][
            "local_buffered_logging"
        ] = local_logging

    if remote_syslog is not None:
        security_parameters["logging"][
            "remote_syslog"
        ] = remote_syslog

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
        "vendor": "Palo Alto Networks",
        "confidence": 0.95,
        "parser": {
            "type": "vendor_specific",
            "name": "paloalto_panos",
            "status": "PARSED",
        },
        "security_parameters": security_parameters,
        "unknown_lines": [],
    }


def parse_paloalto(content: str) -> dict[str, Any]:
    """
    Parse Palo Alto PAN-OS configuration.

    Supported formats:
    1. PAN-OS XML configuration
    2. PAN-OS CLI `set` configuration
    """

    if not content or not content.strip():
        raise ValueError("Configuration cannot be empty")

    stripped = content.lstrip()

    # PAN-OS CLI set-style configuration.
    if re.search(
        r"^\s*set\s+",
        content,
        re.MULTILINE | re.IGNORECASE,
    ):
        return _parse_panos_set_configuration(content)

    # Otherwise preserve the existing XML parser.
    if stripped.startswith("<"):
        return _parse_panos_xml_configuration(content)

    return {
        "vendor": "Palo Alto Networks",
        "confidence": 0.0,
        "parser": {
            "type": "vendor_specific",
            "name": "paloalto_panos",
            "status": "PARSE_ERROR",
        },
        "security_parameters": _empty_security_parameters(),
        "unknown_lines": [],
        "error": "Unsupported PAN-OS configuration format",
    }