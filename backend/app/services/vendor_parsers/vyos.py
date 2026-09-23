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


def parse_vyos(configuration: str) -> dict[str, Any]:
    security = _empty_security_parameters()

    hostname_match = re.search(
        r"^\s*set\s+system\s+host-name\s+(\S+)",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    if hostname_match:
        security["management"]["hostname"] = hostname_match.group(1)

    ssh_enabled = bool(
        re.search(
            r"^\s*set\s+service\s+ssh\b",
            configuration,
            re.MULTILINE | re.IGNORECASE,
        )
    )

    telnet_enabled = bool(
        re.search(
            r"^\s*set\s+service\s+telnet\b",
            configuration,
            re.MULTILINE | re.IGNORECASE,
        )
    )

    security["remote_access"] = {
        "ssh_enabled": ssh_enabled,
        "telnet_enabled": telnet_enabled,
    }

    interface_matches = re.findall(
        r"^\s*set\s+interfaces\s+\S+\s+(\S+)\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    security["interfaces"] = {
        "count": len(interface_matches),
        "names": interface_matches,
    }

    firewall_rules = re.findall(
        r"^\s*set\s+firewall\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    security["firewall"]["rules"] = len(firewall_rules)

    static_routes = re.findall(
        r"^\s*set\s+protocols\s+static\s+route\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    security["routing"]["static_routes"] = len(static_routes)

    return {
        "parser": {
            "type": "vendor_specific",
            "name": "vyos",
            "status": "PARSED",
        },
        "security_parameters": security,
    }