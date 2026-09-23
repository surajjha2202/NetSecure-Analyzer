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


def parse_checkpoint(configuration: str) -> dict[str, Any]:
    security = _empty_security_parameters()

    hostname_match = re.search(
        r"^\s*set\s+hostname\s+(\S+)",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    if hostname_match:
        security["management"]["hostname"] = hostname_match.group(1)

    interface_matches = re.findall(
        r"^\s*set\s+interface\s+(\S+)",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    security["interfaces"] = {
        "count": len(interface_matches),
        "names": interface_matches,
    }

    static_routes = re.findall(
        r"^\s*set\s+static-route\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    security["routing"]["static_routes"] = len(static_routes)

    access_rules = re.findall(
        r"^\s*set\s+access-rule\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    security["firewall"]["access_rules"] = len(access_rules)

    return {
        "parser": {
            "type": "vendor_specific",
            "name": "checkpoint_gaia",
            "status": "PARSED",
        },
        "security_parameters": security,
    }