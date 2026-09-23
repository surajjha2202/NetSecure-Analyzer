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


def parse_cumulus(configuration: str) -> dict[str, Any]:
    security = _empty_security_parameters()

    hostname_match = re.search(
        r"^\s*nv\s+set\s+system\s+hostname\s+(\S+)",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    if hostname_match:
        security["management"]["hostname"] = hostname_match.group(1)

    interface_matches = re.findall(
        r"^\s*nv\s+set\s+interface\s+(\S+)",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    security["interfaces"] = {
        "count": len(set(interface_matches)),
        "names": sorted(set(interface_matches)),
    }

    static_routes = re.findall(
        r"^\s*nv\s+set\s+router\s+static\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    security["routing"]["static_routes"] = len(static_routes)

    firewall_rules = re.findall(
        r"^\s*(?:nv\s+set\s+acl|cl-acltool)\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    security["firewall"]["rules"] = len(firewall_rules)

    return {
        "parser": {
            "type": "vendor_specific",
            "name": "cumulus_linux",
            "status": "PARSED",
        },
        "security_parameters": security,
    }