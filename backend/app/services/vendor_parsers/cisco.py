from __future__ import annotations

import re
from typing import Any


def parse_cisco(
    configuration: str,
) -> dict[str, Any]:
    """
    Parse Cisco IOS/IOS-XE configuration into the
    vendor-neutral security baseline model.

    Security controls use three-state semantics:
        True  = explicitly detected as enabled/configured
        False = explicitly detected as disabled/not configured
        None  = insufficient evidence to determine state
    """

    parameters: dict[str, Any] = {
        "management": {
            "hostname": None,
            "enable_secret": None,
            "local_users": [],
        },
        "authentication": {
            "aaa_new_model": None,
        },
        "remote_access": {
            "ssh_enabled": None,
            "ssh_version": None,
            "telnet_enabled": None,
        },
        "crypto": {
            "password_encryption": None,
        },
        "logging": {
            "local_buffered_logging": None,
            "remote_syslog": None,
            "timestamps": None,
        },
        "access_control": {
            "standard_acls": 0,
            "extended_acls": 0,
        },
        "firewall": {},
        "interfaces": {
            "count": 0,
            "names": [],
        },
        "routing": {
            "ospf": False,
            "bgp": False,
            "eigrp": False,
            "isis": False,
        },
        "monitoring": {
            "logging_configured": None,
        },
    }

    # ---------------------------------------------------------
    # Management / Authentication
    # ---------------------------------------------------------

    hostname_match = re.search(
        r"^\s*hostname\s+(\S+)",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    if hostname_match:
        parameters["management"]["hostname"] = (
            hostname_match.group(1)
        )

    # AAA new-model
    if re.search(
        r"^\s*aaa\s+new-model\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["authentication"]["aaa_new_model"] = True
    elif re.search(
        r"^\s*no\s+aaa\s+new-model\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["authentication"]["aaa_new_model"] = False

    # Enable secret
    if re.search(
        r"^\s*enable\s+secret\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["management"]["enable_secret"] = True
    elif re.search(
        r"^\s*no\s+enable\s+secret\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["management"]["enable_secret"] = False

    parameters["management"]["local_users"] = re.findall(
        r"^\s*username\s+(\S+)",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    # ---------------------------------------------------------
    # SSH / Remote Access
    # ---------------------------------------------------------

    ssh_match = re.search(
        r"^\s*ip\s+ssh\s+version\s+(\d+)",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    transport_ssh_match = re.search(
        r"^\s*transport\s+input\s+.*\bssh\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    if ssh_match:
        parameters["remote_access"]["ssh_enabled"] = True
        parameters["remote_access"]["ssh_version"] = int(
            ssh_match.group(1)
        )
    elif transport_ssh_match:
        parameters["remote_access"]["ssh_enabled"] = True

    # Explicit SSH disable
    if re.search(
        r"^\s*no\s+ip\s+ssh\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["remote_access"]["ssh_enabled"] = False

    vty_blocks = re.findall(
        r"^\s*line\s+vty\b[\s\S]*?(?=^\s*!|\Z)",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    # Explicit VTY transport configuration
    if re.search(
        r"^\s*transport\s+input\s+.*\bssh\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["remote_access"]["ssh_enabled"] = True

    if re.search(
        r"^\s*transport\s+input\s+none\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["remote_access"]["ssh_enabled"] = False

    for block in vty_blocks:
        if re.search(
            r"^\s*transport\s+input\s+.*\btelnet\b",
            block,
            re.MULTILINE | re.IGNORECASE,
        ):
            parameters["remote_access"]["telnet_enabled"] = True

        if re.search(
            r"^\s*transport\s+input\s+none\b",
            block,
            re.MULTILINE | re.IGNORECASE,
        ):
            parameters["remote_access"]["telnet_enabled"] = False

    # ---------------------------------------------------------
    # Logging
    # ---------------------------------------------------------

    # Local buffered logging
    if re.search(
        r"^\s*logging\s+buffered\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["logging"]["local_buffered_logging"] = True
    elif re.search(
        r"^\s*no\s+logging\s+buffered\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["logging"]["local_buffered_logging"] = False

    # Remote syslog
    #
    # Supports both:
    #   logging 10.10.10.50
    #   logging host 10.10.10.50
    #
    if re.search(
        r"^\s*logging\s+(?:host\s+)?\d{1,3}(?:\.\d{1,3}){3}\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["logging"]["remote_syslog"] = True
    elif re.search(
        r"^\s*no\s+logging\s+(?:host\s+)?\d{1,3}(?:\.\d{1,3}){3}\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["logging"]["remote_syslog"] = False

    # Log timestamps
    if re.search(
        r"^\s*service\s+timestamps\s+log\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["logging"]["timestamps"] = True
    elif re.search(
        r"^\s*no\s+service\s+timestamps\s+log\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["logging"]["timestamps"] = False

    # ---------------------------------------------------------
    # Cryptography
    # ---------------------------------------------------------

    # Password encryption
    if re.search(
        r"^\s*service\s+password-encryption\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["crypto"]["password_encryption"] = True
    elif re.search(
        r"^\s*no\s+service\s+password-encryption\b",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    ):
        parameters["crypto"]["password_encryption"] = False

    # ---------------------------------------------------------
    # Access Control
    # ---------------------------------------------------------

    standard_acl_pattern = (
        r"^\s*access-list\s+"
        r"(?:[1-9]\d?|[1-9]\d{3})\s+"
        r"(?:permit|deny)\b"
    )

    extended_acl_pattern = (
        r"^\s*access-list\s+"
        r"(?:1\d{2}|2[0-5]\d{2}|26\d{2})\s+"
        r"(?:permit|deny)\b"
    )

    parameters["access_control"]["standard_acls"] = len(
        re.findall(
            standard_acl_pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        )
    )

    parameters["access_control"]["extended_acls"] = len(
        re.findall(
            extended_acl_pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        )
    )

    # ---------------------------------------------------------
    # Interfaces
    # ---------------------------------------------------------

    interface_names = re.findall(
        r"^\s*interface\s+(\S+)",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    parameters["interfaces"] = {
        "count": len(interface_names),
        "names": interface_names,
    }

    # ---------------------------------------------------------
    # Routing
    # ---------------------------------------------------------

    routing_checks = {
        "ospf": r"^\s*router\s+ospf\b",
        "bgp": r"^\s*router\s+bgp\b",
        "eigrp": r"^\s*router\s+eigrp\b",
        "isis": r"^\s*router\s+isis\b",
    }

    for protocol, pattern in routing_checks.items():
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            parameters["routing"][protocol] = True

    # ---------------------------------------------------------
    # Monitoring
    # ---------------------------------------------------------

    logging_values = [
        parameters["logging"]["local_buffered_logging"],
        parameters["logging"]["remote_syslog"],
        parameters["logging"]["timestamps"],
    ]

    if any(value is True for value in logging_values):
        parameters["monitoring"]["logging_configured"] = True
    elif all(value is False for value in logging_values):
        parameters["monitoring"]["logging_configured"] = False
    else:
        parameters["monitoring"]["logging_configured"] = None

    return {
        "parser": "cisco_ios",
        "status": "PARSED",
        "security_parameters": parameters,
    }