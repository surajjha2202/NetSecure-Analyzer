"""
Framework-aware vendor remediation engine.

The compliance engine evaluates individual framework rules.
This module maps framework-specific rule IDs to canonical
security controls and then generates vendor-specific remediation.

Current implementation:
- Cisco IOS / IOS-XE
- CIS
- NIST
- DISA STIG
- ISO/IEC 27001

The architecture is intentionally extensible for additional vendors.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any


# ---------------------------------------------------------------------------
# Canonical security controls
# ---------------------------------------------------------------------------
#
# Different frameworks may express the same underlying security requirement
# using different rule IDs. We normalize them here before generating CLI.
#
CANONICAL_CONTROLS = {
    "AAA_AUTHENTICATION": {
        "title": "AAA authentication must be enabled",
        "description": (
            "Enable AAA authentication for centralized authentication "
            "and authorization."
        ),
    },
    "LOG_TIMESTAMPS": {
        "title": "Log timestamps must be enabled",
        "description": (
            "Enable timestamps for log event correlation and "
            "security event investigation."
        ),
    },
    "SSH": {
        "title": "SSH must be enabled",
        "description": (
            "Enable secure SSH-based remote administration."
        ),
    },
    "TELNET_DISABLED": {
        "title": "Telnet must be disabled",
        "description": (
            "Disable unencrypted Telnet remote administration."
        ),
    },
    "ENABLE_SECRET": {
        "title": "Enable secret must be configured",
        "description": (
            "Configure a strong encrypted enable secret."
        ),
    },
    "LOCAL_LOGGING": {
        "title": "Local buffered logging must be enabled",
        "description": (
            "Enable local buffered logging for security event retention."
        ),
    },
    "REMOTE_SYSLOG": {
        "title": "Remote syslog logging must be configured",
        "description": (
            "Configure remote syslog logging so security-relevant "
            "events can be forwarded to a centralized logging system."
        ),
    },
    "PASSWORD_ENCRYPTION": {
        "title": "Password encryption must be enabled",
        "description": (
            "Enable password encryption for supported locally stored "
            "credentials."
        ),
    },
}


# ---------------------------------------------------------------------------
# Framework rule -> canonical control
# ---------------------------------------------------------------------------
#
# This is the important part of the fix.
#
# Example:
#   CIS-AAA-001
#   NIST-IA-002
#   STIG-NET-001
#   ISO-A.5.15
#
# all currently evaluate the same baseline parameter:
#
#   authentication.aaa_new_model
#
# Therefore they should produce the same vendor-specific remediation.
#
RULE_TO_CONTROL = {
    # ---------------- CIS ----------------
    "CIS-AAA-001": "AAA_AUTHENTICATION",
    "CIS-AUTH-001": "ENABLE_SECRET",
    "CIS-SSH-001": "SSH",
    "CIS-TELNET-001": "TELNET_DISABLED",
    "CIS-LOG-001": "LOCAL_LOGGING",
    "CIS-LOG-002": "LOG_TIMESTAMPS",
    "CIS-LOG-003": "REMOTE_SYSLOG",
    "CIS-CRYPTO-001": "PASSWORD_ENCRYPTION",
    "CIS-MON-001": "LOCAL_LOGGING",

    # ---------------- NIST ----------------
    "NIST-IA-002": "AAA_AUTHENTICATION",
    "NIST-AU-002": "LOCAL_LOGGING",
    "NIST-SC-008": "SSH",

    # ---------------- DISA STIG ----------------
    "STIG-NET-001": "AAA_AUTHENTICATION",
    "STIG-NET-002": "SSH",
    "STIG-NET-003": "TELNET_DISABLED",
    "STIG-NET-004": "LOCAL_LOGGING",

    # ---------------- ISO/IEC 27001 ----------------
    "ISO-A.5.15": "AAA_AUTHENTICATION",
    "ISO-A.8.15": "LOCAL_LOGGING",
    "ISO-A.8.20": "SSH",
    "ISO-A.8.5": "TELNET_DISABLED",
}


# ---------------------------------------------------------------------------
# Vendor-specific remediation
# ---------------------------------------------------------------------------
#
# Each command is represented as a list so a future remediation can contain
# multiple CLI commands.
#
VENDOR_REMEDIATIONS = {
    "CISCO": {
        "AAA_AUTHENTICATION": {
            "commands": [
                "aaa new-model",
            ],
            "explanation": (
                "Enable AAA authentication for centralized authentication "
                "and authorization."
            ),
        },
        "ENABLE_SECRET": {
            "commands": [
                "enable secret <STRONG_SECRET>",
            ],
            "explanation": (
                "Configure a strong enable secret. Replace "
                "<STRONG_SECRET> with an approved secret."
            ),
        },
        "SSH": {
            "commands": [
                "ip ssh version 2",
                "line vty 0 4",
                "transport input ssh",
            ],
            "explanation": (
                "Use SSH version 2 for secure remote administration "
                "and prevent insecure remote access protocols."
            ),
        },
        "TELNET_DISABLED": {
            "commands": [
                "line vty 0 4",
                "transport input ssh",
            ],
            "explanation": (
                "Restrict VTY lines to SSH so Telnet is not accepted "
                "for remote administration."
            ),
        },
        "LOCAL_LOGGING": {
            "commands": [
                "logging buffered 16384",
            ],
            "explanation": (
                "Enable local buffered logging so security events "
                "are retained on the device."
            ),
        },
        "REMOTE_SYSLOG": {
            "commands": [
                "logging host <SYSLOG_SERVER_IP>",
            ],
            "explanation": (
                "Configure a centralized remote syslog destination. "
                "Replace <SYSLOG_SERVER_IP> with the approved syslog "
                "server address."
            ),
        },
        "LOG_TIMESTAMPS": {
            "commands": [
                "service timestamps log datetime msec",
            ],
            "explanation": (
                "Enable timestamps for log event correlation."
            ),
        },
        "PASSWORD_ENCRYPTION": {
            "commands": [
                "service password-encryption",
            ],
            "explanation": (
                "Enable supported password encryption for locally "
                "stored credentials."
            ),
        },
    },

    # -----------------------------------------------------------------------
    # Fortinet
    # -----------------------------------------------------------------------
    "FORTINET": {
        "AAA_AUTHENTICATION": {
            "commands": [
                "config system admin",
                "edit <ADMIN>",
                "set accprofile super_admin",
                "next",
                "end",
            ],
            "explanation": (
                "Configure centralized administrative authentication "
                "and an appropriate administrative access profile."
            ),
        },
        "SSH": {
            "commands": [
                "config system global",
                "set admin-ssh-port 22",
                "end",
            ],
            "explanation": (
                "Enable secure SSH-based administrative access."
            ),
        },
    },

    # -----------------------------------------------------------------------
    # Juniper
    # -----------------------------------------------------------------------
    "JUNIPER": {
        "AAA_AUTHENTICATION": {
            "commands": [
                "set system authentication-order [ password ]",
            ],
            "explanation": (
                "Configure an explicit authentication order for "
                "administrative access."
            ),
        },
        "SSH": {
            "commands": [
                "set system services ssh",
            ],
            "explanation": (
                "Enable SSH for secure remote administration."
            ),
        },
        "TELNET_DISABLED": {
            "commands": [
                "delete system services telnet",
            ],
            "explanation": (
                "Remove Telnet service to prevent unencrypted "
                "remote administration."
            ),
        },
    },

    # -----------------------------------------------------------------------
    # Arista EOS
    # -----------------------------------------------------------------------
    "ARISTA": {
        "AAA_AUTHENTICATION": {
            "commands": [
                "aaa new-model",
            ],
            "explanation": (
                "Enable AAA authentication for administrative access."
            ),
        },
        "SSH": {
            "commands": [
                "management ssh",
            ],
            "explanation": (
                "Enable secure SSH-based management."
            ),
        },
    },

    # -----------------------------------------------------------------------
    # Aruba
    # -----------------------------------------------------------------------
    "ARUBA": {
        "SSH": {
            "commands": [
                "ssh server vrf default",
            ],
            "explanation": (
                "Enable SSH-based secure management."
            ),
        },
    },

    # -----------------------------------------------------------------------
    # MikroTik
    # -----------------------------------------------------------------------
    "MIKROTIK": {
        "SSH": {
            "commands": [
                "/ip service enable ssh",
            ],
            "explanation": (
                "Enable SSH for secure administrative access."
            ),
        },
        "TELNET_DISABLED": {
            "commands": [
                "/ip service disable telnet",
            ],
            "explanation": (
                "Disable Telnet to prevent unencrypted management access."
            ),
        },
    },

    # -----------------------------------------------------------------------
    # Huawei
    # -----------------------------------------------------------------------
    "HUAWEI": {
        "SSH": {
            "commands": [
                "stelnet server enable",
            ],
            "explanation": (
                "Enable secure STelnet/SSH remote administration."
            ),
        },
    },

    # -----------------------------------------------------------------------
    # VyOS
    # -----------------------------------------------------------------------
    "VYOS": {
        "SSH": {
            "commands": [
                "set service ssh",
            ],
            "explanation": (
                "Enable SSH for secure remote administration."
            ),
        },
    },
}


# ---------------------------------------------------------------------------
# Vendor aliases
# ---------------------------------------------------------------------------

VENDOR_ALIASES = {
    "CISCO": "CISCO",
    "CISCO SYSTEMS": "CISCO",
    "FORTINET": "FORTINET",
    "FORTIGATE": "FORTINET",
    "JUNIPER": "JUNIPER",
    "JUNOS": "JUNIPER",
    "ARISTA": "ARISTA",
    "ARUBA": "ARUBA",
    "MIKROTIK": "MIKROTIK",
    "MIKROTIK ROUTEROS": "MIKROTIK",
    "HUAWEI": "HUAWEI",
    "VYOS": "VYOS",
}

# ---------------------------------------------------------------------------
# Remediation parameter handling
# ---------------------------------------------------------------------------

REMEDIATION_PARAMETER_PATTERNS = {
    "SYSLOG_SERVER_IP": re.compile(
        r"^[A-Za-z0-9.-]+$"
    ),
}


def validate_remediation_parameter(
    parameter: str,
    value: str,
) -> str:
    """
    Validate a remediation parameter before it is inserted into a CLI
    command.

    Currently supported:
      SYSLOG_SERVER_IP

    The returned value is normalized and safe to use as a single CLI
    argument.
    """

    parameter = str(parameter).strip().upper()
    value = str(value).strip()

    if not value:
        raise ValueError(
            f"Remediation parameter '{parameter}' cannot be empty."
        )

    if parameter == "SYSLOG_SERVER_IP":
        # Accept IPv4 and IPv6 addresses.
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            # Also permit a hostname/FQDN for environments where the
            # syslog destination is configured by DNS.
            if not REMEDIATION_PARAMETER_PATTERNS[
                "SYSLOG_SERVER_IP"
            ].fullmatch(value):
                raise ValueError(
                    "SYSLOG_SERVER_IP must be a valid IP address "
                    "or hostname."
                )

            return value

    raise ValueError(
        f"Unsupported remediation parameter: {parameter}"
    )


def render_remediation_command(
    command: str,
    parameters: dict[str, Any] | None = None,
) -> str:
    """
    Replace approved remediation placeholders with validated parameters.

    Example:

        logging host <SYSLOG_SERVER_IP>

    becomes:

        logging host 10.10.10.50
    """

    rendered = str(command).strip()

    if not rendered:
        raise ValueError("Remediation command cannot be empty.")

    parameters = parameters or {}

    placeholders = set(
        re.findall(r"<([A-Z0-9_]+)>", rendered)
    )

    for parameter in placeholders:
        if parameter not in parameters:
            raise ValueError(
                f"Missing required remediation parameter: {parameter}"
            )

        value = validate_remediation_parameter(
            parameter,
            str(parameters[parameter]),
        )

        rendered = rendered.replace(
            f"<{parameter}>",
            value,
        )

    # Never allow unresolved placeholders to reach execution.
    unresolved = re.findall(
        r"<([A-Z0-9_]+)>",
        rendered,
    )

    if unresolved:
        raise ValueError(
            "Remediation command contains unresolved "
            f"parameters: {', '.join(unresolved)}"
        )

    return rendered


def command_contains_unresolved_parameters(command: str) -> bool:
    """Return True if a command still contains <PARAMETER> placeholders."""

    return bool(
        re.search(
            r"<[A-Z0-9_]+>",
            str(command),
        )
    )


def validate_rendered_remediation_command(
    command: str,
    vendor: str,
    rule_id: str,
) -> bool:
    """
    Validate an already-rendered command against the canonical remediation.

    Supports:
      - exact canonical commands
      - safely rendered parameterized commands

    Example:

        logging host <SYSLOG_SERVER_IP>

    accepts:

        logging host 10.10.10.50

    but rejects:

        logging host <SYSLOG_SERVER_IP>
    """

    command = str(command).strip()

    if not command:
        raise ValueError(
            "Remediation command cannot be empty."
        )

    if command_contains_unresolved_parameters(command):
        raise ValueError(
            "Remediation command contains unresolved parameters."
        )

    vendor_name = _normalize_vendor(vendor)

    canonical_control = _get_canonical_control(rule_id)

    if canonical_control is None:
        raise ValueError(
            f"No canonical remediation mapping exists for rule '{rule_id}'."
        )

    remediation = _get_vendor_remediation(
        vendor_name,
        canonical_control,
    )

    if remediation is None:
        raise ValueError(
            f"No remediation exists for vendor '{vendor_name}' "
            f"and control '{canonical_control}'."
        )

    templates = [
        str(item).strip()
        for item in remediation.get("commands", [])
        if item
    ]

    for template in templates:

        # ---------------------------------------------------------
        # 1. Exact command match
        # ---------------------------------------------------------

        if template == command:
            return True

        # ---------------------------------------------------------
        # 2. Parameterized command match
        # ---------------------------------------------------------

        placeholders = re.findall(
            r"<([A-Z0-9_]+)>",
            template,
        )

        if not placeholders:
            continue

        # Split the template around placeholders and construct a
        # strict regular expression from the literal portions.
        parts = re.split(
            r"<([A-Z0-9_]+)>",
            template,
        )

        pattern_parts: list[str] = [
            "^"
        ]

        parameter_names: list[str] = []

        for index, part in enumerate(parts):

            if index % 2 == 0:
                # Literal command text.
                pattern_parts.append(
                    re.escape(part)
                )
            else:
                # Placeholder.
                parameter_names.append(part)

                if part == "SYSLOG_SERVER_IP":
                    pattern_parts.append(
                        r"([A-Za-z0-9.-]+)"
                    )
                else:
                    # Generic parameter fallback.
                    pattern_parts.append(
                        r"([^ \t]+)"
                    )

        pattern_parts.append("$")

        pattern = "".join(pattern_parts)

        match = re.fullmatch(
            pattern,
            command,
        )

        if not match:
            continue

        # ---------------------------------------------------------
        # 3. Validate extracted parameter values
        # ---------------------------------------------------------

        for parameter, value in zip(
            parameter_names,
            match.groups(),
        ):
            validate_remediation_parameter(
                parameter,
                value,
            )

        return True

    return False

def _normalize_vendor(vendor: str | None) -> str:
    """Normalize vendor names to internal vendor keys."""

    if not vendor:
        return "UNKNOWN"

    normalized = str(vendor).strip().upper()

    return VENDOR_ALIASES.get(normalized, normalized)


def _get_rule_id(compliance_result: dict[str, Any]) -> str | None:
    """Safely extract a rule ID from a compliance result."""

    rule_id = compliance_result.get("rule_id")

    if rule_id is None:
        return None

    return str(rule_id).strip()


def _get_canonical_control(rule_id: str | None) -> str | None:
    """Map a framework-specific rule ID to a canonical security control."""

    if not rule_id:
        return None

    return RULE_TO_CONTROL.get(rule_id)


def _get_vendor_remediation(
    vendor: str,
    canonical_control: str | None,
) -> dict[str, Any] | None:
    """Return remediation definition for a vendor/control pair."""

    if canonical_control is None:
        return None

    vendor_rules = VENDOR_REMEDIATIONS.get(vendor, {})

    return vendor_rules.get(canonical_control)


def _build_unavailable_item(
    compliance_result: dict[str, Any],
    canonical_control: str | None,
) -> dict[str, Any]:
    """Build a structured unavailable remediation item."""

    rule_id = _get_rule_id(compliance_result)

    control_info = CANONICAL_CONTROLS.get(
        canonical_control or "",
        {},
    )

    description = (
        compliance_result.get("title")
        or control_info.get("title")
        or "Remediation required"
    )

    return {
        "rule_id": rule_id,
        "framework": compliance_result.get("framework"),
        "canonical_control": canonical_control,
        "status": "UNAVAILABLE",
        "command": None,
        "commands": [],
        "parameters": [],
        "description": description,
        "explanation": (
            "Vendor-specific remediation is not yet available "
            "for this control."
        ),
        "approval_required": True,
    }


def _build_available_item(
    compliance_result: dict[str, Any],
    canonical_control: str,
    remediation: dict[str, Any],
) -> dict[str, Any]:
    """Build a structured available remediation item."""

    rule_id = _get_rule_id(compliance_result)

    commands = list(remediation.get("commands", []))
    parameters = sorted(
        set(
            re.findall(
                r"<([A-Z0-9_]+)>",
                " ".join(commands),
            )
        )
    )

    control_info = CANONICAL_CONTROLS.get(
        canonical_control,
        {},
    )

    description = (
        compliance_result.get("title")
        or control_info.get("title")
        or "Remediation required"
    )

    explanation = (
        remediation.get("explanation")
        or control_info.get("description")
        or "Apply the vendor-specific remediation."
    )

    return {
        "rule_id": rule_id,
        "framework": compliance_result.get("framework"),
        "canonical_control": canonical_control,
        "status": "AVAILABLE",
        "command": commands[0] if commands else None,
        "commands": commands,
        "parameters": parameters,
        "description": description,
        "explanation": explanation,
        "approval_required": True,
    }


def generate_remediation(
    compliance_result: list[dict[str, Any]] | dict[str, Any],
    vendor: str | None = None,
) -> dict[str, Any]:
    """
    Generate vendor-specific remediation for failed compliance controls.

    The function accepts either:
      - a list of compliance result dictionaries
      - a single compliance result dictionary

    Only FAILED controls receive remediation.

    Framework-specific rule IDs are normalized through RULE_TO_CONTROL,
    allowing equivalent CIS/NIST/STIG/ISO findings to use the same
    vendor-specific remediation.

    Duplicate commands are removed from the top-level command list while
    individual framework findings remain visible in `remediations`.
    """

    # Normalize input to a list.
    if isinstance(compliance_result, dict):
        # Multi-framework API may provide:
        # {"results": [compliance_result, ...]}
        if isinstance(compliance_result.get("results"), list):
            compliance_results = compliance_result["results"]
        else:
            compliance_results = [compliance_result]
    elif isinstance(compliance_result, list):
        compliance_results = compliance_result
    else:
        compliance_results = []

    original_vendor = vendor or "Unknown"
    vendor_name = _normalize_vendor(original_vendor)

    remediation_items: list[dict[str, Any]] = []

    # Track framework findings independently.
    processed_rule_ids: set[str] = set()

    for result in compliance_results:
        if not isinstance(result, dict):
            continue

        status = str(result.get("status", "")).upper()

        # Remediation is only required for failed controls.
        if status != "FAIL":
            continue

        rule_id = _get_rule_id(result)

        # Avoid processing the exact same rule twice.
        if rule_id and rule_id in processed_rule_ids:
            continue

        if rule_id:
            processed_rule_ids.add(rule_id)

        canonical_control = _get_canonical_control(rule_id)

        remediation = _get_vendor_remediation(
            vendor_name,
            canonical_control,
        )

        if remediation is None:
            remediation_items.append(
                _build_unavailable_item(
                    result,
                    canonical_control,
                )
            )
            continue

        if canonical_control is None:
            remediation_items.append(
                _build_unavailable_item(
                    result,
                    canonical_control,
                )
            )
            continue

        remediation_items.append(
            _build_available_item(
                result,
                canonical_control,
                remediation,
            )
        )

    # -----------------------------------------------------------------------
    # Build unique top-level CLI command list.
    #
    # Multiple frameworks can identify the same underlying control.
    # We do NOT want:
    #
    # aaa new-model
    # aaa new-model
    # aaa new-model
    #
    # Instead, the dashboard receives one unique executable command while
    # still retaining every framework finding in `remediations`.
    # -----------------------------------------------------------------------

    unique_commands: list[str] = []
    seen_commands: set[str] = set()

    for item in remediation_items:
        for command in item.get("commands", []):
            if not command:
                continue

            normalized_command = str(command).strip()

            if not normalized_command:
                continue

            if normalized_command not in seen_commands:
                seen_commands.add(normalized_command)
                unique_commands.append(normalized_command)

    available_count = sum(
        1
        for item in remediation_items
        if item.get("status") == "AVAILABLE"
    )

    unavailable_count = sum(
        1
        for item in remediation_items
        if item.get("status") == "UNAVAILABLE"
    )

    return {
        "vendor": original_vendor,
        "total_remediations": len(remediation_items),

        # Number of framework findings for which a remediation was found.
        "available_remediations": available_count,

        # Number of failed framework findings for which no vendor-specific
        # remediation exists yet.
        "unavailable_remediations": unavailable_count,

        # Unique executable commands across all failed controls.
        "commands": unique_commands,

        # Detailed framework-level remediation records.
        "remediations": remediation_items,
    }