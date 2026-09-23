from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ComplianceRule:
    rule_id: str
    framework: str
    title: str
    category: str
    severity: str
    description: str
    baseline_path: str
    expected_value: Any
    remediation_required: bool = True


# ============================================================
# INITIAL FRAMEWORK RULES
# ============================================================

FRAMEWORK_RULES: list[ComplianceRule] = [

    ComplianceRule(
        rule_id="CIS-AAA-001",
        framework="CIS",
        title="AAA authentication must be enabled",
        category="Authentication",
        severity="HIGH",
        description=(
            "Centralized AAA authentication should be enabled "
            "for network device management."
        ),
        baseline_path="authentication.aaa_new_model",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="CIS-AUTH-001",
        framework="CIS",
        title="Enable secret must be configured",
        category="Authentication",
        severity="HIGH",
        description=(
            "A secure enable secret should be configured "
            "for privileged access."
        ),
        baseline_path="management.enable_secret",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="CIS-SSH-001",
        framework="CIS",
        title="SSH must be enabled",
        category="Management",
        severity="HIGH",
        description=(
            "Secure remote management should use SSH."
        ),
        baseline_path="remote_access.ssh_enabled",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="CIS-TELNET-001",
        framework="CIS",
        title="Telnet must be disabled",
        category="Management",
        severity="CRITICAL",
        description=(
            "Unencrypted Telnet remote access should not "
            "be permitted."
        ),
        baseline_path="remote_access.telnet_enabled",
        expected_value=False,
    ),

    ComplianceRule(
        rule_id="CIS-LOG-001",
        framework="CIS",
        title="Local buffered logging must be enabled",
        category="Logging",
        severity="MEDIUM",
        description=(
            "Local buffered logging should be configured "
            "to retain security-relevant events."
        ),
        baseline_path="logging.local_buffered_logging",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="CIS-LOG-002",
        framework="CIS",
        title="Log timestamps must be enabled",
        category="Logging",
        severity="MEDIUM",
        description=(
            "Log timestamps should be enabled to support "
            "event correlation and investigation."
        ),
        baseline_path="logging.timestamps",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="CIS-LOG-003",
        framework="CIS",
        title="Remote syslog logging must be configured",
        category="Logging",
        severity="HIGH",
        description=(
            "Remote syslog logging should be configured "
            "to forward security-relevant events to a "
            "centralized logging system."
        ),
        baseline_path="logging.remote_syslog",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="CIS-CRYPTO-001",
        framework="CIS",
        title="Password encryption must be enabled",
        category="Cryptography",
        severity="MEDIUM",
        description=(
            "Password encryption should be enabled "
            "where supported by the platform."
        ),
        baseline_path="crypto.password_encryption",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="CIS-MON-001",
        framework="CIS",
        title="Security logging should be configured",
        category="Monitoring",
        severity="MEDIUM",
        description=(
            "At least one supported logging mechanism "
            "should be configured."
        ),
        baseline_path="monitoring.logging_configured",
        expected_value=True,
    ),

        ComplianceRule(
        rule_id="NIST-IA-002",
        framework="NIST",
        title="Identification and authentication mechanisms",
        category="Identification and Authentication",
        severity="HIGH",
        description="The device should provide an authentication mechanism for administrative access.",
        baseline_path="authentication.aaa_new_model",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="NIST-AU-002",
        framework="NIST",
        title="Audit events should be recorded",
        category="Audit and Accountability",
        severity="HIGH",
        description="The device should have security-relevant logging configured.",
        baseline_path="monitoring.logging_configured",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="NIST-SC-008",
        framework="NIST",
        title="Transmission confidentiality protection",
        category="System and Communications Protection",
        severity="HIGH",
        description="Secure remote administration should use SSH rather than unencrypted Telnet.",
        baseline_path="remote_access.ssh_enabled",
        expected_value=True,
    ),


        ComplianceRule(
        rule_id="STIG-NET-001",
        framework="DISA_STIG",
        title="Network device authentication",
        category="Authentication",
        severity="HIGH",
        description="The network device should use centralized or AAA-based authentication for administrative access.",
        baseline_path="authentication.aaa_new_model",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="STIG-NET-002",
        framework="DISA_STIG",
        title="Secure remote administration",
        category="Remote Access",
        severity="HIGH",
        description="Remote administrative access should use SSH.",
        baseline_path="remote_access.ssh_enabled",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="STIG-NET-003",
        framework="DISA_STIG",
        title="Unencrypted remote access disabled",
        category="Remote Access",
        severity="CRITICAL",
        description="Unencrypted Telnet remote access should be disabled.",
        baseline_path="remote_access.telnet_enabled",
        expected_value=False,
    ),

    ComplianceRule(
        rule_id="STIG-NET-004",
        framework="DISA_STIG",
        title="Audit logging configured",
        category="Audit and Accountability",
        severity="HIGH",
        description="Security-relevant device activity should be logged.",
        baseline_path="monitoring.logging_configured",
        expected_value=True,
    ),

        ComplianceRule(
        rule_id="ISO-A.5.15",
        framework="ISO_27001",
        title="Access control",
        category="Access Control",
        severity="HIGH",
        description="Administrative access should be protected through an authentication mechanism.",
        baseline_path="authentication.aaa_new_model",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="ISO-A.8.15",
        framework="ISO_27001",
        title="Logging",
        category="Logging and Monitoring",
        severity="HIGH",
        description="Security-relevant device activity should have logging configured.",
        baseline_path="monitoring.logging_configured",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="ISO-A.8.20",
        framework="ISO_27001",
        title="Network security",
        category="Network Security",
        severity="HIGH",
        description="Remote administrative access should use a secure communication protocol.",
        baseline_path="remote_access.ssh_enabled",
        expected_value=True,
    ),

    ComplianceRule(
        rule_id="ISO-A.8.5",
        framework="ISO_27001",
        title="Secure authentication",
        category="Authentication",
        severity="CRITICAL",
        description="Unencrypted Telnet remote administration should be disabled.",
        baseline_path="remote_access.telnet_enabled",
        expected_value=False,
    ),
]


def get_framework_rules(
    framework: str | None = None,
) -> list[ComplianceRule]:
    """
    Return rules for the requested security framework.

    Supported framework identifiers:
        CIS
        NIST
        DISA_STIG
        ISO_27001
        CUSTOM

    Frameworks without rules yet return an empty list.
    """

    if framework is None:
        return FRAMEWORK_RULES

    framework_name = framework.strip().upper()

    aliases = {
        "ISO/IEC 27001": "ISO_27001",
        "ISO 27001": "ISO_27001",
        "STIG": "DISA_STIG",
        "DISA STIG": "DISA_STIG",
    }

    framework_name = aliases.get(
        framework_name,
        framework_name,
    )

    supported_frameworks = {
        "CIS",
        "NIST",
        "DISA_STIG",
        "ISO_27001",
        "CUSTOM",
    }

    if framework_name not in supported_frameworks:
        raise ValueError(
            f"Unsupported framework: {framework}"
        )

    return [
        rule
        for rule in FRAMEWORK_RULES
        if rule.framework.upper() == framework_name
    ]