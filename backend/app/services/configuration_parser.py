from __future__ import annotations

import re
from typing import Any

from app.services.vendor_detectors import detect_vendor
from app.services.ai_ingestion import (
    HIGH_CONFIDENCE_THRESHOLD,
    analyze_unknown_configuration,
)
from app.services.parser_registry import parser_registry
from app.services.vendor_parsers import register_builtin_parsers


def _empty_security_parameters() -> dict[str, Any]:
    """
    Return the vendor-neutral security baseline structure.

    Every vendor parser should populate this same structure.
    """
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


def _set_nested_security_parameter(
    security_parameters: dict[str, Any],
    parameter: str,
    value: Any,
) -> bool:
    """
    Set a vendor-neutral security parameter using a dotted path.

    Example:
        authentication.aaa_new_model
        logging.timestamps
        remote_access.ssh_enabled

    Returns True when the parameter was successfully applied.
    """

    parts = parameter.split(".")

    if len(parts) != 2:
        return False

    category, parameter_name = parts

    if category not in security_parameters:
        return False

    if not isinstance(
        security_parameters[category],
        dict,
    ):
        security_parameters[category] = {}

    security_parameters[category][parameter_name] = value

    return True


def _apply_ai_results_to_security_parameters(
    security_parameters: dict[str, Any],
    ai_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Apply trusted AI/NLP results to the vendor-neutral
    security parameter model.

    Rules:

    1. Administrator-approved learned mappings are trusted.
    2. HIGH-confidence semantic matches are automatically applied.
    3. MEDIUM/LOW confidence matches are NOT applied.
    4. Every applied mapping is returned with provenance.

    This is the bridge between AI ingestion and compliance.
    """

    applied_results: list[dict[str, Any]] = []

    for result in ai_results:

        if not result.get("matched"):
            continue

        parameter = result.get("parameter")

        if not parameter:
            continue

        source = result.get(
            "source",
            "semantic_nlp",
        )

        confidence = float(
            result.get(
                "confidence",
                0.0,
            )
        )

        # -----------------------------------------------------
        # Administrator-approved mappings are trusted.
        # -----------------------------------------------------

        is_learned_mapping = (
            source == "learned_mapping"
        )

        # -----------------------------------------------------
        # Automatic AI application is restricted to HIGH
        # confidence results.
        # -----------------------------------------------------

        is_high_confidence = (
            confidence >= HIGH_CONFIDENCE_THRESHOLD
        )

        if not (
            is_learned_mapping
            or is_high_confidence
        ):
            continue

        expected_value = result.get(
            "expected_value"
        )

        applied = _set_nested_security_parameter(
            security_parameters,
            parameter,
            expected_value,
        )

        if not applied:
            continue

        applied_results.append(
            {
                "configuration_line": result.get(
                    "configuration_line"
                ),
                "parameter": parameter,
                "category": result.get(
                    "category"
                ),
                "expected_value": expected_value,
                "confidence": confidence,
                "confidence_level": result.get(
                    "confidence_level",
                    "HIGH",
                ),
                "source": source,
                "evidence": result.get(
                    "evidence",
                    [],
                ),
                "learned_mapping_id": result.get(
                    "learned_mapping_id"
                ),
            }
        )

    return applied_results


def _extract_cisco_unknown_lines(
    configuration: str,
) -> list[str]:
    """
    Identify Cisco configuration lines that are not currently
    handled by the deterministic parser.

    The extractor is context-aware so that ordinary Cisco
    subcommands and sensitive configuration material do not
    become AI training candidates.

    Security-relevant parent commands remain available for
    AI/NLP semantic analysis.
    """

    known_patterns = [
        # ---------------------------------------------------------
        # Core configuration
        # ---------------------------------------------------------
        r"^\s*version\b",
        r"^\s*hostname\b",
        r"^\s*aaa\s+.*",
        r"^\s*enable\s+(?:secret|password)\b",
        r"^\s*username\b",

        # ---------------------------------------------------------
        # SSH / VTY / console / auxiliary
        # ---------------------------------------------------------
        r"^\s*ip\s+ssh\b",
        r"^\s*line\s+vty\b",
        r"^\s*line\s+(?:console|con)\b",
        r"^\s*line\s+aux(?:iliary)?\b",
        r"^\s*transport\s+input\b",
        r"^\s*login\b",
        r"^\s*stopbits\b",

        # ---------------------------------------------------------
        # Logging
        # ---------------------------------------------------------
        r"^\s*logging\s+buffered\b",
        r"^\s*logging\s+(?:host\s+)?\d{1,3}(?:\.\d{1,3}){3}\b",
        r"^\s*service\s+timestamps\s+log\b",

        # ---------------------------------------------------------
        # Encryption
        # ---------------------------------------------------------
        r"^\s*service\s+password-encryption\b",

        # ---------------------------------------------------------
        # ACLs
        # ---------------------------------------------------------
        r"^\s*access-list\b",
        r"^\s*ip\s+access-list\b",
        r"^\s*permit\b",
        r"^\s*deny\b",

        # ---------------------------------------------------------
        # Interfaces / switching
        # ---------------------------------------------------------
        r"^\s*interface\b",
        r"^\s*ip\s+address\b",
        r"^\s*shutdown\b",
        r"^\s*no\s+shutdown\b",
        r"^\s*description\b",
        r"^\s*switchport\b",
        r"^\s*spanning-tree\b",
        r"^\s*negotiation\s+auto$",

        # ---------------------------------------------------------
        # Routing
        # ---------------------------------------------------------
        r"^\s*router\s+ospf\b",
        r"^\s*router\s+bgp\b",
        r"^\s*router\s+eigrp\b",
        r"^\s*router\s+isis\b",
        r"^\s*ip\s+route\b",
        r"^\s*address-family\b",
        r"^\s*exit-address-family$",
        r"^\s*vrf\s+definition\b",

        # ---------------------------------------------------------
        # Management / monitoring
        # ---------------------------------------------------------
        r"^\s*snmp-server\b",
        r"^\s*ntp\b",

        # ---------------------------------------------------------
        # Cisco structural commands
        # ---------------------------------------------------------
        r"^\s*end$",
        r"^\s*exit$",
        r"^\s*control-plane\b",
        r"^\s*boot-start-marker$",
        r"^\s*boot-end-marker$",
        r"^\s*platform\b",
        r"^\s*subscriber\s+templating$",
        r"^\s*redundancy$",

        # ---------------------------------------------------------
        # Configuration-output metadata
        # ---------------------------------------------------------
        r"^\s*Current configuration\s*:",
        r"^\s*Building configuration\.*$",

        # ---------------------------------------------------------
        # Ordinary platform/configuration information
        # ---------------------------------------------------------
        r"^\s*license\s+udi\b",
        r"^\s*memory\s+free-low-watermark\b",
        r"^\s*memory\s+free\s+low-watermark\b",
        r"^\s*diagnostic\s+bootup\s+level\b",
        r"^\s*ip\s+default-gateway\b",
        r"^\s*ip\s+forward-protocol\b",
        r"^\s*ip\s+domain\s+name\b",
        r"^\s*no\s+ip\s+domain\s+lookup\b",
    ]

    # Known non-security subcommands that should not become
    # independent AI-training candidates when encountered inside
    # a relevant Cisco parent block.
    interface_subcommands = (
        "ip address",
        "no ip address",
        "shutdown",
        "no shutdown",
        "description",
        "negotiation auto",
        "switchport",
        "spanning-tree",
    )

    tacacs_subcommands = (
        "server name",
        "address ipv4",
        "address ipv6",
        "key ",
        "timeout ",
        "port ",
        "single-connection",
        "no single-connection",
    )

    pki_subcommands = (
        "certificate ",
        "enrollment ",
        "hash ",
        "rsakeypair ",
        "revocation-check ",
        "subject-name ",
        "quit",
    )

    # Parent contexts whose indented contents are implementation
    # details rather than standalone semantic candidates.
    context_parents = (
        "interface ",
        "line ",
        "tacacs server ",
        "crypto pki certificate ",
        "crypto pki trustpoint ",
        "certificate ca ",
        "certificate self-signed ",
        "vrf definition ",
    )

    unknown_lines: list[str] = []

    current_context: str | None = None
    in_certificate_block = False

    for raw_line in configuration.splitlines():
        if not raw_line.strip():
            continue

        stripped = raw_line.strip()
        lower_line = stripped.lower()

        # Preserve indentation because Cisco indentation carries
        # parent/subcommand context.
        indentation = len(raw_line) - len(raw_line.lstrip())

        # Cisco "!" terminates most configuration blocks.
        if stripped.startswith(("!", "#", "//")):
            current_context = None
            in_certificate_block = False
            continue

        # ---------------------------------------------------------
        # Certificate / PKI handling
        # ---------------------------------------------------------

        if (
            lower_line.startswith("crypto pki certificate")
            or lower_line.startswith("certificate ca ")
            or lower_line.startswith("certificate self-signed ")
        ):
            current_context = "pki"
            in_certificate_block = True
            continue

        if lower_line.startswith("crypto pki trustpoint "):
            current_context = "pki"
            in_certificate_block = False
            continue

        if in_certificate_block:
            continue

        # Obvious hexadecimal certificate/key payload.
        compact = stripped.replace(" ", "")

        if (
            len(compact) >= 16
            and len(compact) % 2 == 0
            and re.fullmatch(r"[0-9A-Fa-f]+", compact)
        ):
            continue

        # ---------------------------------------------------------
        # Parent-context detection
        # ---------------------------------------------------------

        parent_context = None

        for parent in context_parents:
            if lower_line.startswith(parent):
                parent_context = parent.rstrip()
                break

        if parent_context:
            current_context = parent_context

            # Parent commands themselves can still be meaningful.
            # PKI parents are intentionally suppressed above.
            if parent_context in {
                "interface",
                "line",
                "tacacs server",
                "vrf definition",
            }:
                if any(
                    re.search(
                        pattern,
                        stripped,
                        re.IGNORECASE,
                    )
                    for pattern in known_patterns
                ):
                    continue

                # Security-relevant parent commands are retained.
                if parent_context == "tacacs server":
                    unknown_lines.append(stripped)

                continue

        # ---------------------------------------------------------
        # Context-aware subcommands
        # ---------------------------------------------------------

        if indentation > 0 and current_context == "interface":
            if lower_line.startswith(interface_subcommands):
                continue

        if indentation > 0 and current_context == "tacacs server":
            if lower_line.startswith(tacacs_subcommands):
                continue

            # Any "key" line is sensitive credential material.
            if lower_line.startswith("key "):
                continue

        if indentation > 0 and current_context == "pki":
            if lower_line.startswith(pki_subcommands):
                continue

        # ---------------------------------------------------------
        # Global known syntax
        # ---------------------------------------------------------

        if any(
            re.search(
                pattern,
                stripped,
                re.IGNORECASE,
            )
            for pattern in known_patterns
        ):
            continue

        # ---------------------------------------------------------
        # Standalone sensitive key material
        # ---------------------------------------------------------

        if re.match(
            r"^\s*key\s+\d+\s+\S+",
            stripped,
            re.IGNORECASE,
        ):
            continue

        unknown_lines.append(stripped)

    return unknown_lines


def _build_ai_ingestion_result(
    ai_result: dict[str, Any],
    applied_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Build a consistent AI ingestion response while exposing
    which semantic results were actually trusted and applied.
    """

    return {
        "required": True,
        "status": "ANALYZED",
        "engine": ai_result["engine"],
        "total_lines": ai_result["total_lines"],
        "high_confidence_matches": ai_result[
            "high_confidence_matches"
        ],
        "training_required": ai_result[
            "training_required"
        ],
        "applied_count": len(applied_results),
        "applied_results": applied_results,
        "results": ai_result["results"],
    }


def parse_configuration(
    configuration: str,
) -> dict[str, Any]:
    """
    Parse a raw network configuration into a vendor-neutral
    intermediate representation.

    Vendor detection selects the appropriate parser from the
    parser registry.

    Unknown syntax is sent to AI/NLP ingestion.

    HIGH-confidence semantic matches and administrator-approved
    learned mappings are applied to the security parameter model.
    """

    configuration = configuration.lstrip("\ufeff")

    if not configuration or not configuration.strip():
        raise ValueError("Configuration cannot be empty")

    # Ensure built-in parsers have been registered.
    register_builtin_parsers()

    vendor_result = detect_vendor(configuration)

    vendor = vendor_result.get(
        "vendor",
        "Unknown",
    )

    result: dict[str, Any] = {
        "vendor": vendor,
        "vendor_confidence": vendor_result.get(
            "confidence",
            0.0,
        ),
        "vendor_evidence": vendor_result.get(
            "evidence",
            [],
        ),
        "configuration_length": len(configuration),
        "sections": [],
        "security_parameters": _empty_security_parameters(),
        "unknown_lines": [],
        "ai_ingestion": {
            "required": False,
            "status": "NOT_REQUIRED",
            "engine": None,
            "total_lines": 0,
            "high_confidence_matches": 0,
            "training_required": 0,
            "applied_count": 0,
            "applied_results": [],
            "results": [],
        },
    }

    # =========================================================
    # PARSER REGISTRY
    # =========================================================

    parser = parser_registry.get(vendor)

    if parser is not None:
        parser_result = parser(configuration)

        parser_metadata = parser_result.get(
            "parser",
            {},
        )

        if isinstance(parser_metadata, dict):
            result["parser"] = {
                "type": parser_metadata.get(
                    "type",
                    "vendor_specific",
                ),
                "name": parser_metadata.get(
                    "name"
                ),
                "status": parser_metadata.get(
                    "status",
                    "PARSED",
                ),
            }
        else:
            result["parser"] = {
                "type": "vendor_specific",
                "name": parser_metadata,
                "status": parser_result.get(
                    "status",
                    "PARSED",
                ),
            }

        result["security_parameters"] = (
            parser_result.get(
                "security_parameters",
                _empty_security_parameters(),
            )
        )

        # -----------------------------------------------------
        # Cisco-specific unsupported syntax detection
        # -----------------------------------------------------

        if vendor == "Cisco":
            unknown_lines = _extract_cisco_unknown_lines(
                configuration
            )

            result["unknown_lines"] = unknown_lines

            if unknown_lines:
                ai_result = analyze_unknown_configuration(
                    unknown_lines
                )

                applied_results = (
                    _apply_ai_results_to_security_parameters(
                        result["security_parameters"],
                        ai_result["results"],
                    )
                )

                result["ai_ingestion"] = (
                    _build_ai_ingestion_result(
                        ai_result,
                        applied_results,
                    )
                )

        return result

    # =========================================================
    # UNKNOWN VENDOR
    # =========================================================

    if vendor == "Unknown":
        unknown_lines = [
            line.strip()
            for line in configuration.splitlines()
            if line.strip()
            and not line.strip().startswith(
                ("!", "#", "//")
            )
        ]

        ai_result = analyze_unknown_configuration(
            unknown_lines
        )

        applied_results = (
            _apply_ai_results_to_security_parameters(
                result["security_parameters"],
                ai_result["results"],
            )
        )

        result["unknown_lines"] = unknown_lines

        result["parser"] = {
            "type": "ai_nlp",
            "name": "semantic_nlp",
            "status": "AI_ANALYZED",
        }

        result["ai_ingestion"] = (
            _build_ai_ingestion_result(
                ai_result,
                applied_results,
            )
        )

        return result

    # =========================================================
    # KNOWN VENDOR WITHOUT A PARSER
    # =========================================================

    result["parser"] = {
        "type": "vendor_specific",
        "name": None,
        "status": "NOT_IMPLEMENTED",
    }

    return result