from __future__ import annotations

from app.services.configuration_parser import parse_configuration
from app.services.device_intelligence import analyze_device
from app.services.security_baseline import build_security_baseline
from app.services.framework_rules import get_framework_rules
from app.services.compliance_engine import evaluate_compliance
from app.services.risk_engine import calculate_risk
from app.services.remediation_engine import (
    generate_remediation,
    RULE_TO_CONTROL,
)

def _build_multi_framework_compliance(
    baseline: dict,
    frameworks: list[str],
) -> dict:
    """
    Evaluate the security baseline independently against
    each selected compliance framework.
    """

    framework_results = {}

    for framework in frameworks:
        rules = get_framework_rules(
            framework
        )

        framework_result = evaluate_compliance(
            baseline,
            rules,
        )

        framework_results[framework] = (
            framework_result
        )

    return framework_results

def _build_combined_compliance(
    framework_results: dict[str, dict],
) -> dict:
    """
    Combine individual framework results into one
    multi-framework compliance summary.

    The combined result preserves the same field names
    used by the single-framework compliance engine so
    the API has one consistent compliance schema.
    """

    all_results: list[dict] = []

    for framework_result in framework_results.values():
        all_results.extend(
            framework_result.get(
                "results",
                [],
            )
        )

    total = len(all_results)

    pass_count = sum(
        1
        for result in all_results
        if result.get("status") == "PASS"
    )

    fail_count = sum(
        1
        for result in all_results
        if result.get("status") == "FAIL"
    )

    na_count = sum(
        1
        for result in all_results
        if result.get("status") == "N/A"
    )

    applicable_count = pass_count + fail_count

    if applicable_count:
        compliance_percentage = round(
            (pass_count / applicable_count) * 100,
            2,
        )
    else:
        compliance_percentage = 0.0

    return {
        "framework": "MULTI",
        "frameworks": list(
            framework_results.keys()
        ),
        "total_rules": total,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "na_count": na_count,
        "compliance_percentage": compliance_percentage,
        "results": all_results,
    }


def _build_unique_risk_input(
    framework_results: dict[str, dict],
) -> dict:
    """
    Deduplicate failed framework rules by their canonical
    security control before calculating risk.

    Example:
    CIS AAA + NIST AAA + STIG AAA
    become one underlying AAA risk.
    """

    severity_rank = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    unique_failures: dict[str, dict] = {}

    for framework_result in framework_results.values():

        for result in framework_result.get(
            "results",
            [],
        ):

            if result.get("status") != "FAIL":
                continue

            control_key = (
                RULE_TO_CONTROL.get(
                    result.get("rule_id")
                )
                or result.get("baseline_path")
                or result.get("category")
                or result.get("rule_id")
            )

            existing = unique_failures.get(
                control_key
            )

            if existing is None:
                unique_failures[control_key] = result
                continue

            current_severity = severity_rank.get(
                str(
                    result.get(
                        "severity",
                        "LOW",
                    )
                ).upper(),
                1,
            )

            existing_severity = severity_rank.get(
                str(
                    existing.get(
                        "severity",
                        "LOW",
                    )
                ).upper(),
                1,
            )

            if current_severity > existing_severity:
                unique_failures[control_key] = result

    return {
        "framework": "MULTI-RISK",
        "results": list(
            unique_failures.values()
        ),
    }


def _build_multi_framework_remediation(
    framework_results: dict[str, dict],
    vendor: str,
) -> dict:
    """
    Generate remediation for failed rules across all
    selected frameworks.

    Remediation is deduplicated by canonical control,
    while framework-level findings remain available.
    """

    failed_results: list[dict] = []

    for framework_result in framework_results.values():
        failed_results.extend(
            result
            for result in framework_result.get(
                "results",
                [],
            )
            if result.get("status") == "FAIL"
        )

    return generate_remediation(
        failed_results,
        vendor,
    )


def analyze_configuration_content(
    content: str,
    frameworks: list[str],
) -> dict:
    """
    Run the complete configuration analysis pipeline.

    This function contains no HTTP or database logic so it
    can safely be reused by:

    - Single configuration analysis
    - Bulk analysis
    - Live scanning
    - Background jobs
    - Future scheduled scans
    """

    # ---------------------------------------------------------
    # 1. Parse configuration
    # ---------------------------------------------------------

    parsed = parse_configuration(
        content
    )

    device_intelligence = analyze_device(
        content
    )

    # ---------------------------------------------------------
    # 2. Build vendor-neutral Security Baseline Model
    # ---------------------------------------------------------

    baseline = build_security_baseline(
        parsed
    )

    # ---------------------------------------------------------
    # 3. Evaluate selected frameworks
    # ---------------------------------------------------------

    framework_results = (
        _build_multi_framework_compliance(
            baseline,
            frameworks,
        )
    )

    # ---------------------------------------------------------
    # 4. Preserve single-framework compatibility
    # ---------------------------------------------------------

    if len(frameworks) == 1:
        compliance = framework_results[
            frameworks[0]
        ]
    else:
        compliance = _build_combined_compliance(
            framework_results
        )

    # ---------------------------------------------------------
    # 5. Calculate risk using unique controls
    # ---------------------------------------------------------

    risk_input = _build_unique_risk_input(
        framework_results
    )

    risk = calculate_risk(
        risk_input
    )

    # ---------------------------------------------------------
    # 6. Generate remediation
    # ---------------------------------------------------------

    remediation = (
        _build_multi_framework_remediation(
            framework_results,
            parsed.get(
                "vendor",
                "Unknown",
            ),
        )
    )

    return {
        "device_intelligence": device_intelligence,
        "parser": parsed.get("parser"),
        "security_baseline": baseline,
        "compliance": compliance,
        "framework_results": framework_results,
        "selected_frameworks": frameworks,

        # AI / Human Training information
        "ai_ingestion": parsed.get(
            "ai_ingestion",
            {},
        ),
        "unknown_lines": parsed.get(
            "unknown_lines",
            [],
        ),

        "risk": risk,
        "remediation": remediation,
    }