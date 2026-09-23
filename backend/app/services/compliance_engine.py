from __future__ import annotations

from typing import Any

from app.services.framework_rules import ComplianceRule


def _get_nested_value(
    data: dict[str, Any],
    path: str,
) -> Any:
    """
    Read a nested value using a dot-separated path.

    Example:
        authentication.aaa_new_model
    """

    current: Any = data

    for key in path.split("."):
        if not isinstance(current, dict):
            return None

        if key not in current:
            return None

        current = current[key]

    return current


def evaluate_rule(
    baseline: dict[str, Any],
    rule: ComplianceRule,
) -> dict[str, Any]:
    """
    Evaluate one compliance rule against
    the normalized Security Baseline Model.
    """

    actual_value = _get_nested_value(
        baseline,
        rule.baseline_path,
    )

    if actual_value is None:
        status = "N/A"
        confidence = 0.0
    elif actual_value == rule.expected_value:
        status = "PASS"
        confidence = 1.0
    else:
        status = "FAIL"
        confidence = 1.0

    return {
        "rule_id": rule.rule_id,
        "framework": rule.framework,
        "title": rule.title,
        "category": rule.category,
        "severity": rule.severity,
        "description": rule.description,
        "baseline_path": rule.baseline_path,
        "expected_value": rule.expected_value,
        "actual_value": actual_value,
        "status": status,
        "confidence": confidence,
        "evidence": (
            f"{rule.baseline_path} = {actual_value!r}; "
            f"expected {rule.expected_value!r}"
        ),
        "remediation_required": (
            status == "FAIL"
            and rule.remediation_required
    ),
    }


def evaluate_compliance(
    baseline: dict[str, Any],
    rules: list[ComplianceRule],
) -> dict[str, Any]:
    """
    Evaluate all supplied compliance rules and
    generate an overall compliance summary.
    """

    results = [
        evaluate_rule(baseline, rule)
        for rule in rules
    ]

    pass_count = sum(
        1
        for result in results
        if result["status"] == "PASS"
    )

    fail_count = sum(
        1
        for result in results
        if result["status"] == "FAIL"
    )

    na_count = sum(
        1
        for result in results
        if result["status"] == "N/A"
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
        "framework": (
            rules[0].framework
            if rules
            else None
        ),
        "total_rules": len(rules),
        "pass_count": pass_count,
        "fail_count": fail_count,
        "na_count": na_count,
        "compliance_percentage": (
            compliance_percentage
        ),
        "results": results,
    }