from __future__ import annotations

from typing import Any


SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
}


def calculate_risk(
    compliance_results: dict[str, Any],
) -> dict[str, Any]:
    """
    Calculate an overall risk score from compliance findings.

    Only FAIL findings contribute to risk.
    """

    results = compliance_results.get(
        "results",
        [],
    )

    risk_points = 0
    critical_findings: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for result in results:

        if result.get("status") != "FAIL":
            continue

        severity = result.get(
            "severity",
            "LOW",
        ).upper()

        confidence = float(
            result.get(
                "confidence",
                0.0,
            )
        )

        severity_weight = SEVERITY_WEIGHTS.get(
            severity,
            SEVERITY_WEIGHTS["LOW"],
        )

        points = round(
            severity_weight * confidence,
            2,
        )

        finding = {
            "rule_id": result.get("rule_id"),
            "title": result.get("title"),
            "category": result.get("category"),
            "severity": severity,
            "confidence": confidence,
            "risk_points": points,
            "evidence": result.get(
                "evidence",
                "",
            ),
        }

        findings.append(finding)

        risk_points += points

        if severity == "CRITICAL":
            critical_findings.append(finding)

    # Normalize the score to 0–100.
    risk_score = min(
        round(risk_points, 2),
        100.0,
    )

    if risk_score >= 75:
        risk_level = "CRITICAL"
    elif risk_score >= 50:
        risk_level = "HIGH"
    elif risk_score >= 25:
        risk_level = "MEDIUM"
    elif risk_score > 0:
        risk_level = "LOW"
    else:
        risk_level = "MINIMAL"

    findings.sort(
        key=lambda item: item["risk_points"],
        reverse=True,
    )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_findings": len(findings),
        "critical_findings": len(
            critical_findings
        ),
        "findings": findings,
    }