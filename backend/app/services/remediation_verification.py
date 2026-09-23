from __future__ import annotations

from typing import Any


def verify_remediation(
    before_result: dict[str, Any],
    after_result: dict[str, Any],
    requested_rule_id: str | None = None,
) -> dict[str, Any]:
    """
    Compare compliance results before and after remediation.

    If requested_rule_id is supplied, only that rule is considered.
    A remediation is verified only when the requested rule changes
    from FAIL to PASS.

    This function does not execute network commands.
    """

    before_results = {
        result["rule_id"]: result
        for result in before_result.get("results", [])
        if result.get("rule_id")
    }

    after_results = {
        result["rule_id"]: result
        for result in after_result.get("results", [])
        if result.get("rule_id")
    }

    if requested_rule_id:
        rule_ids = [requested_rule_id]
    else:
        rule_ids = list(before_results.keys())

    verification: list[dict[str, Any]] = []

    for rule_id in rule_ids:
        before = before_results.get(rule_id)
        after = after_results.get(rule_id)

        if before is None:
            verification.append(
                {
                    "rule_id": rule_id,
                    "before_status": None,
                    "after_status": (
                        after.get("status")
                        if after
                        else None
                    ),
                    "verified": False,
                    "message": (
                        "Requested rule was not present in "
                        "the pre-remediation result."
                    ),
                }
            )
            continue

        if after is None:
            verification.append(
                {
                    "rule_id": rule_id,
                    "before_status": before.get("status"),
                    "after_status": None,
                    "verified": False,
                    "message": (
                        "Requested rule was not present in "
                        "the post-remediation result."
                    ),
                }
            )
            continue

        before_status = before.get("status")
        after_status = after.get("status")

        verified = (
            before_status == "FAIL"
            and after_status == "PASS"
        )

        verification.append(
            {
                "rule_id": rule_id,
                "before_status": before_status,
                "after_status": after_status,
                "verified": verified,
                "message": (
                    "Remediation verified"
                    if verified
                    else "Remediation not verified"
                ),
            }
        )

    verified_count = sum(
        1
        for item in verification
        if item["verified"]
    )

    failed_count = sum(
        1
        for item in verification
        if not item["verified"]
    )

    return {
        "verified": (
            len(verification) > 0
            and failed_count == 0
        ),
        "total_rules_checked": len(verification),
        "verified_count": verified_count,
        "failed_count": failed_count,
        "results": verification,
    }