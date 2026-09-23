from __future__ import annotations

from datetime import datetime
from typing import Any


VALID_STATES = {
    "PENDING",
    "APPROVED",
    "REJECTED",
    "EXECUTED",
}


def create_approval_request(
    remediation: dict[str, Any],
    user_id: int,
) -> dict[str, Any]:
    """
    Create a human-approval request for one remediation.

    No network command is executed here.
    """

    if remediation.get("status") != "AVAILABLE":
        raise ValueError(
            "Only available remediations can be submitted "
            "for approval."
        )

    return {
        "rule_id": remediation.get("rule_id"),
        "command": remediation.get("command"),
        "vendor": remediation.get("vendor"),
        "state": "PENDING",
        "requested_by": user_id,
        "requested_at": datetime.utcnow().isoformat(),
        "approval_required": True,
    }


def approve_remediation(
    approval_request: dict[str, Any],
    approved_by: int,
) -> dict[str, Any]:
    """
    Approve a pending remediation.

    Approval only changes the state.
    It does not execute the command.
    """

    if approval_request.get("state") != "PENDING":
        raise ValueError(
            "Only pending remediation requests "
            "can be approved."
        )

    approval_request = approval_request.copy()

    approval_request["state"] = "APPROVED"
    approval_request["approved_by"] = approved_by
    approval_request["approved_at"] = (
        datetime.utcnow().isoformat()
    )

    return approval_request


def reject_remediation(
    approval_request: dict[str, Any],
    rejected_by: int,
) -> dict[str, Any]:
    """
    Reject a pending remediation.

    Rejection does not execute the command.
    """

    if approval_request.get("state") != "PENDING":
        raise ValueError(
            "Only pending remediation requests "
            "can be rejected."
        )

    approval_request = approval_request.copy()

    approval_request["state"] = "REJECTED"
    approval_request["rejected_by"] = rejected_by
    approval_request["rejected_at"] = (
        datetime.utcnow().isoformat()
    )

    return approval_request