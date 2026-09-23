from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.db.database import SessionLocal
from app.models import Configuration, Device, RemediationRequest, User
from app.services.analysis_service import analyze_configuration_content
from app.services.audit_service import create_audit_log
from app.services.permission_dependency import require_permission
from app.services.remediation_approval import (
    approve_remediation,
    create_approval_request,
    reject_remediation,
)
from app.services.remediation_engine import (
    generate_remediation,
    render_remediation_command,
    validate_rendered_remediation_command,
)
from app.services.remediation_executor import execute_remediation
from app.services.remediation_verification import verify_remediation
from app.services.ssh_scanner import scan_ssh_device

router = APIRouter(
    prefix="/remediation",
    tags=["Remediation"],
    )


class RemediationRequestCreate(BaseModel):
    configuration_id: int | None = None
    device_id: int | None = None

    rule_id: str = Field(min_length=1, max_length=100)
    control: str | None = Field(default=None, max_length=100)
    vendor: str = Field(min_length=1, max_length=100)

    command: str = Field(min_length=1)
    explanation: str | None = None

    remediation: dict[str, Any]

    parameters: dict[str, str] | None = None

class RemediationExecuteRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    secret: str | None = None
    dry_run: bool = True

class RemediationVerifyRequest(BaseModel):
    before_configuration_id: int | None = None
    after_configuration_id: int | None = None


def _get_owned_remediation_request(
    db,
    request_id: int,
    current_user: User,
):
    """
    Load a remediation request only when all referenced resources
    belong to the current user's account.

    Ownership rules:
    - configuration_id -> configuration must belong to current user
    - device_id -> device must belong to current user
    - if neither resource exists -> requested_by must match current user
    """

    request = db.scalar(
        select(RemediationRequest).where(
            RemediationRequest.id == request_id
        )
    )

    if not request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation request not found.",
        )

    if request.configuration_id is not None:
        configuration = db.scalar(
            select(Configuration).where(
                Configuration.id == request.configuration_id,
                Configuration.uploaded_by == current_user.id,
            )
        )

        if not configuration:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Remediation request not found.",
            )

    if request.device_id is not None:
        device = db.scalar(
            select(Device).where(
                Device.id == request.device_id,
                Device.owner_id == current_user.id,
            )
        )

        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Remediation request not found.",
            )

    if (
        request.configuration_id is None
        and request.device_id is None
        and request.requested_by != current_user.id
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation request not found.",
        )

    return request

@router.post("/requests/{request_id}/verify")
def verify_remediation_request(
    request_id: int,
    verification_data: RemediationVerifyRequest,
    current_user: User = Depends(
        require_permission("remediation.view")
    ),
):
    """Explicitly verify an executed remediation against before/after configurations."""
    db = SessionLocal()

    try:
        request = _get_owned_remediation_request(
            db,
            request_id,
            current_user,
        )

        if not request:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Remediation request not found.",
            )

        if request.state != "EXECUTED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Only EXECUTED remediation requests can be verified. "
                    f"Current state: {request.state}"
                ),
            )

        before_configuration_id = (
            verification_data.before_configuration_id
            or request.configuration_id
        )

        if not before_configuration_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "No before configuration is available for verification."
                ),
            )

        # If the caller does not provide an after_configuration_id, use the
        # configuration persisted by the automatic post-execution scan.
        after_configuration_id = verification_data.after_configuration_id

        if not after_configuration_id and isinstance(
            request.verification_result, dict
        ):
            saved_after_id = request.verification_result.get(
                "after_configuration_id"
            )
            if saved_after_id is not None:
                after_configuration_id = int(saved_after_id)

        if not after_configuration_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "after_configuration_id is required unless the remediation "
                    "execution already persisted a post-execution scan."
                ),
            )

        before_configuration = db.scalar(
            select(Configuration).where(
                Configuration.id == before_configuration_id,
                Configuration.uploaded_by == current_user.id,
            )
        )

        after_configuration = db.scalar(
            select(Configuration).where(
                Configuration.id == after_configuration_id,
                Configuration.uploaded_by == current_user.id,
            )
        )

        if not before_configuration:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Before configuration not found.",
            )

        if not after_configuration:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="After configuration not found.",
            )

        framework = _framework_for_rule(request.rule_id)

        before_analysis = analyze_configuration_content(
            before_configuration.content,
            [framework],
        )
        after_analysis = analyze_configuration_content(
            after_configuration.content,
            [framework],
        )

        verification = verify_remediation(
            before_analysis["compliance"],
            after_analysis["compliance"],
            requested_rule_id=request.rule_id,
        )

        verification["before_configuration_id"] = before_configuration_id
        verification["after_configuration_id"] = after_configuration_id

        request.verification_result = verification
        request.execution_status = (
            "VERIFIED"
            if verification.get("verified")
            else "EXECUTED_UNVERIFIED"
        )

        db.commit()
        db.refresh(request)

        create_audit_log(
            db=db,
            action=(
                "REMEDIATION_VERIFIED"
                if verification.get("verified")
                else "REMEDIATION_VERIFICATION_FAILED"
            ),
            status=(
                "SUCCESS"
                if verification.get("verified")
                else "WARNING"
            ),
            user=current_user,
            resource_type="remediation_request",
            resource_id=str(request.id),
            details={
                "rule_id": request.rule_id,
                "vendor": request.vendor,
                "before_configuration_id": before_configuration_id,
                "after_configuration_id": after_configuration_id,
                "verified": verification.get("verified"),
            },
        )

        return {
            "id": request.id,
            "rule_id": request.rule_id,
            "vendor": request.vendor,
            "state": request.state,
            "execution_status": request.execution_status,
            "verification": request.verification_result,
        }

    finally:
        db.close()

@router.get("/requests")
def list_remediation_requests(
    current_user: User = Depends(
        require_permission("remediation.view")
    ),
):
    db = SessionLocal()

    try:
        requests = db.scalars(
            select(RemediationRequest)
            .outerjoin(
                Configuration,
                Configuration.id == RemediationRequest.configuration_id,
            )
            .outerjoin(
                Device,
                Device.id == RemediationRequest.device_id,
            )
            .where(
                (
                    RemediationRequest.configuration_id.is_(None)
                    | (Configuration.uploaded_by == current_user.id)
                )
                & (
                    RemediationRequest.device_id.is_(None)
                    | (Device.owner_id == current_user.id)
                )
                & (
                    RemediationRequest.configuration_id.is_not(None)
                    | RemediationRequest.device_id.is_not(None)
                    | (RemediationRequest.requested_by == current_user.id)
                )
            )
            .order_by(RemediationRequest.id.desc())
        ).all()

        return [
            {
                "id": request.id,
                "configuration_id": request.configuration_id,
                "device_id": request.device_id,
                "rule_id": request.rule_id,
                "control": request.control,
                "vendor": request.vendor,
                "command": request.command,
                "parameters": request.parameters,
                "explanation": request.explanation,
                "state": request.state,
                "requested_by": request.requested_by,
                "requested_at": request.requested_at,
                "approved_by": request.approved_by,
                "approved_at": request.approved_at,
                "rejected_by": request.rejected_by,
                "rejected_at": request.rejected_at,
                "executed_by": request.executed_by,
                "executed_at": request.executed_at,
                "execution_status": request.execution_status,
                "verification_result": request.verification_result,
            }
            for request in requests
        ]

    finally:
        db.close()

@router.get("/requests/{request_id}")
def get_remediation_request(
    request_id: int,
    current_user: User = Depends(
        require_permission("remediation.view")
    ),
):
    db = SessionLocal()

    try:
        request = _get_owned_remediation_request(
            db,
            request_id,
            current_user,
        )

        if not request:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Remediation request not found.",
            )

        return {
            "id": request.id,
            "configuration_id": request.configuration_id,
            "device_id": request.device_id,
            "rule_id": request.rule_id,
            "control": request.control,
            "vendor": request.vendor,
            "command": request.command,
            "parameters": request.parameters,
            "explanation": request.explanation,
            "state": request.state,
            "requested_by": request.requested_by,
            "requested_at": request.requested_at,
            "approved_by": request.approved_by,
            "approved_at": request.approved_at,
            "rejected_by": request.rejected_by,
            "rejected_at": request.rejected_at,
            "executed_by": request.executed_by,
            "executed_at": request.executed_at,
            "execution_status": request.execution_status,
            "execution_output": request.execution_output,
            "verification_result": request.verification_result,
        }

    finally:
        db.close()

@router.post(
    "/requests",
    status_code=status.HTTP_201_CREATED,
)
def create_remediation_request(
    request_data: RemediationRequestCreate,
    current_user: User = Depends(
        require_permission("remediation.view")
    ),
):
    db = SessionLocal()

    try:
        remediation = request_data.remediation

        # ---------------------------------------------------------
        # Validate account ownership of referenced resources
        # ---------------------------------------------------------

        if request_data.configuration_id is not None:
            configuration = db.scalar(
                select(Configuration).where(
                    Configuration.id == request_data.configuration_id,
                    Configuration.uploaded_by == current_user.id,
                )
            )

            if not configuration:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Configuration not found.",
                )

        if request_data.device_id is not None:
            device = db.scalar(
                select(Device).where(
                    Device.id == request_data.device_id,
                    Device.owner_id == current_user.id,
                )
            )

            if not device:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Device not found.",
                )

        # ---------------------------------------------------------
        # Render and validate parameterized commands
        # ---------------------------------------------------------

        try:
            rendered_command = render_remediation_command(
                request_data.command,
                request_data.parameters,
            )

            if request_data.parameters:
                validate_rendered_remediation_command(
                    rendered_command,
                    request_data.vendor,
                    request_data.rule_id,
                )

        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

        try:
            approval_request = create_approval_request(
                remediation=remediation,
                user_id=current_user.id,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

        request = RemediationRequest(
            configuration_id=request_data.configuration_id,
            device_id=request_data.device_id,
            rule_id=request_data.rule_id,
            control=request_data.control,
            vendor=request_data.vendor,
            command=rendered_command,
            parameters=request_data.parameters,
            explanation=request_data.explanation,
            state=approval_request["state"],
            requested_by=current_user.id,
            requested_at=datetime.utcnow(),
        )

        db.add(request)
        db.commit()
        db.refresh(request)

        create_audit_log(
            db=db,
            action="REMEDIATION_REQUEST_CREATED",
            status="SUCCESS",
            user=current_user,
            resource_type="remediation_request",
            resource_id=str(request.id),
            details={
                "configuration_id": request.configuration_id,
                "device_id": request.device_id,
                "rule_id": request.rule_id,
                "vendor": request.vendor,
                "state": request.state,
            },
        )

        return {
            "id": request.id,
            "configuration_id": request.configuration_id,
            "device_id": request.device_id,
            "rule_id": request.rule_id,
            "control": request.control,
            "vendor": request.vendor,
            "command": rendered_command,
            "parameters": request.parameters,
            "explanation": request.explanation,
            "state": request.state,
            "requested_by": request.requested_by,
            "requested_at": request.requested_at,
            "approval_required": True,
        }

    finally:
        db.close()

@router.post("/requests/{request_id}/approve")
def approve_remediation_request(
    request_id: int,
    current_user: User = Depends(
        require_permission("remediation.approve")
    ),
):
    db = SessionLocal()

    try:
        request = _get_owned_remediation_request(
            db,
            request_id,
            current_user,
        )

        if not request:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Remediation request not found.",
            )

        if request.state != "PENDING":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Only PENDING remediation requests can be "
                    f"approved. Current state: {request.state}"
                ),
            )

        approval_request = {
            "state": request.state,
            "rule_id": request.rule_id,
            "command": request.command,
            "vendor": request.vendor,
        }

        try:
            approved = approve_remediation(
                approval_request=approval_request,
                approved_by=current_user.id,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

        request.state = approved["state"]
        request.approved_by = approved["approved_by"]
        request.approved_at = datetime.fromisoformat(
            approved["approved_at"]
        )

        db.commit()
        db.refresh(request)

        create_audit_log(
            db=db,
            action="REMEDIATION_APPROVED",
            status="SUCCESS",
            user=current_user,
            resource_type="remediation_request",
            resource_id=str(request.id),
            details={
                "rule_id": request.rule_id,
                "vendor": request.vendor,
                "configuration_id": request.configuration_id,
                "device_id": request.device_id,
                "state": request.state,
            },
        )

        return {
            "id": request.id,
            "rule_id": request.rule_id,
            "vendor": request.vendor,
            "command": request.command,
            "state": request.state,
            "requested_by": request.requested_by,
            "approved_by": request.approved_by,
            "approved_at": request.approved_at,
            "execution_allowed": True,
        }

    finally:
        db.close()


@router.post("/requests/{request_id}/reject")
def reject_remediation_request(
    request_id: int,
    current_user: User = Depends(
        require_permission("remediation.approve")
    ),
):
    db = SessionLocal()

    try:
        request = _get_owned_remediation_request(
            db,
            request_id,
            current_user,
        )

        if not request:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Remediation request not found.",
            )

        if request.state != "PENDING":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Only PENDING remediation requests can be "
                    f"rejected. Current state: {request.state}"
                ),
            )

        approval_request = {
            "state": request.state,
            "rule_id": request.rule_id,
            "command": request.command,
            "vendor": request.vendor,
        }

        try:
            rejected = reject_remediation(
                approval_request=approval_request,
                rejected_by=current_user.id,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

        request.state = rejected["state"]
        request.rejected_by = rejected["rejected_by"]
        request.rejected_at = datetime.fromisoformat(
            rejected["rejected_at"]
        )

        db.commit()
        db.refresh(request)

        create_audit_log(
            db=db,
            action="REMEDIATION_REJECTED",
            status="SUCCESS",
            user=current_user,
            resource_type="remediation_request",
            resource_id=str(request.id),
            details={
                "rule_id": request.rule_id,
                "vendor": request.vendor,
                "configuration_id": request.configuration_id,
                "device_id": request.device_id,
                "state": request.state,
            },
        )

        return {
            "id": request.id,
            "rule_id": request.rule_id,
            "vendor": request.vendor,
            "command": request.command,
            "state": request.state,
            "requested_by": request.requested_by,
            "rejected_by": request.rejected_by,
            "rejected_at": request.rejected_at,
            "execution_allowed": False,
        }

    finally:
        db.close()

def _framework_for_rule(rule_id: str) -> str:
    if rule_id.startswith("CIS-"):
        return "CIS"

    if rule_id.startswith("NIST-"):
        return "NIST"

    if rule_id.startswith("STIG-"):
        return "DISA_STIG"

    if rule_id.startswith("ISO-"):
        return "ISO_27001"

    return "CIS"

@router.post("/requests/{request_id}/execute")
def execute_remediation_request(
    request_id: int,
    execution_data: RemediationExecuteRequest,
    current_user: User = Depends(
        require_permission("remediation.execute")
    ),
):
    db = SessionLocal()

    try:
        # ---------------------------------------------------------
        # 1. Load remediation request
        # ---------------------------------------------------------

        request = _get_owned_remediation_request(
            db,
            request_id,
            current_user,
        )

        if not request:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Remediation request not found.",
            )

        if request.state != "APPROVED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Only APPROVED remediation requests can be "
                    f"executed. Current state: {request.state}"
                ),
            )

        if not request.device_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Remediation request is not associated with a device.",
            )

        # ---------------------------------------------------------
        # 2. Load target device
        # ---------------------------------------------------------

        device = db.scalar(
            select(Device).where(
                Device.id == request.device_id,
                Device.owner_id == current_user.id,
            )
        )

        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target device not found.",
            )

        # ---------------------------------------------------------
        # 3. Validate persisted command against canonical engine
        # ---------------------------------------------------------

        generated = generate_remediation(
            {
                "rule_id": request.rule_id,
                "status": "FAIL",
            },
            vendor=request.vendor,
        )

        approved_command = request.command.strip()

        # ---------------------------------------------------------
        # Never execute unresolved placeholders.
        # ---------------------------------------------------------

        if "<" in approved_command or ">" in approved_command:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Remediation command contains unresolved "
                    "parameters and cannot be executed."
                ),
            )

        # ---------------------------------------------------------
        # Validate command against canonical remediation definition.
        # Supports both exact commands and safely rendered
        # parameterized commands.
        # ---------------------------------------------------------

        try:
            command_is_valid = validate_rendered_remediation_command(
                approved_command,
                request.vendor,
                request.rule_id,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

        if not command_is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "The approved command is not valid for the "
                    "canonical remediation definition."
                ),
            )

        # ---------------------------------------------------------
        # 4. Dry run
        # ---------------------------------------------------------

        result = execute_remediation(
            device=device,
            command=approved_command,
            username=execution_data.username,
            password=execution_data.password,
            port=execution_data.port,
            secret=execution_data.secret,
            dry_run=execution_data.dry_run,
        )

        if execution_data.dry_run:
            create_audit_log(
                db=db,
                action="REMEDIATION_DRY_RUN",
                status="SUCCESS",
                user=current_user,
                resource_type="remediation_request",
                resource_id=str(request.id),
                details={
                    "device_id": device.id,
                    "hostname": device.hostname,
                    "rule_id": request.rule_id,
                    "vendor": request.vendor,
                    "command": approved_command,
                },
            )

            return {
                "id": request.id,
                "state": request.state,
                "execution_status": "DRY_RUN",
                "result": result,
            }

        # ---------------------------------------------------------
        # 5. Real execution failed
        # ---------------------------------------------------------

        if not result["success"]:
            request.executed_by = current_user.id
            request.executed_at = datetime.utcnow()
            request.execution_status = "FAILED"
            request.execution_output = result.get(
                "error",
                "Remediation execution failed.",
            )

            db.commit()
            db.refresh(request)

            create_audit_log(
                db=db,
                action="REMEDIATION_EXECUTION_FAILED",
                status="FAILED",
                user=current_user,
                resource_type="remediation_request",
                resource_id=str(request.id),
                details={
                    "device_id": device.id,
                    "hostname": device.hostname,
                    "rule_id": request.rule_id,
                    "vendor": request.vendor,
                    "command": approved_command,
                    "error": result.get("error"),
                },
            )

            return {
                "id": request.id,
                "state": request.state,
                "execution_status": request.execution_status,
                "error": request.execution_output,
            }

        # ---------------------------------------------------------
        # 6. Real execution succeeded
        # ---------------------------------------------------------

        request.executed_by = current_user.id
        request.executed_at = datetime.utcnow()
        request.state = "EXECUTED"
        request.execution_output = result.get("output", "")

        # ---------------------------------------------------------
        # 7. Load BEFORE configuration
        # ---------------------------------------------------------

        before_analysis = None

        before_configuration = None

        if request.configuration_id:
            before_configuration = db.scalar(
                select(Configuration).where(
                    Configuration.id == request.configuration_id,
                    Configuration.uploaded_by == current_user.id,
                )
            )

        if before_configuration:
            framework = _framework_for_rule(
                request.rule_id
            )

            before_analysis = analyze_configuration_content(
                before_configuration.content,
                [framework],
            )

        # ---------------------------------------------------------
        # 8. Obtain fresh AFTER configuration
        # ---------------------------------------------------------

        scan_result = scan_ssh_device(
            host=device.management_ip,
            username=execution_data.username,
            password=execution_data.password,
            device_type=(
                result.get("device_type")
                or device.device_type
                or "cisco_ios"
            ),
            port=execution_data.port,
            secret=execution_data.secret,
        )

        if not scan_result["success"]:
            request.execution_status = "EXECUTED_UNVERIFIED"
            request.verification_result = {
                "verified": False,
                "reason": "Post-execution scan failed.",
                "scan_error": scan_result.get("error"),
            }

            db.commit()
            db.refresh(request)

            create_audit_log(
                db=db,
                action="REMEDIATION_EXECUTED_UNVERIFIED",
                status="WARNING",
                user=current_user,
                resource_type="remediation_request",
                resource_id=str(request.id),
                details={
                    "device_id": device.id,
                    "rule_id": request.rule_id,
                    "command": approved_command,
                    "reason": "Post-execution scan failed.",
                    "error": scan_result.get("error"),
                },
            )

            return {
                "id": request.id,
                "state": request.state,
                "execution_status": request.execution_status,
                "output": request.execution_output,
                "verification": request.verification_result,
            }

        # ---------------------------------------------------------
        # 9. Persist AFTER configuration
        # ---------------------------------------------------------

        after_configuration = Configuration(
            original_filename=(
                f"{device.hostname}_remediation_{request.id}_after.cfg"
            ),
            file_extension=".cfg",
            file_size=len(
                scan_result["configuration"].encode("utf-8")
            ),
            content=scan_result["configuration"],
            upload_status="REMEDIATION_VERIFY",
            uploaded_by=current_user.id,
        )

        db.add(after_configuration)
        db.flush()

        # ---------------------------------------------------------
        # 10. Analyze AFTER configuration
        # ---------------------------------------------------------

        framework = _framework_for_rule(
            request.rule_id
        )

        after_analysis = analyze_configuration_content(
            after_configuration.content,
            [framework],
        )

        # ---------------------------------------------------------
        # 10. Verify requested remediation
        # ---------------------------------------------------------

        if before_analysis:
            verification = verify_remediation(
                before_analysis["compliance"],
                after_analysis["compliance"],
                requested_rule_id=request.rule_id,
            )
        else:
            verification = {
                "verified": False,
                "reason": (
                    "Original configuration was unavailable; "
                    "post-execution verification could not compare "
                    "before and after states."
                ),
            }

        verification["before_configuration_id"] = request.configuration_id
        verification["after_configuration_id"] = after_configuration.id

        request.verification_result = verification

        if verification.get("verified"):
            request.execution_status = "VERIFIED"

            audit_action = "REMEDIATION_VERIFIED"
            audit_status = "SUCCESS"
        else:
            request.execution_status = "EXECUTED_UNVERIFIED"

            audit_action = "REMEDIATION_EXECUTED_UNVERIFIED"
            audit_status = "WARNING"

        db.commit()
        db.refresh(request)

        # ---------------------------------------------------------
        # 11. Audit final result
        # ---------------------------------------------------------

        create_audit_log(
            db=db,
            action=audit_action,
            status=audit_status,
            user=current_user,
            resource_type="remediation_request",
            resource_id=str(request.id),
            details={
                "device_id": device.id,
                "hostname": device.hostname,
                "rule_id": request.rule_id,
                "vendor": request.vendor,
                "command": approved_command,
                "execution_status": request.execution_status,
                "before_configuration_id": request.configuration_id,
                "after_configuration_id": after_configuration.id,
                "verified": verification.get("verified"),
            },
        )

        return {
            "id": request.id,
            "device_id": request.device_id,
            "rule_id": request.rule_id,
            "vendor": request.vendor,
            "command": request.command,
            "state": request.state,
            "execution_status": request.execution_status,
            "executed_by": request.executed_by,
            "executed_at": request.executed_at,
            "output": request.execution_output,
            "verification": request.verification_result,
        }

    finally:
        db.close()