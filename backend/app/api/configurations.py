from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import func, select, update

from app.db.database import SessionLocal
from app.models import AnalysisRun, Configuration, User
from app.services.audit_service import create_audit_log
from app.services.analysis_service import analyze_configuration_content
from app.services.training_candidate_service import (
    persist_training_candidates,
)
from app.services.auth_dependency import get_current_user
from app.services.permission_dependency import require_permission


router = APIRouter(
    prefix="/configurations",
    tags=["Configurations"],
)


ALLOWED_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".txt",
}


MAX_FILE_SIZE = 5 * 1024 * 1024


SUPPORTED_FRAMEWORKS = {
    "CIS": "CIS",
    "NIST": "NIST",
    "DISA_STIG": "DISA_STIG",
    "ISO_27001": "ISO_27001",
}


FRAMEWORK_ALIASES = {
    "ISO/IEC 27001": "ISO_27001",
    "ISO 27001": "ISO_27001",
    "STIG": "DISA_STIG",
    "DISA STIG": "DISA_STIG",
}


def _normalize_framework_name(framework: str) -> str:
    """
    Normalize a user-supplied framework name.
    """

    normalized = framework.strip().upper()

    normalized = FRAMEWORK_ALIASES.get(
        normalized,
        normalized,
    )

    if normalized not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported framework '{framework}'. "
                f"Supported frameworks: "
                f"{', '.join(SUPPORTED_FRAMEWORKS.keys())}"
            ),
        )

    return normalized


def _normalize_frameworks(
    frameworks: list[str] | None,
) -> list[str]:
    """
    Normalize and deduplicate framework names.

    If no framework is supplied, CIS is used as the
    backward-compatible default.
    """

    if not frameworks:
        return ["CIS"]

    normalized_frameworks: list[str] = []

    for framework in frameworks:
        normalized = _normalize_framework_name(
            framework
        )

        if normalized not in normalized_frameworks:
            normalized_frameworks.append(
                normalized
            )

    return normalized_frameworks


# ============================================================
# CONFIGURATION UPLOAD
# ============================================================

@router.post("/upload")
async def upload_configuration(
    file: UploadFile = File(...),
    current_user: User = Depends(
        require_permission("configs.upload")
    ),
):
    filename = file.filename or ""

    if "." not in filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must have an extension.",
        )

    extension = "." + filename.rsplit(
        ".",
        1,
    )[1].lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Unsupported file type. "
                "Allowed extensions: .cfg, .conf, .txt"
            ),
        )

    content_bytes = await file.read()

    if len(content_bytes) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File size exceeds the 5 MB limit.",
        )

    try:
        content = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Configuration file must be valid UTF-8 text.",
        )

    if not content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Configuration file is empty.",
        )

    db = SessionLocal()

    try:
        configuration = Configuration(
            original_filename=filename,
            file_extension=extension,
            file_size=len(content_bytes),
            content=content,
            upload_status="UPLOADED",
            uploaded_by=current_user.id,
        )

        db.add(configuration)
        db.commit()
        db.refresh(configuration)

        create_audit_log(
            db=db,
            action="CONFIGURATION_UPLOADED",
            status="SUCCESS",
            user=current_user,
            resource_type="configuration",
            resource_id=str(configuration.id),
            details={
                "filename": filename,
                "extension": extension,
                "file_size": len(content_bytes),
            },
        )

        return {
            "id": configuration.id,
            "filename": configuration.original_filename,
            "extension": configuration.file_extension,
            "size": configuration.file_size,
            "status": configuration.upload_status,
            "uploaded_by": current_user.username,
            "created_at": configuration.created_at,
        }

    except Exception:
        db.rollback()

        create_audit_log(
            db=db,
            action="CONFIGURATION_UPLOAD_FAILED",
            status="FAILED",
            user=current_user,
            details={
                "filename": filename,
            },
        )

        raise

    finally:
        db.close()


# ============================================================
# LIST CONFIGURATIONS
# ============================================================

@router.get("")
def list_configurations(
    current_user: User = Depends(
        require_permission("configs.view")
    ),
):
    db = SessionLocal()

    try:
        latest_run_subquery = (
            select(
                AnalysisRun.configuration_id,
                func.max(AnalysisRun.id).label("latest_run_id"),
            )
            .where(
                AnalysisRun.status == "COMPLETED"
            )
            .group_by(
                AnalysisRun.configuration_id
            )
            .subquery()
        )

        rows = db.execute(
            select(
                Configuration,
                AnalysisRun,
            )
            .outerjoin(
                latest_run_subquery,
                latest_run_subquery.c.configuration_id
                == Configuration.id,
            )
            .outerjoin(
                AnalysisRun,
                AnalysisRun.id
                == latest_run_subquery.c.latest_run_id,
            )
            .where(
                Configuration.uploaded_by == current_user.id
            )
            .order_by(
                Configuration.created_at.desc()
            )
        ).all()

        configurations = []

        for configuration, analysis_run in rows:
            latest_analysis = None

            if analysis_run:
                compliance = analysis_run.compliance or {}
                risk = analysis_run.risk or {}

                latest_analysis = {
                    "id": analysis_run.id,
                    "status": analysis_run.status,
                    "selected_frameworks": (
                        analysis_run.selected_frameworks or []
                    ),
                    "compliance_percentage": compliance.get(
                        "compliance_percentage"
                    ),
                    "risk_score": risk.get(
                        "risk_score"
                    ),
                    "risk_level": risk.get(
                        "risk_level"
                    ),
                    "created_at": analysis_run.created_at,
                }

            configurations.append(
                {
                    "id": configuration.id,
                    "filename": configuration.original_filename,
                    "extension": configuration.file_extension,
                    "size": configuration.file_size,
                    "status": configuration.upload_status,
                    "uploaded_by": configuration.uploaded_by,
                    "created_at": configuration.created_at,
                    "latest_analysis": latest_analysis,
                }
            )

        return {
            "count": len(configurations),
            "configurations": configurations,
        }

    finally:
        db.close()


# ============================================================
# GET CONFIGURATION
# ============================================================

@router.get("/{configuration_id}")
def get_configuration(
    configuration_id: int,
    current_user: User = Depends(
        require_permission("configs.view")
    ),
):
    db = SessionLocal()

    try:
        configuration = db.scalar(
            select(Configuration).where(
                Configuration.id == configuration_id,
                Configuration.uploaded_by == current_user.id,
            )
        )

        if not configuration:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Configuration not found.",
            )

        return {
            "id": configuration.id,
            "filename": configuration.original_filename,
            "extension": configuration.file_extension,
            "size": configuration.file_size,
            "content": configuration.content,
            "status": configuration.upload_status,
            "uploaded_by": configuration.uploaded_by,
            "created_at": configuration.created_at,
        }

    finally:
        db.close()


# ============================================================
# ANALYZE CONFIGURATION
# ============================================================

@router.post("/{configuration_id}/analyze")
def analyze_configuration(
    configuration_id: int,
    frameworks: list[str] | None = Query(
        default=None,
        description=(
            "Security frameworks to evaluate. "
            "Supported values: CIS, NIST, DISA_STIG, ISO_27001. "
            "If omitted, CIS is used."
        ),
    ),
    current_user: User = Depends(
        require_permission("configs.view")
    ),
):
    db = SessionLocal()

    try:
        configuration = db.scalar(
            select(Configuration).where(
                Configuration.id == configuration_id,
                Configuration.uploaded_by == current_user.id,
            )
        )

        if not configuration:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Configuration not found.",
            )

        selected_frameworks = _normalize_frameworks(
            frameworks
        )

        # -----------------------------------------------------
        # 1-6. Run complete analysis pipeline
        # -----------------------------------------------------

        analysis = analyze_configuration_content(
            configuration.content,
            selected_frameworks,
        )

        # -----------------------------------------------------
        # Persist AI results requiring human training
        # -----------------------------------------------------

        training_candidates = (
            persist_training_candidates(
                db=db,
                configuration_id=configuration.id,
                ai_ingestion=analysis.get(
                    "ai_ingestion",
                    {},
                ),
            )
        )

        device_intelligence = analysis[
            "device_intelligence"
        ]

        parsed_parser = analysis["parser"]

        baseline = analysis[
            "security_baseline"
        ]

        compliance = analysis[
            "compliance"
        ]

        framework_results = analysis[
            "framework_results"
        ]

        risk = analysis["risk"]

        remediation = analysis[
            "remediation"
        ]

        # -----------------------------------------------------
        # 7. Persist analysis result
        # -----------------------------------------------------

        analysis_run = AnalysisRun(
            configuration_id=configuration.id,
            analyzed_by=current_user.id,
            status="COMPLETED",
            selected_frameworks=selected_frameworks,
            device_intelligence=device_intelligence,
            parser=parsed_parser,
            security_baseline=baseline,
            compliance=compliance,
            framework_results=framework_results,
            ai_ingestion=analysis.get(
                "ai_ingestion",
                {},
            ),
            unknown_lines=analysis.get(
                "unknown_lines",
                [],
            ),
            risk=risk,
            remediation=remediation,
        )

        db.add(analysis_run)

        # Keep the existing configuration status behavior.
        configuration.upload_status = "ANALYZED"

        db.commit()
        db.refresh(analysis_run)

        # -----------------------------------------------------
        # 8. Audit analysis
        # -----------------------------------------------------

        create_audit_log(
            db=db,
            action="CONFIGURATION_ANALYZED",
            status="SUCCESS",
            user=current_user,
            resource_type="configuration",
            resource_id=str(configuration.id),
            details={
                "vendor": baseline.get(
                    "vendor",
                    "Unknown",
                ),
                "frameworks": selected_frameworks,
                "compliance_percentage": compliance.get(
                    "compliance_percentage",
                    0.0,
                ),
                "risk_score": risk.get(
                    "risk_score",
                    0.0,
                ),
            },
        )

        # -----------------------------------------------------
        # 9. Return complete analysis
        # -----------------------------------------------------

        return {
            "configuration_id": configuration.id,
            "filename": configuration.original_filename,
            "device_intelligence": device_intelligence,
            "parser": parsed_parser,
            "security_baseline": baseline,
            "compliance": compliance,
            "framework_results": framework_results,
            "selected_frameworks": selected_frameworks,
            "ai_ingestion": analysis.get(
                "ai_ingestion",
                {},
            ),
            "unknown_lines": analysis.get(
                "unknown_lines",
                [],
            ),
            "training": {
                "candidates_created": len(
                    training_candidates
                ),
            },
            "risk": risk,
            "remediation": remediation,
        }

    except HTTPException:
        raise

    except Exception:
        db.rollback()

        create_audit_log(
            db=db,
            action="CONFIGURATION_ANALYSIS_FAILED",
            status="FAILED",
            user=current_user,
            resource_type="configuration",
            resource_id=str(configuration_id),
        )

        raise

    finally:
        db.close()

@router.delete("/history")
def delete_configuration_history(
    current_user: User = Depends(get_current_user),
):
    """
    Delete all configuration history owned by the current user.

    Associated analysis runs and training candidates are removed.
    Remediation history is preserved but detached from the deleted
    configurations. Audit history and global learned mappings are
    preserved.
    """

    db = SessionLocal()

    try:
        # Only ADMIN and SECURITY_ANALYST accounts can delete
        # their own configuration history.
        role_name = (
            current_user.role.name
            if current_user.role
            else None
        )

        if role_name not in {
            "ADMIN",
            "SECURITY_ANALYST",
        }:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "You do not have permission to delete "
                    "configuration history."
                ),
            )

        from app.models import (
            RemediationRequest,
            TrainingCandidate,
        )

        # Find ONLY configurations owned by the current user.
        configurations = db.scalars(
            select(Configuration).where(
                Configuration.uploaded_by == current_user.id
            )
        ).all()

        configuration_ids = [
            configuration.id
            for configuration in configurations
        ]

        # Nothing to delete.
        if not configuration_ids:
            return {
                "message": "No configuration history to delete.",
                "deleted_count": 0,
            }

        # Delete training candidates associated with
        # the user's configurations.
        training_candidates = db.scalars(
            select(TrainingCandidate).where(
                TrainingCandidate.configuration_id.in_(
                    configuration_ids
                )
            )
        ).all()

        for candidate in training_candidates:
            db.delete(candidate)

        # Delete analysis history associated with
        # the user's configurations.
        analysis_runs = db.scalars(
            select(AnalysisRun).where(
                AnalysisRun.configuration_id.in_(
                    configuration_ids
                )
            )
        ).all()

        for analysis_run in analysis_runs:
            db.delete(analysis_run)
        db.flush()
        # Preserve remediation history.
        # Only detach the deleted configurations.
        db.execute(
            update(RemediationRequest)
            .where(
                RemediationRequest.configuration_id.in_(
                    configuration_ids
                )
            )
            .values(configuration_id=None)
        )

        deleted_count = len(configurations)

        # Delete the user's configurations.
        for configuration in configurations:
            db.delete(configuration)

        # Preserve an audit record of the bulk deletion.
        create_audit_log(
            db=db,
            action="CONFIGURATION_HISTORY_DELETED",
            status="SUCCESS",
            user=current_user,
            resource_type="configuration_history",
            resource_id="bulk",
            details={
                "deleted_count": deleted_count,
                "configuration_ids": configuration_ids,
            },
        )

        db.commit()

        return {
            "message": (
                f"{deleted_count} configuration"
                f"{'s' if deleted_count != 1 else ''} "
                "deleted successfully."
            ),
            "deleted_count": deleted_count,
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()

@router.delete("/{configuration_id}")
def delete_configuration(
    configuration_id: int,
    current_user: User = Depends(get_current_user),
):
    """
    Delete a configuration owned by the current user.

    Associated analysis runs and training candidates are removed.
    Remediation history is preserved but detached from the deleted
    configuration. Audit history is intentionally preserved.
    """

    db = SessionLocal()

    try:
        # Only ADMIN and SECURITY_ANALYST accounts can delete
        # their own configuration history.
        role_name = (
            current_user.role.name
            if current_user.role
            else None
        )

        if role_name not in {
            "ADMIN",
            "SECURITY_ANALYST",
        }:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "You do not have permission to delete "
                    "configurations."
                ),
            )

        configuration = db.scalar(
            select(Configuration).where(
                Configuration.id == configuration_id,
                Configuration.uploaded_by == current_user.id,
            )
        )

        if not configuration:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Configuration not found.",
            )

        # Import here to avoid changing unrelated module
        # initialization behavior.
        from app.models import (
            AnalysisRun,
            RemediationRequest,
            TrainingCandidate,
        )

        # Training candidates belong to this configuration.
        training_candidates = db.scalars(
            select(TrainingCandidate).where(
                TrainingCandidate.configuration_id
                == configuration_id
            )
        ).all()

        for candidate in training_candidates:
            db.delete(candidate)
        # Flush dependent records first so PostgreSQL
        # can safely remove the configuration afterward.
        db.flush()

        # Analysis history belongs to this configuration.
        analysis_runs = db.scalars(
            select(AnalysisRun).where(
                AnalysisRun.configuration_id
                == configuration_id
            )
        ).all()

        for analysis_run in analysis_runs:
            db.delete(analysis_run)

        # Flush dependent records before deleting configurations.
        db.flush()

        # Preserve remediation history.
        # Only detach the deleted configuration.
        db.execute(
            update(RemediationRequest)
            .where(
                RemediationRequest.configuration_id
                == configuration_id
            )
            .values(configuration_id=None)
        )

        deleted_filename = (
            configuration.original_filename
            or f"Configuration #{configuration_id}"
        )

        db.delete(configuration)

        create_audit_log(
            db=db,
            action="CONFIGURATION_DELETED",
            status="SUCCESS",
            user=current_user,
            resource_type="configuration",
            resource_id=str(configuration_id),
            details={
                "configuration_id": configuration_id,
                "filename": deleted_filename,
            },
        )

        db.commit()

        return {
            "message": (
                f"Configuration #{configuration_id} "
                "deleted successfully."
            ),
            "configuration_id": configuration_id,
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()
