from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query,Request ,status
from sqlalchemy import select

from app.db.database import SessionLocal
from app.models import BulkAnalysisJob, Configuration, User
from app.services.analysis_service import (
    analyze_configuration_content,
)
from app.services.audit_service import create_audit_log
from app.services.permission_dependency import require_permission


router = APIRouter(
    prefix="/bulk",
    tags=["Bulk Analysis"],
)


SUPPORTED_FRAMEWORKS = {
    "CIS",
    "NIST",
    "DISA_STIG",
    "ISO_27001",
}


FRAMEWORK_ALIASES = {
    "ISO/IEC 27001": "ISO_27001",
    "ISO 27001": "ISO_27001",
    "STIG": "DISA_STIG",
    "DISA STIG": "DISA_STIG",
}


def _normalize_framework_name(
    framework: str,
) -> str:
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
                "Supported frameworks: "
                "CIS, NIST, DISA_STIG, ISO_27001."
            ),
        )

    return normalized


def _normalize_frameworks(
    frameworks: list[str] | None,
) -> list[str]:
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


def _calculate_summary(
    results: list[dict],
) -> dict:
    compliance_values = [
        result["compliance"]["compliance_percentage"]
        for result in results
        if result.get("status") == "SUCCESS"
        and result.get("compliance")
    ]

    risk_values = [
        result["risk"]["risk_score"]
        for result in results
        if result.get("status") == "SUCCESS"
        and result.get("risk")
    ]

    average_compliance = (
        round(
            sum(compliance_values)
            / len(compliance_values),
            2,
        )
        if compliance_values
        else 0.0
    )

    average_risk = (
        round(
            sum(risk_values)
            / len(risk_values),
            2,
        )
        if risk_values
        else 0.0
    )

    total_findings = sum(
        result["risk"].get(
            "total_findings",
            0,
        )
        for result in results
        if result.get("status") == "SUCCESS"
        and result.get("risk")
    )

    critical_findings = sum(
        (
            result["risk"].get(
                "critical_findings",
                0,
            )
            if isinstance(
                result["risk"].get(
                    "critical_findings",
                    0,
                ),
                int,
            )
            else len(
                result["risk"].get(
                    "critical_findings",
                    [],
                )
            )
        )
        for result in results
        if result.get("status") == "SUCCESS"
        and result.get("risk")
    )

    return {
        "average_compliance_percentage": (
            average_compliance
        ),
        "average_risk_score": average_risk,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
    }


@router.post("/analyze")
def analyze_bulk_configurations(
    configuration_ids: list[int],
    request: Request,
    frameworks: list[str] | None = Query(
        default=None,
        description=(
            "Security frameworks to evaluate. "
            "If omitted, CIS is used."
        ),
    ),
    current_user: User = Depends(
        require_permission("scans.run")
    ),
):
    """
    Analyze multiple uploaded configurations using
    the same analysis pipeline as single configuration
    analysis and persist the execution as a bulk job.
    """

    if not configuration_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one configuration ID is required.",
        )

    if len(configuration_ids) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "A maximum of 500 configurations "
                "can be processed in one bulk request."
            ),
        )

    selected_frameworks = _normalize_frameworks(
        frameworks
    )

    db = SessionLocal()

    job: BulkAnalysisJob | None = None

    try:
        job = BulkAnalysisJob(
            status="PENDING",
            total_configurations=len(
                configuration_ids
            ),
            successful=0,
            failed=0,
            selected_frameworks=selected_frameworks,
            summary={},
            results=[],
            created_by=current_user.id,
            created_at=datetime.utcnow(),
        )

        db.add(job)
        db.commit()
        db.refresh(job)

        create_audit_log(
            db=db,
            action="BULK_ANALYSIS_STARTED",
            status="STARTED",
            user=current_user,
            request=request,
            resource_type="bulk_analysis_job",
            resource_id=str(job.id),
            details={
                "total_configurations": len(
                    configuration_ids
                ),
                "configuration_ids": configuration_ids,
                "frameworks": selected_frameworks,
            },
        )

        job.status = "RUNNING"
        db.commit()

        configurations = db.scalars(
            select(Configuration).where(
                Configuration.id.in_(configuration_ids),
                Configuration.uploaded_by == current_user.id,
            )
        ).all()

        configurations_by_id = {
            configuration.id: configuration
            for configuration in configurations
        }

        results: list[dict] = []
        successful = 0
        failed = 0

        for configuration_id in configuration_ids:
            configuration = configurations_by_id.get(
                configuration_id
            )

            if configuration is None:
                failed += 1

                results.append(
                    {
                        "configuration_id": (
                            configuration_id
                        ),
                        "status": "FAILED",
                        "error": (
                            "Configuration not found."
                        ),
                    }
                )

                continue

            try:
                analysis = analyze_configuration_content(
                    configuration.content,
                    selected_frameworks,
                )

                configuration.upload_status = (
                    "ANALYZED"
                )

                successful += 1

                results.append(
                    {
                        "configuration_id": (
                            configuration.id
                        ),
                        "filename": (
                            configuration.original_filename
                        ),
                        "status": "SUCCESS",
                        "vendor": (
                            analysis[
                                "security_baseline"
                            ].get(
                                "vendor",
                                "Unknown",
                            )
                        ),
                        "device_intelligence": (
                            analysis[
                                "device_intelligence"
                            ]
                        ),
                        "parser": analysis["parser"],
                        "compliance": (
                            analysis["compliance"]
                        ),
                        "risk": analysis["risk"],
                        "remediation": (
                            analysis["remediation"]
                        ),
                        "selected_frameworks": (
                            analysis[
                                "selected_frameworks"
                            ]
                        ),
                    }
                )

            except Exception as exc:
                failed += 1

                results.append(
                    {
                        "configuration_id": (
                            configuration.id
                        ),
                        "filename": (
                            configuration.original_filename
                        ),
                        "status": "FAILED",
                        "error": str(exc),
                    }
                )

        summary = _calculate_summary(results)

        job.status = (
            "COMPLETED"
            if failed == 0
            else "COMPLETED_WITH_ERRORS"
        )

        job.successful = successful
        job.failed = failed
        job.summary = summary
        job.results = results
        job.completed_at = datetime.utcnow()

        db.commit()
        db.refresh(job)

        create_audit_log(
            db=db,
            action="BULK_ANALYSIS_COMPLETED",
            status="SUCCESS",
            user=current_user,
            request=request,
            resource_type="bulk_analysis_job",
            resource_id=str(job.id),
            details={
                "total_configurations": job.total_configurations,
                "successful": job.successful,
                "failed": job.failed,
                "frameworks": job.selected_frameworks,
                "summary": job.summary,
            },
        )

        return {
            "job_id": job.id,
            "status": job.status,
            "total_configurations": (
                job.total_configurations
            ),
            "successful": job.successful,
            "failed": job.failed,
            "selected_frameworks": (
                job.selected_frameworks
            ),
            "summary": job.summary,
            "results": job.results,
        }

    except HTTPException:
        db.rollback()

        if job is not None:
            job.status = "FAILED"
            job.completed_at = datetime.utcnow()
            db.commit()

        raise

    except Exception as exc:
        db.rollback()

        if job is not None:
            try:
                db.refresh(job)

                job.status = "FAILED"
                job.summary = {
                    "error": str(exc)
                }
                job.completed_at = datetime.utcnow()

                db.commit()

                create_audit_log(
                    db=db,
                    action="BULK_ANALYSIS_FAILED",
                    status="FAILED",
                    user=current_user,
                    request=request,
                    resource_type="bulk_analysis_job",
                    resource_id=str(job.id),
                    details={
                        "error": str(exc),
                    },
                )

            except Exception:
                db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Bulk analysis failed.",
        ) from exc

    finally:
        db.close()

@router.get("/jobs")
def list_bulk_analysis_jobs(
    current_user: User = Depends(
        require_permission("scans.view")
    ),
):
    """
    Return persisted bulk analysis jobs.
    """

    db = SessionLocal()

    try:
        jobs = db.scalars(
            select(BulkAnalysisJob)
            .where(
                BulkAnalysisJob.created_by == current_user.id
            )
            .order_by(
                BulkAnalysisJob.created_at.desc()
            )
        ).all()

        return [
            {
                "job_id": job.id,
                "status": job.status,
                "total_configurations": (
                    job.total_configurations
                ),
                "successful": job.successful,
                "failed": job.failed,
                "selected_frameworks": (
                    job.selected_frameworks
                ),
                "summary": job.summary,
                "created_by": job.created_by,
                "created_at": job.created_at,
                "completed_at": job.completed_at,
            }
            for job in jobs
        ]

    finally:
        db.close()


@router.get("/jobs/{job_id}")
def get_bulk_analysis_job(
    job_id: int,
    current_user: User = Depends(
        require_permission("scans.view")
    ),
):
    """
    Return one persisted bulk analysis job,
    including its complete results.
    """

    db = SessionLocal()

    try:
        job = db.scalar(
            select(BulkAnalysisJob).where(
                BulkAnalysisJob.id == job_id,
                BulkAnalysisJob.created_by == current_user.id,
            )
        )

        if job is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Bulk analysis job not found.",
            )

        return {
            "job_id": job.id,
            "status": job.status,
            "total_configurations": (
                job.total_configurations
            ),
            "successful": job.successful,
            "failed": job.failed,
            "selected_frameworks": (
                job.selected_frameworks
            ),
            "summary": job.summary,
            "results": job.results,
            "created_by": job.created_by,
            "created_at": job.created_at,
            "completed_at": job.completed_at,
        }

    finally:
        db.close()