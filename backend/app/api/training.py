from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from datetime import datetime

from app.db.database import SessionLocal
from app.models import Configuration, LearnedMapping, TrainingCandidate, User
from app.services.audit_service import create_audit_log
from app.services.permission_dependency import require_permission

def _get_owned_training_candidate(db, candidate_id: int, current_user: User):
    candidate = db.scalar(
        select(TrainingCandidate)
        .join(
            Configuration,
            Configuration.id == TrainingCandidate.configuration_id,
        )
        .where(
            TrainingCandidate.id == candidate_id,
            Configuration.uploaded_by == current_user.id,
        )
    )

    if not candidate:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Training candidate not found.",
        )

    return candidate

router = APIRouter(
    prefix="/training",
    tags=["Human Training"],
)


class LearnedMappingCreate(BaseModel):
    configuration_pattern: str = Field(
        min_length=1,
        max_length=5000,
    )
    security_category: str = Field(
        min_length=1,
        max_length=100,
    )
    baseline_parameter: str = Field(
        min_length=1,
        max_length=255,
    )
    expected_value: str = Field(
        min_length=1,
    )
class TrainingCandidateRejectBatch(BaseModel):
    candidate_ids: list[int] = Field(
        min_length=1,
        max_length=500,
    )

@router.post("/mappings")
def create_learned_mapping(
    mapping: LearnedMappingCreate,
    current_user: User = Depends(
        require_permission("configs.view")
    ),
):
    db = SessionLocal()

    try:
        learned_mapping = LearnedMapping(
            configuration_pattern=mapping.configuration_pattern,
            security_category=mapping.security_category,
            baseline_parameter=mapping.baseline_parameter,
            expected_value=mapping.expected_value,
            confidence=1.0,
            is_active=True,
            created_by=current_user.id,
        )

        db.add(learned_mapping)
        db.commit()
        db.refresh(learned_mapping)

        create_audit_log(
            db=db,
            action="LEARNED_MAPPING_CREATED",
            status="SUCCESS",
            user=current_user,
            resource_type="learned_mapping",
            resource_id=str(learned_mapping.id),
            details={
                "security_category": mapping.security_category,
                "baseline_parameter": mapping.baseline_parameter,
            },
        )

        return {
            "id": learned_mapping.id,
            "configuration_pattern": learned_mapping.configuration_pattern,
            "security_category": learned_mapping.security_category,
            "baseline_parameter": learned_mapping.baseline_parameter,
            "expected_value": learned_mapping.expected_value,
            "confidence": learned_mapping.confidence,
            "is_active": learned_mapping.is_active,
            "created_by": learned_mapping.created_by,
            "created_at": learned_mapping.created_at,
        }

    except Exception:
        db.rollback()

        create_audit_log(
            db=db,
            action="LEARNED_MAPPING_CREATE_FAILED",
            status="FAILED",
            user=current_user,
            resource_type="learned_mapping",
        )

        raise

    finally:
        db.close()


@router.get("/mappings")
def list_learned_mappings(
    current_user: User = Depends(
        require_permission("configs.view")
    ),
):
    db = SessionLocal()

    try:
        mappings = db.scalars(
            select(LearnedMapping)
            .order_by(LearnedMapping.created_at.desc())
        ).all()

        return {
            "count": len(mappings),
            "mappings": [
                {
                    "id": mapping.id,
                    "configuration_pattern": mapping.configuration_pattern,
                    "security_category": mapping.security_category,
                    "baseline_parameter": mapping.baseline_parameter,
                    "expected_value": mapping.expected_value,
                    "confidence": mapping.confidence,
                    "is_active": mapping.is_active,
                    "created_by": mapping.created_by,
                    "created_at": mapping.created_at,
                    "updated_at": mapping.updated_at,
                }
                for mapping in mappings
            ],
        }

    finally:
        db.close()

# ============================================================
# TRAINING CANDIDATES
# ============================================================

@router.get("/candidates")
def list_training_candidates(
    candidate_status: str | None = None,
    current_user: User = Depends(
        require_permission("configs.view")
    ),
):
    db = SessionLocal()

    try:
        query = (
            select(TrainingCandidate)
            .join(
                Configuration,
                Configuration.id == TrainingCandidate.configuration_id,
            )
            .where(Configuration.uploaded_by == current_user.id)
        )

        if candidate_status:
            normalized_status = candidate_status.strip().upper()

            if normalized_status not in {
                "PENDING",
                "APPROVED",
                "REJECTED",
            }:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "Invalid candidate status. "
                        "Supported values: "
                        "PENDING, APPROVED, REJECTED."
                    ),
                )

            query = query.where(
                TrainingCandidate.status
                == normalized_status
            )

        candidates = db.scalars(
            query.order_by(
                TrainingCandidate.created_at.desc()
            )
        ).all()

        return {
            "count": len(candidates),
            "candidates": [
                {
                    "id": candidate.id,
                    "configuration_id": (
                        candidate.configuration_id
                    ),
                    "configuration_line": (
                        candidate.configuration_line
                    ),
                    "suggested_category": (
                        candidate.suggested_category
                    ),
                    "suggested_baseline_parameter": (
                        candidate.suggested_baseline_parameter
                    ),
                    "suggested_expected_value": (
                        candidate.suggested_expected_value
                    ),
                    "confidence": candidate.confidence,
                    "confidence_level": (
                        candidate.confidence_level
                    ),
                    "evidence": candidate.evidence,
                    "source": candidate.source,
                    "status": candidate.status,
                    "created_at": candidate.created_at,
                    "reviewed_at": candidate.reviewed_at,
                    "reviewed_by": candidate.reviewed_by,
                    "learned_mapping_id": (
                        candidate.learned_mapping_id
                    ),
                }
                for candidate in candidates
            ],
        }

    finally:
        db.close()

@router.post(
    "/candidates/{candidate_id}/approve"
)
def approve_training_candidate(
    candidate_id: int,
    mapping_data: LearnedMappingCreate,
    current_user: User = Depends(
        require_permission("configs.view")
    ),
):
    db = SessionLocal()

    try:
        candidate = _get_owned_training_candidate(
            db,
            candidate_id,
            current_user,
        )

        if candidate.status != "PENDING":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Training candidate is already "
                    f"{candidate.status}."
                ),
            )

        mapping = LearnedMapping(
            configuration_pattern=(
                mapping_data.configuration_pattern
            ),
            security_category=(
                mapping_data.security_category
            ),
            baseline_parameter=(
                mapping_data.baseline_parameter
            ),
            expected_value=(
                mapping_data.expected_value
            ),
            confidence=1.0,
            is_active=True,
            created_by=current_user.id,
        )

        db.add(mapping)
        db.flush()

        candidate.status = "APPROVED"
        candidate.learned_mapping_id = mapping.id
        candidate.reviewed_by = current_user.id
        candidate.reviewed_at = datetime.utcnow()

        db.commit()

        db.refresh(mapping)
        db.refresh(candidate)

        create_audit_log(
            db=db,
            action="TRAINING_CANDIDATE_APPROVED",
            status="SUCCESS",
            user=current_user,
            resource_type="training_candidate",
            resource_id=str(candidate.id),
            details={
                "configuration_line": (
                    candidate.configuration_line
                ),
                "learned_mapping_id": mapping.id,
                "security_category": (
                    mapping.security_category
                ),
                "baseline_parameter": (
                    mapping.baseline_parameter
                ),
                "expected_value": (
                    mapping.expected_value
                ),
            },
        )

        return {
            "message": (
                "Training candidate approved "
                "successfully."
            ),
            "candidate": {
                "id": candidate.id,
                "status": candidate.status,
                "learned_mapping_id": (
                    candidate.learned_mapping_id
                ),
                "reviewed_by": candidate.reviewed_by,
                "reviewed_at": candidate.reviewed_at,
            },
            "mapping": {
                "id": mapping.id,
                "configuration_pattern": (
                    mapping.configuration_pattern
                ),
                "security_category": (
                    mapping.security_category
                ),
                "baseline_parameter": (
                    mapping.baseline_parameter
                ),
                "expected_value": (
                    mapping.expected_value
                ),
                "confidence": mapping.confidence,
                "is_active": mapping.is_active,
            },
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()

        create_audit_log(
            db=db,
            action="TRAINING_CANDIDATE_APPROVAL_FAILED",
            status="FAILED",
            user=current_user,
            resource_type="training_candidate",
            resource_id=str(candidate_id),
        )

        raise

    finally:
        db.close()

@router.post(
    "/candidates/{candidate_id}/reject"
)
def reject_training_candidate(
    candidate_id: int,
    current_user: User = Depends(
        require_permission("configs.view")
    ),
):
    db = SessionLocal()

    try:
        candidate = _get_owned_training_candidate(
            db,
            candidate_id,
            current_user,
        )


        candidate.status = "REJECTED"
        candidate.reviewed_by = current_user.id
        candidate.reviewed_at = datetime.utcnow()

        db.commit()
        db.refresh(candidate)

        create_audit_log(
            db=db,
            action="TRAINING_CANDIDATE_REJECTED",
            status="SUCCESS",
            user=current_user,
            resource_type="training_candidate",
            resource_id=str(candidate.id),
            details={
                "configuration_id": (
                    candidate.configuration_id
                ),
                "configuration_line": (
                    candidate.configuration_line
                ),
                "suggested_category": (
                    candidate.suggested_category
                ),
                "suggested_baseline_parameter": (
                    candidate.suggested_baseline_parameter
                ),
                "confidence": candidate.confidence,
                "confidence_level": (
                    candidate.confidence_level
                ),
            },
        )

        return {
            "message": (
                "Training candidate rejected successfully."
            ),
            "candidate": {
                "id": candidate.id,
                "configuration_id": (
                    candidate.configuration_id
                ),
                "configuration_line": (
                    candidate.configuration_line
                ),
                "status": candidate.status,
                "reviewed_by": candidate.reviewed_by,
                "reviewed_at": candidate.reviewed_at,
                "learned_mapping_id": (
                    candidate.learned_mapping_id
                ),
            },
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()

        create_audit_log(
            db=db,
            action="TRAINING_CANDIDATE_REJECTION_FAILED",
            status="FAILED",
            user=current_user,
            resource_type="training_candidate",
            resource_id=str(candidate_id),
        )

        raise

    finally:
        db.close()

@router.post(
    "/candidates/reject-batch"
)
def reject_training_candidates_batch(
    request: TrainingCandidateRejectBatch,
    current_user: User = Depends(
        require_permission("configs.view")
    ),
):
    db = SessionLocal()

    try:
        candidate_ids = list(
            dict.fromkeys(request.candidate_ids)
        )

        candidates = db.scalars(
            select(TrainingCandidate)
            .join(
                Configuration,
                Configuration.id == TrainingCandidate.configuration_id,
            )
            .where(
                TrainingCandidate.id.in_(candidate_ids),
                Configuration.uploaded_by == current_user.id,
            )
        ).all()

        candidates_by_id = {
            candidate.id: candidate
            for candidate in candidates
        }

        missing_ids = [
            candidate_id
            for candidate_id in candidate_ids
            if candidate_id not in candidates_by_id
        ]

        if missing_ids:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "message": "One or more training candidates were not found.",
                    "missing_ids": missing_ids,
                },
            )

        non_pending = [
            {
                "id": candidate.id,
                "status": candidate.status,
            }
            for candidate in candidates
            if candidate.status != "PENDING"
        ]

        if non_pending:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": (
                        "All candidates must currently be PENDING."
                    ),
                    "non_pending": non_pending,
                },
            )

        rejected = []

        for candidate in candidates:
            candidate.status = "REJECTED"
            candidate.reviewed_by = current_user.id
            candidate.reviewed_at = datetime.utcnow()

            create_audit_log(
                db=db,
                action="TRAINING_CANDIDATE_REJECTED",
                status="SUCCESS",
                user=current_user,
                resource_type="training_candidate",
                resource_id=str(candidate.id),
                details={
                    "configuration_id": (
                        candidate.configuration_id
                    ),
                    "configuration_line": (
                        candidate.configuration_line
                    ),
                    "suggested_category": (
                        candidate.suggested_category
                    ),
                    "suggested_baseline_parameter": (
                        candidate.suggested_baseline_parameter
                    ),
                    "confidence": candidate.confidence,
                    "confidence_level": (
                        candidate.confidence_level
                    ),
                    "batch": True,
                },
            )

            rejected.append(
                {
                    "id": candidate.id,
                    "configuration_id": (
                        candidate.configuration_id
                    ),
                    "configuration_line": (
                        candidate.configuration_line
                    ),
                    "status": candidate.status,
                }
            )

        db.commit()

        return {
            "message": (
                "Training candidates rejected successfully."
            ),
            "count": len(rejected),
            "candidates": rejected,
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()

        create_audit_log(
            db=db,
            action="TRAINING_CANDIDATE_BATCH_REJECTION_FAILED",
            status="FAILED",
            user=current_user,
            resource_type="training_candidate_batch",
            details={
                "candidate_ids": candidate_ids,
            },
        )

        raise

    finally:
        db.close()

@router.get("/candidates/{candidate_id}")
def get_training_candidate(
    candidate_id: int,
    current_user: User = Depends(
        require_permission("configs.view")
    ),
):
    db = SessionLocal()

    try:
        candidate = _get_owned_training_candidate(
            db,
            candidate_id,
            current_user,
        )

        return {
            "id": candidate.id,
            "configuration_id": (
                candidate.configuration_id
            ),
            "configuration_line": (
                candidate.configuration_line
            ),
            "suggested_category": (
                candidate.suggested_category
            ),
            "suggested_baseline_parameter": (
                candidate.suggested_baseline_parameter
            ),
            "suggested_expected_value": (
                candidate.suggested_expected_value
            ),
            "confidence": candidate.confidence,
            "confidence_level": (
                candidate.confidence_level
            ),
            "evidence": candidate.evidence,
            "source": candidate.source,
            "status": candidate.status,
            "created_at": candidate.created_at,
            "reviewed_at": candidate.reviewed_at,
            "reviewed_by": candidate.reviewed_by,
            "learned_mapping_id": (
                candidate.learned_mapping_id
            ),
        }

    finally:
        db.close()

@router.patch("/mappings/{mapping_id}/status")
def update_mapping_status(
    mapping_id: int,
    is_active: bool,
    current_user: User = Depends(
        require_permission("configs.view")
    ),
):
    db = SessionLocal()

    try:
        mapping = db.scalar(
            select(LearnedMapping).where(
                LearnedMapping.id == mapping_id
            )
        )

        if not mapping:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Learned mapping not found.",
            )

        mapping.is_active = is_active

        db.commit()
        db.refresh(mapping)

        create_audit_log(
            db=db,
            action="LEARNED_MAPPING_STATUS_UPDATED",
            status="SUCCESS",
            user=current_user,
            resource_type="learned_mapping",
            resource_id=str(mapping.id),
            details={
                "is_active": is_active,
            },
        )

        return {
            "id": mapping.id,
            "is_active": mapping.is_active,
            "message": (
                "Learned mapping activated."
                if is_active
                else "Learned mapping deactivated."
            ),
        }

    except HTTPException:
        raise

    except Exception:
        db.rollback()

        create_audit_log(
            db=db,
            action="LEARNED_MAPPING_STATUS_UPDATE_FAILED",
            status="FAILED",
            user=current_user,
            resource_type="learned_mapping",
            resource_id=str(mapping_id),
        )

        raise

    finally:
        db.close()
