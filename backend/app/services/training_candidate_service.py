from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import TrainingCandidate


def _normalize_configuration_line(line: str) -> str:
    """Normalize configuration syntax for duplicate detection."""
    return " ".join(line.lower().split())


def persist_training_candidates(
    db: Session,
    configuration_id: int,
    ai_ingestion: dict[str, Any] | None,
) -> list[TrainingCandidate]:
    """
    Persist AI results that require human training.

    Existing PENDING or APPROVED candidates for the same
    configuration and normalized configuration line are reused.
    """

    if not ai_ingestion:
        return []

    results = ai_ingestion.get("results", [])

    if not isinstance(results, list):
        return []

    persisted_candidates: list[TrainingCandidate] = []

    for result in results:
        if not isinstance(result, dict):
            continue

        if result.get("requires_human_training") is not True:
            continue

        configuration_line = str(
            result.get("configuration_line", "")
        ).strip()

        if not configuration_line:
            continue

        normalized_line = _normalize_configuration_line(
            configuration_line
        )

        existing_candidates = db.scalars(
            select(TrainingCandidate).where(
                TrainingCandidate.configuration_id
                == configuration_id
            )
        ).all()

        duplicate = None

        for candidate in existing_candidates:
            if (
                _normalize_configuration_line(
                    candidate.configuration_line
                )
                == normalized_line
                and candidate.status
                in {"PENDING", "APPROVED"}
            ):
                duplicate = candidate
                break

        if duplicate:
            persisted_candidates.append(duplicate)
            continue

        evidence = result.get("evidence", [])

        if isinstance(evidence, list):
            evidence_text = " | ".join(
                str(item)
                for item in evidence
            )
        else:
            evidence_text = str(evidence)

        expected_value = result.get(
            "expected_value"
        )

        if expected_value is None:
            expected_value_text = ""
        else:
            expected_value_text = str(
                expected_value
            )

        candidate = TrainingCandidate(
            configuration_id=configuration_id,
            configuration_line=configuration_line,
            suggested_category=str(
                result.get(
                    "category",
                    "Unknown",
                )
            ),
            suggested_baseline_parameter=str(
                result.get(
                    "parameter",
                    "",
                )
            ),
            suggested_expected_value=(
                expected_value_text
            ),
            confidence=float(
                result.get(
                    "confidence",
                    0.0,
                )
            ),
            confidence_level=str(
                result.get(
                    "confidence_level",
                    "LOW",
                )
            ),
            evidence=evidence_text,
            source=str(
                result.get(
                    "source",
                    "semantic_nlp",
                )
            ),
            status="PENDING",
        )

        db.add(candidate)
        db.flush()

        persisted_candidates.append(candidate)

    return persisted_candidates
