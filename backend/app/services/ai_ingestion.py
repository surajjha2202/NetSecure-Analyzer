from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select

from app.db.database import SessionLocal
from app.models import LearnedMapping


# ---------------------------------------------------------------------------
# AI/NLP semantic knowledge
# ---------------------------------------------------------------------------
#
# These are intentionally lightweight semantic heuristics.
# Deterministic vendor parsers remain authoritative whenever they can
# confidently interpret a configuration line.
#
SECURITY_SEMANTICS: dict[str, dict[str, Any]] = {
    "authentication.aaa_new_model": {
        "category": "Authentication",
        "keywords": [
            "aaa new-model",
            "aaa authentication",
            "centralized authentication",
            "login authentication",
        ],
        "expected_value": True,
    },
    "management.enable_secret": {
        "category": "Authentication",
        "keywords": [
            "enable secret",
            "administrator secret",
            "privileged password",
        ],
        "expected_value": True,
    },
    "remote_access.ssh_enabled": {
        "category": "Remote Access",
        "keywords": [
            "ssh server enable",
            "service ssh",
            "ip ssh",
            "secure shell",
            "secure remote access",
        ],
        "expected_value": True,
    },
    "remote_access.telnet_enabled": {
        "category": "Remote Access",
        "keywords": [
            "telnet server enable",
            "transport input telnet",
            "telnet",
            "unencrypted remote access",
            "remote access via telnet",
        ],
        "expected_value": True,
    },
    "logging.local_buffered_logging": {
        "category": "Logging",
        "keywords": [
            "logging buffered",
            "local logging",
            "buffered logging",
            "log buffer",
        ],
        "expected_value": True,
    },
    "logging.remote_syslog": {
        "category": "Logging",
        "keywords": [
            "remote syslog",
            "syslog server",
            "remote logging",
            "remote log server",
            "syslog",
        ],
        "expected_value": True,
    },
    "logging.timestamps": {
        "category": "Logging",
        "keywords": [
            "service timestamps log",
            "log timestamp",
            "log timestamps",
            "timestamps",
        ],
        "expected_value": True,
    },
    "crypto.password_encryption": {
        "category": "Cryptography",
        "keywords": [
            "service password-encryption",
            "password encryption",
            "encrypted password",
            "password encrypt",
        ],
        "expected_value": True,
    },
    "access_control.standard_acls": {
        "category": "Access Control",
        "keywords": [
            "standard access-list",
            "standard acl",
            "access control list",
            "traffic filtering",
        ],
        "expected_value": True,
    },
}


# Medium/high confidence threshold used by the AI ingestion layer.
HIGH_CONFIDENCE_THRESHOLD = 0.85
MEDIUM_CONFIDENCE_THRESHOLD = 0.65


def _normalize(text: str) -> str:
    """Normalize configuration text for semantic matching."""
    return re.sub(r"\s+", " ", text.lower()).strip()


def _keyword_score(
    text: str,
    keywords: list[str],
) -> tuple[float, list[str]]:
    """
    Calculate semantic confidence using two levels:

    1. Exact technical phrase matching.
    2. Token-level semantic matching when the exact phrase is
       not present.

    Exact technical phrases receive high confidence.
    Related token combinations receive medium confidence so
    they can be reviewed through Human Training.
    """

    normalized = _normalize(text)

    if not normalized:
        return 0.0, []

    # ---------------------------------------------------------------
    # Level 1: Exact technical phrase matching
    # ---------------------------------------------------------------
    matched_keywords = [
        keyword
        for keyword in keywords
        if keyword.lower() in normalized
    ]

    if matched_keywords:
        longest_match = max(
            matched_keywords,
            key=len,
        )

        word_count = len(longest_match.split())

        if word_count >= 3:
            score = 0.95
        elif word_count == 2:
            score = 0.90
        else:
            score = 0.75

        return score, matched_keywords

    # ---------------------------------------------------------------
    # Level 2: Token-level semantic matching
    # ---------------------------------------------------------------
    text_tokens = set(
        re.findall(r"[a-z0-9]+", normalized)
    )

    best_overlap = 0
    best_keywords: list[str] = []

    for keyword in keywords:
        keyword_tokens = set(
            re.findall(
                r"[a-z0-9]+",
                keyword.lower(),
            )
        )

        overlap = len(
            text_tokens.intersection(keyword_tokens)
        )

        if overlap > best_overlap:
            best_overlap = overlap
            best_keywords = [keyword]
        elif (
            overlap > 0
            and overlap == best_overlap
        ):
            best_keywords.append(keyword)

    # A single generic word is not enough to infer a
    # security meaning.
    if best_overlap < 2:
        return 0.0, []

    semantic_evidence = []

    for keyword in best_keywords:
        keyword_tokens = set(
            re.findall(
                r"[a-z0-9]+",
                keyword.lower(),
            )
        )

        overlapping_tokens = sorted(
            text_tokens.intersection(keyword_tokens)
        )

        if overlapping_tokens:
            semantic_evidence.append(
                "Semantic token overlap: "
                + ", ".join(overlapping_tokens)
                + f" (related keyword: {keyword})"
            )
    if best_overlap >= 4:
        score = 0.80
    elif best_overlap == 3:
        score = 0.75
    else:
        score = 0.70

    return score, semantic_evidence


def _infer_expected_value(
    configuration_line: str,
    default_value: Any,
) -> Any:
    """
    Infer whether a configuration line explicitly enables or disables
    a security control.

    This prevents negative syntax such as 'no service ssh' or
    'undo telnet server enable' from automatically being treated
    as a positive configuration.
    """

    normalized = _normalize(configuration_line)

    negative_prefixes = (
        "no ",
        "undo ",
        "disable ",
        "disabled ",
    )

    if normalized.startswith(negative_prefixes):
        return False

    if " disable" in normalized or normalized.endswith(" disabled"):
        return False

    return default_value


def _learned_mapping_match(
    configuration_line: str,
) -> dict[str, Any] | None:
    """
    Match a configuration line against administrator-approved
    learned mappings stored in PostgreSQL.

    The longest matching learned pattern wins. Confidence is preserved
    from the administrator-approved mapping.
    """

    normalized_line = _normalize(configuration_line)

    if not normalized_line:
        return None

    db = SessionLocal()

    try:
        mappings = db.scalars(
            select(LearnedMapping).where(
                LearnedMapping.is_active.is_(True)
            )
        ).all()

        candidates = []

        for mapping in mappings:
            pattern = _normalize(
                mapping.configuration_pattern
            )

            if pattern and pattern in normalized_line:
                candidates.append(
                    {
                        "mapping": mapping,
                        "pattern_length": len(pattern),
                    }
                )

        if not candidates:
            return None

        candidates.sort(
            key=lambda item: (
                item["pattern_length"],
                item["mapping"].confidence,
            ),
            reverse=True,
        )

        best_mapping = candidates[0]["mapping"]

        expected_value = best_mapping.expected_value

        if isinstance(expected_value, str):
            expected_value = expected_value.strip().lower() == "true"

        return {
            "matched": True,
            "parameter": best_mapping.baseline_parameter,
            "category": best_mapping.security_category,
            "expected_value": expected_value,
            "confidence": float(best_mapping.confidence),
            "confidence_level": "HIGH",
            "evidence": [
                "Administrator-approved learned mapping",
                (
                    "Learned pattern: "
                    f"{best_mapping.configuration_pattern}"
                ),
            ],
            "requires_human_training": False,
            "source": "learned_mapping",
            "learned_mapping_id": best_mapping.id,
        }

    finally:
        db.close()


def semantic_match(
    configuration_line: str,
) -> dict[str, Any]:
    """
    Map an unsupported configuration line to a security baseline
    parameter using learned mappings and semantic matching.
    """

    if not configuration_line or not configuration_line.strip():
        return {
            "matched": False,
            "parameter": None,
            "category": None,
            "expected_value": None,
            "confidence": 0.0,
            "confidence_level": "LOW",
            "evidence": [],
            "requires_human_training": True,
            "source": "semantic_nlp",
        }

    # Administrator-approved mappings always take precedence.
    learned_result = _learned_mapping_match(
        configuration_line
    )

    if learned_result:
        return learned_result

    candidates: list[dict[str, Any]] = []

    for parameter, semantic in SECURITY_SEMANTICS.items():
        score, matched_keywords = _keyword_score(
            configuration_line,
            semantic["keywords"],
        )

        if score <= 0:
            continue

        expected_value = _infer_expected_value(
            configuration_line,
            semantic["expected_value"],
        )

        candidates.append(
            {
                "parameter": parameter,
                "category": semantic["category"],
                "expected_value": expected_value,
                "confidence": score,
                "evidence": matched_keywords,
            }
        )

    if not candidates:
        return {
            "matched": False,
            "parameter": None,
            "category": None,
            "expected_value": None,
            "confidence": 0.0,
            "confidence_level": "LOW",
            "evidence": [
                "No semantic security meaning detected"
            ],
            "requires_human_training": True,
            "source": "semantic_nlp",
        }

    # Highest confidence wins.
    candidates.sort(
        key=lambda item: item["confidence"],
        reverse=True,
    )

    best = candidates[0]
    confidence = float(best["confidence"])

    if confidence >= HIGH_CONFIDENCE_THRESHOLD:
        confidence_level = "HIGH"
        requires_human_training = False
    elif confidence >= MEDIUM_CONFIDENCE_THRESHOLD:
        confidence_level = "MEDIUM"
        requires_human_training = True
    else:
        confidence_level = "LOW"
        requires_human_training = True

    return {
        "matched": True,
        "parameter": best["parameter"],
        "category": best["category"],
        "expected_value": best["expected_value"],
        "confidence": confidence,
        "confidence_level": confidence_level,
        "evidence": best["evidence"],
        "requires_human_training": requires_human_training,
        "source": "semantic_nlp",
    }


def analyze_unknown_configuration(
    unknown_lines: list[str],
) -> dict[str, Any]:
    """
    Analyze multiple unsupported or unknown configuration lines.
    """

    results = []

    for line in unknown_lines:
        result = semantic_match(line)

        results.append(
            {
                "configuration_line": line,
                **result,
            }
        )

    high_confidence = sum(
        1
        for result in results
        if result["confidence_level"] == "HIGH"
    )

    training_required = sum(
        1
        for result in results
        if result["requires_human_training"]
    )

    return {
        "engine": "semantic_nlp",
        "total_lines": len(results),
        "high_confidence_matches": high_confidence,
        "training_required": training_required,
        "results": results,
    }