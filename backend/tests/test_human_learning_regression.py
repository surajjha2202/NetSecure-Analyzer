from unittest.mock import patch

from app.services.ai_ingestion import semantic_match
from app.services.security_baseline import build_security_baseline


def test_unknown_line_requires_human_training():
    result = semantic_match("custom-security-feature")

    assert result["matched"] is False
    assert result["requires_human_training"] is True
    assert result["confidence_level"] == "LOW"
    assert result["source"] == "semantic_nlp"


def test_semantic_match_without_learned_mapping_requires_training():
    with patch(
        "app.services.ai_ingestion._learned_mapping_match",
        return_value=None,
    ):
        result = semantic_match("syslog")

    assert result["matched"] is True
    assert result["parameter"] == "logging.remote_syslog"
    assert result["expected_value"] is True
    assert result["confidence"] == 0.75
    assert result["confidence_level"] == "MEDIUM"
    assert result["requires_human_training"] is True
    assert result["source"] == "semantic_nlp"


def test_negative_syntax_is_inferred_as_false():
    with patch(
        "app.services.ai_ingestion._learned_mapping_match",
        return_value=None,
    ):
        result = semantic_match(
            "no service password-encryption"
        )

    assert result["matched"] is True
    assert result["parameter"] == "crypto.password_encryption"
    assert result["expected_value"] is False


def test_approved_learned_mapping_overrides_semantic_match():
    learned_result = {
        "matched": True,
        "parameter": "logging.remote_syslog",
        "category": "Logging",
        "expected_value": True,
        "confidence": 1.0,
        "confidence_level": "HIGH",
        "evidence": [
            "Administrator-approved learned mapping",
            "Learned pattern: custom-syslog",
        ],
        "requires_human_training": False,
        "source": "learned_mapping",
        "learned_mapping_id": 999,
    }

    with patch(
        "app.services.ai_ingestion._learned_mapping_match",
        return_value=learned_result,
    ):
        result = semantic_match(
            "custom-syslog 10.10.10.50"
        )

    assert result["matched"] is True
    assert result["parameter"] == "logging.remote_syslog"
    assert result["expected_value"] is True
    assert result["confidence"] == 1.0
    assert result["confidence_level"] == "HIGH"
    assert result["requires_human_training"] is False
    assert result["source"] == "learned_mapping"
    assert result["learned_mapping_id"] == 999


def test_inactive_or_unmatched_mapping_falls_back_to_semantic_nlp():
    with patch(
        "app.services.ai_ingestion._learned_mapping_match",
        return_value=None,
    ):
        result = semantic_match("syslog")

    assert result["source"] == "semantic_nlp"
    assert result["parameter"] == "logging.remote_syslog"
    assert result["requires_human_training"] is True


def test_learned_result_feeds_security_baseline():
    learned_result = {
        "matched": True,
        "parameter": "logging.remote_syslog",
        "category": "Logging",
        "expected_value": True,
        "confidence": 1.0,
        "confidence_level": "HIGH",
        "evidence": [
            "Administrator-approved learned mapping"
        ],
        "requires_human_training": False,
        "source": "learned_mapping",
        "learned_mapping_id": 999,
    }

    with patch(
        "app.services.ai_ingestion._learned_mapping_match",
        return_value=learned_result,
    ):
        semantic_result = semantic_match(
            "custom remote logger 10.10.10.50"
        )

    assert semantic_result["parameter"] == (
        "logging.remote_syslog"
    )
    assert semantic_result["expected_value"] is True

    parsed_configuration = {
        "vendor": "Unknown",
        "security_parameters": {
            "logging": {
                "remote_syslog": semantic_result[
                    "expected_value"
                ],
            }
        },
    }

    baseline = build_security_baseline(
        parsed_configuration
    )

    assert baseline["logging"]["remote_syslog"] is True
