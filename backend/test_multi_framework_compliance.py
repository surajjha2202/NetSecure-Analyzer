from __future__ import annotations

from app.services.framework_rules import get_framework_rules
from app.services.compliance_engine import evaluate_compliance
from app.services.risk_engine import calculate_risk


FRAMEWORKS = [
    "CIS",
    "NIST",
    "DISA_STIG",
    "ISO_27001",
]


SECURE_BASELINE = {
    "authentication": {
        "aaa_new_model": True,
    },
    "management": {
        "enable_secret": True,
    },
    "remote_access": {
        "ssh_enabled": True,
        "telnet_enabled": False,
    },
    "logging": {
        "local_buffered_logging": True,
        "timestamps": True,
    },
    "crypto": {
        "password_encryption": True,
    },
    "monitoring": {
        "logging_configured": True,
    },
    "access_control": {
        "standard_acls": 0,
    },
}


INSECURE_BASELINE = {
    "authentication": {
        "aaa_new_model": False,
    },
    "management": {
        "enable_secret": False,
    },
    "remote_access": {
        "ssh_enabled": False,
        "telnet_enabled": True,
    },
    "logging": {
        "local_buffered_logging": False,
        "timestamps": False,
    },
    "crypto": {
        "password_encryption": False,
    },
    "monitoring": {
        "logging_configured": False,
    },
    "access_control": {
        "standard_acls": 2,
    },
}


def run_framework_test(
    framework: str,
    baseline: dict,
) -> dict:
    rules = get_framework_rules(framework)

    assert rules, f"No rules found for {framework}"

    result = evaluate_compliance(
        baseline,
        rules,
    )

    assert result["framework"] == framework
    assert result["total_rules"] == len(rules)

    for item in result["results"]:
        assert "rule_id" in item
        assert "framework" in item
        assert "expected_value" in item
        assert "actual_value" in item
        assert "baseline_path" in item
        assert "evidence" in item
        assert item["status"] in {
            "PASS",
            "FAIL",
            "N/A",
        }

    return result


def main() -> None:
    print("=" * 100)
    print("MULTI-FRAMEWORK COMPLIANCE REGRESSION")
    print("=" * 100)

    print("\nSECURE BASELINE")
    print("-" * 100)

    for framework in FRAMEWORKS:
        result = run_framework_test(
            framework,
            SECURE_BASELINE,
        )

        print(
            f"{framework:<15} "
            f"PASS={result['pass_count']:<3} "
            f"FAIL={result['fail_count']:<3} "
            f"N/A={result['na_count']:<3} "
            f"COMPLIANCE={result['compliance_percentage']:>6.2f}%"
        )

        assert result["fail_count"] == 0
        assert result["na_count"] == 0
        assert result["compliance_percentage"] == 100.0

    print("\nINSECURE BASELINE")
    print("-" * 100)

    for framework in FRAMEWORKS:
        result = run_framework_test(
            framework,
            INSECURE_BASELINE,
        )

        risk = calculate_risk(result)

        print(
            f"{framework:<15} "
            f"PASS={result['pass_count']:<3} "
            f"FAIL={result['fail_count']:<3} "
            f"N/A={result['na_count']:<3} "
            f"COMPLIANCE={result['compliance_percentage']:>6.2f}% "
            f"RISK={risk['risk_score']:>6.2f} "
            f"{risk['risk_level']}"
        )

        assert result["fail_count"] > 0
        assert result["compliance_percentage"] < 100.0
        assert risk["risk_score"] > 0
        assert risk["total_findings"] == result["fail_count"]

    print("\nALIAS TEST")
    print("-" * 100)

    assert len(get_framework_rules("ISO/IEC 27001")) == 4
    assert len(get_framework_rules("ISO 27001")) == 4
    assert len(get_framework_rules("STIG")) == 4
    assert len(get_framework_rules("DISA STIG")) == 4

    print("ISO/IEC 27001  -> ISO_27001: PASS")
    print("ISO 27001      -> ISO_27001: PASS")
    print("STIG           -> DISA_STIG: PASS")
    print("DISA STIG      -> DISA_STIG: PASS")

    print("\n" + "=" * 100)
    print("MULTI-FRAMEWORK RESULT: PASS")
    print("=" * 100)


if __name__ == "__main__":
    main()