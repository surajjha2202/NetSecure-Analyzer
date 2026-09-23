import sys
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

# ---------------------------------------------------------------------------
# Make the backend package importable when this file is executed directly.
# ---------------------------------------------------------------------------

BACKEND_DIR = Path(__file__).resolve().parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


# ---------------------------------------------------------------------------
# Test database
# ---------------------------------------------------------------------------

TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestSessionLocal = sessionmaker(
    bind=test_engine,
    autoflush=False,
    autocommit=False,
)


# ---------------------------------------------------------------------------
# Import application after the test engine is prepared.
# ---------------------------------------------------------------------------

from app.db.database import Base
from app.main import app
from app.models import Permission, Role, User
from app.services.security import hash_password


# ---------------------------------------------------------------------------
# Test configurations
# ---------------------------------------------------------------------------

SECURE_CISCO_CONFIGURATION = """version 17.15
hostname MULTI-FRAMEWORK-SECURE
aaa new-model
enable secret 0 strong-test-secret
ip ssh version 2
line vty 0 4
 transport input ssh
logging buffered 16384
logging 10.0.0.10
service timestamps log datetime msec
service password-encryption
"""

INSECURE_CISCO_CONFIGURATION = """version 17.15
hostname MULTI-FRAMEWORK-INSECURE
enable password weak-password
line vty 0 4
 transport input telnet
"""


FRAMEWORKS = [
    "CIS",
    "NIST",
    "DISA_STIG",
    "ISO_27001",
]

EXPECTED_RULE_COUNTS = {
    "CIS": 8,
    "NIST": 4,
    "DISA_STIG": 4,
    "ISO_27001": 4,
}


# ---------------------------------------------------------------------------
# Test database setup
# ---------------------------------------------------------------------------

def setup_test_database():
    Base.metadata.create_all(test_engine)

    db = TestSessionLocal()

    try:
        upload_permission = Permission(
            name="configs.upload",
            description="Upload configurations",
        )

        view_permission = Permission(
            name="configs.view",
            description="View and analyze configurations",
        )

        db.add_all([
            upload_permission,
            view_permission,
        ])

        db.flush()

        role = Role(
            name="MULTI_FRAMEWORK_REGRESSION",
            description="Temporary multi-framework API regression role",
        )

        role.permissions.extend([
            upload_permission,
            view_permission,
        ])

        db.add(role)
        db.flush()

        user = User(
            username="multiframework_regression",
            email="multiframework_regression@test.local",
            password_hash=hash_password(
                "RegressionPassword123!"
            ),
            role_id=role.id,
            is_active=True,
        )

        db.add(user)
        db.commit()

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Patch every production SessionLocal reference used by the API path.
# ---------------------------------------------------------------------------

def patch_session_locals():
    return [
        patch(
            "app.api.configurations.SessionLocal",
            TestSessionLocal,
        ),
        patch(
            "app.services.permission_dependency.SessionLocal",
            TestSessionLocal,
        ),
        patch(
            "app.services.auth_dependency.SessionLocal",
            TestSessionLocal,
        ),
        patch(
            "app.api.auth.SessionLocal",
            TestSessionLocal,
        ),
    ]


# ---------------------------------------------------------------------------
# Login helper
# ---------------------------------------------------------------------------

def login(client: TestClient) -> dict:
    response = client.post(
        "/api/auth/login",
        json={
            "username": "multiframework_regression",
            "password": "RegressionPassword123!",
        },
    )

    assert response.status_code == 200, (
        f"Authentication failed: "
        f"{response.status_code} {response.text}"
    )

    token = response.json().get("access_token")

    assert token, "Authentication response did not contain access_token."

    return {
        "Authorization": f"Bearer {token}",
    }


# ---------------------------------------------------------------------------
# Upload helper
# ---------------------------------------------------------------------------

def upload_configuration(
    client: TestClient,
    headers: dict,
    filename: str,
    configuration: str,
) -> int:

    # Deliberately include a UTF-8 BOM to preserve the parser regression
    # coverage already established in the 15-vendor test.
    bom_configuration = "\ufeff" + configuration

    response = client.post(
        "/api/configurations/upload",
        headers=headers,
        files={
            "file": (
                filename,
                bom_configuration.encode("utf-8"),
                "text/plain",
            )
        },
    )

    assert response.status_code == 200, (
        f"Upload failed: "
        f"{response.status_code} {response.text}"
    )

    configuration_id = response.json().get("id")

    assert configuration_id is not None

    return configuration_id


# ---------------------------------------------------------------------------
# Validate framework result structure
# ---------------------------------------------------------------------------

def validate_framework_results(
    framework_results: dict,
):
    assert isinstance(
        framework_results,
        dict,
    )

    assert set(framework_results.keys()) == set(
        FRAMEWORKS
    )

    for framework in FRAMEWORKS:
        result = framework_results[framework]

        assert result["framework"] == framework

        assert result["total_rules"] == (
            EXPECTED_RULE_COUNTS[framework]
        )

        assert isinstance(
            result.get("results"),
            list,
        )

        assert len(result["results"]) == (
            EXPECTED_RULE_COUNTS[framework]
        )

        for rule_result in result["results"]:
            assert "rule_id" in rule_result
            assert "framework" in rule_result
            assert "title" in rule_result
            assert "severity" in rule_result
            assert "baseline_path" in rule_result
            assert "expected_value" in rule_result
            assert "actual_value" in rule_result
            assert "status" in rule_result
            assert "confidence" in rule_result
            assert "evidence" in rule_result

            assert rule_result["framework"] == framework

            assert rule_result["status"] in {
                "PASS",
                "FAIL",
                "N/A",
            }


# ---------------------------------------------------------------------------
# Main regression
# ---------------------------------------------------------------------------

def main():

    print("=" * 110)
    print("MULTI-FRAMEWORK API END-TO-END REGRESSION")
    print("=" * 110)

    setup_test_database()

    session_patches = patch_session_locals()

    for session_patch in session_patches:
        session_patch.start()

    try:
        client = TestClient(app)

        # ---------------------------------------------------------------
        # Authentication
        # ---------------------------------------------------------------

        headers = login(client)

        print("Authentication: PASS")
        print("-" * 110)

        # ===============================================================
        # SECURE CONFIGURATION
        # ===============================================================

        print()
        print("SECURE CIS CONFIGURATION")
        print("-" * 110)

        secure_id = upload_configuration(
            client,
            headers,
            "multi_framework_secure.cfg",
            SECURE_CISCO_CONFIGURATION,
        )

        secure_response = client.post(
            f"/api/configurations/"
            f"{secure_id}/analyze",
            headers=headers,
            params=[
                ("frameworks", "CIS"),
                ("frameworks", "NIST"),
                ("frameworks", "DISA_STIG"),
                ("frameworks", "ISO_27001"),
            ],
        )

        assert secure_response.status_code == 200, (
            f"Secure analysis failed: "
            f"{secure_response.status_code} "
            f"{secure_response.text}"
        )

        secure_result = secure_response.json()

        # ---------------------------------------------------------------
        # Selected frameworks
        # ---------------------------------------------------------------

        selected_frameworks = secure_result.get(
            "selected_frameworks"
        )

        assert selected_frameworks == FRAMEWORKS

        print(
            f"Selected frameworks: "
            f"{selected_frameworks}"
        )

        # ---------------------------------------------------------------
        # Individual framework results
        # ---------------------------------------------------------------

        secure_framework_results = secure_result.get(
            "framework_results",
            {},
        )

        validate_framework_results(
            secure_framework_results
        )

        for framework in FRAMEWORKS:
            framework_result = secure_framework_results[
                framework
            ]

            assert framework_result["pass_count"] == (
                EXPECTED_RULE_COUNTS[framework]
            )

            assert framework_result["fail_count"] == 0
            assert framework_result["na_count"] == 0
            assert framework_result[
                "compliance_percentage"
            ] == 100.0

            print(
                f"{framework:<15} "
                f"RULES={framework_result['total_rules']:<3} "
                f"PASS={framework_result['pass_count']:<3} "
                f"FAIL={framework_result['fail_count']:<3} "
                f"COMPLIANCE="
                f"{framework_result['compliance_percentage']:.2f}% "
                f"PASS"
            )

        # ---------------------------------------------------------------
        # Combined compliance
        # ---------------------------------------------------------------

        secure_compliance = secure_result.get(
            "compliance",
            {},
        )

        expected_total_rules = sum(
            EXPECTED_RULE_COUNTS.values()
        )

        assert secure_compliance["framework"] == "MULTI"
        assert secure_compliance["total_rules"] == (
            expected_total_rules
        )
        assert secure_compliance["pass_count"] == (
            expected_total_rules
        )
        assert secure_compliance["fail_count"] == 0
        assert secure_compliance["na_count"] == 0
        assert secure_compliance[
            "compliance_percentage"
        ] == 100.0

        print(
            f"COMBINED        "
            f"RULES={secure_compliance['total_rules']:<3} "
            f"PASS={secure_compliance['pass_count']:<3} "
            f"FAIL={secure_compliance['fail_count']:<3} "
            f"COMPLIANCE="
            f"{secure_compliance['compliance_percentage']:.2f}% "
            f"PASS"
        )

        # ---------------------------------------------------------------
        # Secure risk
        # ---------------------------------------------------------------

        secure_risk = secure_result.get(
            "risk",
            {},
        )

        assert secure_risk["risk_score"] == 0.0
        assert secure_risk["risk_level"] == "MINIMAL"
        assert secure_risk["total_findings"] == 0
        assert secure_risk["critical_findings"] == 0

        print(
            "SECURE RISK     "
            "SCORE=0.00 "
            "LEVEL=MINIMAL "
            "FINDINGS=0 PASS"
        )

        # ---------------------------------------------------------------
        # Secure remediation
        # ---------------------------------------------------------------

        secure_remediation = secure_result.get(
            "remediation",
            {},
        )

        assert secure_remediation["vendor"] == "Cisco"
        assert secure_remediation[
            "total_remediations"
        ] == 0
        assert secure_remediation[
            "available_remediations"
        ] == 0
        assert secure_remediation[
            "unavailable_remediations"
        ] == 0

        print(
            "SECURE REMEDIATION "
            "REQUIRED=0 PASS"
        )

        # ===============================================================
        # INSECURE CONFIGURATION
        # ===============================================================

        print()
        print("INSECURE CIS CONFIGURATION")
        print("-" * 110)

        insecure_id = upload_configuration(
            client,
            headers,
            "multi_framework_insecure.cfg",
            INSECURE_CISCO_CONFIGURATION,
        )

        insecure_response = client.post(
            f"/api/configurations/"
            f"{insecure_id}/analyze",
            headers=headers,
            params=[
                ("frameworks", "CIS"),
                ("frameworks", "NIST"),
                ("frameworks", "DISA_STIG"),
                ("frameworks", "ISO_27001"),
            ],
        )

        assert insecure_response.status_code == 200, (
            f"Insecure analysis failed: "
            f"{insecure_response.status_code} "
            f"{insecure_response.text}"
        )

        insecure_result = insecure_response.json()

        # ---------------------------------------------------------------
        # Selected frameworks
        # ---------------------------------------------------------------

        assert insecure_result[
            "selected_frameworks"
        ] == FRAMEWORKS

        # ---------------------------------------------------------------
        # Individual framework results
        # ---------------------------------------------------------------

        insecure_framework_results = (
            insecure_result.get(
                "framework_results",
                {},
            )
        )

        validate_framework_results(
            insecure_framework_results
        )

        total_failed_framework_rules = 0

        for framework in FRAMEWORKS:
            framework_result = (
                insecure_framework_results[
                    framework
                ]
            )

            assert framework_result[
                "fail_count"
            ] > 0

            assert framework_result[
                "compliance_percentage"
            ] < 100.0

            total_failed_framework_rules += (
                framework_result["fail_count"]
            )

            print(
                f"{framework:<15} "
                f"RULES={framework_result['total_rules']:<3} "
                f"PASS={framework_result['pass_count']:<3} "
                f"FAIL={framework_result['fail_count']:<3} "
                f"COMPLIANCE="
                f"{framework_result['compliance_percentage']:.2f}% "
                f"PASS"
            )

        # ---------------------------------------------------------------
        # Combined compliance
        # ---------------------------------------------------------------

        insecure_compliance = (
            insecure_result.get(
                "compliance",
                {},
            )
        )

        assert insecure_compliance[
            "framework"
        ] == "MULTI"

        assert insecure_compliance[
            "total_rules"
        ] == expected_total_rules

        assert insecure_compliance[
            "fail_count"
        ] == total_failed_framework_rules

        assert insecure_compliance[
            "fail_count"
        ] > 0

        assert insecure_compliance[
            "compliance_percentage"
        ] < 100.0

        print(
            f"COMBINED        "
            f"RULES={insecure_compliance['total_rules']:<3} "
            f"PASS={insecure_compliance['pass_count']:<3} "
            f"FAIL={insecure_compliance['fail_count']:<3} "
            f"COMPLIANCE="
            f"{insecure_compliance['compliance_percentage']:.2f}% "
            f"PASS"
        )

        # ---------------------------------------------------------------
        # Risk deduplication
        # ---------------------------------------------------------------

        insecure_risk = insecure_result.get(
            "risk",
            {},
        )

        assert insecure_risk["risk_score"] > 0
        assert insecure_risk["total_findings"] > 0
        assert insecure_risk["critical_findings"] > 0

        # Multiple frameworks may report the same underlying
        # technical weakness. Risk must therefore be based on
        # unique canonical controls rather than raw framework
        # failure count.
        assert insecure_risk[
            "total_findings"
        ] < total_failed_framework_rules

        print(
            "RISK DEDUP      "
            f"FRAMEWORK FAILURES="
            f"{total_failed_framework_rules} "
            f"→ UNIQUE FINDINGS="
            f"{insecure_risk['total_findings']} "
            f"PASS"
        )

        print(
            "RISK SCORE      "
            f"{insecure_risk['risk_score']:.2f} "
            f"{insecure_risk['risk_level']} "
            f"PASS"
        )

        # ---------------------------------------------------------------
        # Remediation deduplication
        # ---------------------------------------------------------------

        insecure_remediation = (
            insecure_result.get(
                "remediation",
                {},
            )
        )

        assert insecure_remediation[
            "vendor"
        ] == "Cisco"

        assert insecure_remediation[
            "total_remediations"
        ] > 0

        commands = insecure_remediation.get(
            "commands",
            [],
        )

        assert isinstance(commands, list)

        # Commands must be unique at the executable level.
        assert len(commands) == len(
            set(commands)
        )

        print(
            "REMEDIATION     "
            f"FINDINGS="
            f"{insecure_remediation['total_remediations']} "
            f"COMMANDS="
            f"{len(commands)} "
            f"UNIQUE PASS"
        )

        # ---------------------------------------------------------------
        # Evidence / actual values
        # ---------------------------------------------------------------

        evidence_count = 0

        for framework_result in (
            insecure_framework_results.values()
        ):
            for rule_result in framework_result.get(
                "results",
                [],
            ):
                if rule_result["status"] == "FAIL":
                    assert "actual_value" in rule_result
                    assert "expected_value" in rule_result
                    assert "evidence" in rule_result

                    evidence_count += 1

        assert evidence_count == total_failed_framework_rules

        print(
            "EVIDENCE        "
            f"{evidence_count} FAILED RULES "
            "WITH ACTUAL/EXPECTED/EVIDENCE PASS"
        )

        # ===============================================================
        # ALIAS API TEST
        # ===============================================================

        print()
        print("FRAMEWORK ALIAS API TEST")
        print("-" * 110)

        alias_id = upload_configuration(
            client,
            headers,
            "multi_framework_alias.cfg",
            SECURE_CISCO_CONFIGURATION,
        )

        alias_response = client.post(
            f"/api/configurations/"
            f"{alias_id}/analyze",
            headers=headers,
            params=[
                ("frameworks", "CIS"),
                ("frameworks", "NIST"),
                ("frameworks", "STIG"),
                ("frameworks", "ISO/IEC 27001"),
            ],
        )

        assert alias_response.status_code == 200, (
            f"Alias API request failed: "
            f"{alias_response.status_code} "
            f"{alias_response.text}"
        )

        alias_result = alias_response.json()

        assert alias_result[
            "selected_frameworks"
        ] == [
            "CIS",
            "NIST",
            "DISA_STIG",
            "ISO_27001",
        ]

        print(
            "CIS              -> CIS: PASS"
        )
        print(
            "NIST             -> NIST: PASS"
        )
        print(
            "STIG             -> DISA_STIG: PASS"
        )
        print(
            "ISO/IEC 27001    -> ISO_27001: PASS"
        )

        # ===============================================================
        # FINAL RESULT
        # ===============================================================

        print()
        print("=" * 110)
        print(
            "MULTI-FRAMEWORK API RESULT: PASS"
        )
        print("=" * 110)

        return 0

    except AssertionError as exc:
        print()
        print("=" * 110)
        print("MULTI-FRAMEWORK API RESULT: FAIL")
        print("=" * 110)
        print(f"ASSERTION: {exc}")
        return 1

    except Exception as exc:
        print()
        print("=" * 110)
        print("MULTI-FRAMEWORK API RESULT: ERROR")
        print("=" * 110)
        print(
            f"{type(exc).__name__}: {exc}"
        )
        return 1

    finally:
        for session_patch in reversed(
            session_patches
        ):
            session_patch.stop()


if __name__ == "__main__":
    raise SystemExit(main())