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
# 15-vendor API fixtures
# ---------------------------------------------------------------------------

SAMPLES = {
    "Cisco": """version 17.15
hostname CISCO-TEST
aaa new-model
enable secret 0 test
ip ssh version 2
service timestamps log datetime msec
service password-encryption""",

    "Fortinet": """config system global
set hostname FortiGate-Test
end""",

    "Juniper": """set system host-name JUNOS-TEST
set system services ssh
set system syslog file messages any any""",

    "Arista": """hostname ARISTA-TEST
management api http-commands
router bgp 65001""",

    "Aruba": """hostname ARUBA-TEST
ssh server vrf default
vlan 10""",

    "MikroTik": """/system identity set name=MIKROTIK-TEST
/ip service
set ssh disabled=no
set telnet disabled=yes""",

    "Huawei": """sysname HUAWEI-TEST
stelnet server enable
undo telnet server enable""",

    "Nokia": """configure
system name NOKIA-TEST
configure system security ssh server""",

    "HPE Comware": """sysname HPE-COMWARE-TEST
ssh server enable
undo telnet server enable
port link-type trunk""",

    "Extreme Networks": """configure snmp add EXTREME-TEST
configure ssh2 enable""",

    "Dell Networking": """hostname DELL-OS10-TEST
interface ethernet1/1/1
 ip address 10.0.0.1/24""",

    "Palo Alto Networks": """<config>
<devices>
<entry name="localhost.localdomain">
<deviceconfig>
<system>
<hostname>PA-TEST</hostname>
</system>
</deviceconfig>
</entry>
</devices>
</config>""",

    "Check Point": """set hostname CHECKPOINT-TEST
set interface eth0 ipv4-address 10.0.0.1 mask-length 24
set static-route 0.0.0.0/0 nexthop gateway address 10.0.0.254""",

    "VyOS": """set system host-name VYOS-TEST
set service ssh
set interfaces ethernet eth0 address 10.0.0.1/24
commit""",

    "NVIDIA Cumulus": """nv set system hostname CUMULUS-TEST
nv set interface swp1 ip address 10.0.0.1/24
nv set interface swp1 link state up""",
}


EXPECTED_PARSERS = {
    "Cisco": "cisco_ios",
    "Fortinet": "fortinet",
    "Juniper": "juniper_junos",
    "Arista": "arista_eos",
    "Aruba": "aruba_aoscx",
    "MikroTik": "mikrotik_routeros",
    "Huawei": "huawei_vrp",
    "Nokia": "nokia_sros",
    "HPE Comware": "hp_comware",
    "Extreme Networks": "extreme_exos",
    "Dell Networking": "dell_os10",
    "Palo Alto Networks": "paloalto_panos",
    "Check Point": "checkpoint_gaia",
    "VyOS": "vyos",
    "NVIDIA Cumulus": "cumulus_linux",
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
            name="API_REGRESSION",
            description="Temporary API regression test role",
        )

        role.permissions.extend([
            upload_permission,
            view_permission,
        ])

        db.add(role)
        db.flush()

        user = User(
            username="api_regression",
            email="api_regression@test.local",
            password_hash=hash_password("RegressionPassword123!"),
            role_id=role.id,
            is_active=True,
        )

        db.add(user)
        db.commit()

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Patch every production SessionLocal reference that the API path uses.
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
# Main regression
# ---------------------------------------------------------------------------

def main():
    print("=" * 110)
    print("15-VENDOR FULL API END-TO-END REGRESSION")
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

        login_response = client.post(
            "/api/auth/login",
            json={
                "username": "api_regression",
                "password": "RegressionPassword123!",
            },
        )

        if login_response.status_code != 200:
            print("LOGIN: FAIL")
            print(login_response.text)
            return 1

        token = login_response.json()["access_token"]

        headers = {
            "Authorization": f"Bearer {token}",
        }

        print("Authentication: PASS")
        print("-" * 110)
        print(
            f"{'EXPECTED':<24}"
            f"{'DETECTED':<24}"
            f"{'CONF':<10}"
            f"{'PARSER':<22}"
            f"{'BASELINE':<24}"
            f"STATUS"
        )
        print("-" * 110)

        total = len(SAMPLES)
        passed = 0

        for expected_vendor, configuration in SAMPLES.items():
            filename = (
                expected_vendor.lower()
                .replace(" ", "_")
                .replace("-", "_")
                + ".cfg"
            )

            # Deliberately include a UTF-8 BOM.
            bom_configuration = "\ufeff" + configuration

            try:
                upload_response = client.post(
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

                if upload_response.status_code != 200:
                    print(
                        f"{expected_vendor:<24}"
                        f"{'UPLOAD ERROR':<24}"
                        f"{'-':<10}"
                        f"{'-':<22}"
                        f"{'-':<24}"
                        f"FAIL"
                    )
                    print(
                        f"  Upload HTTP "
                        f"{upload_response.status_code}: "
                        f"{upload_response.text}"
                    )
                    continue

                configuration_id = upload_response.json()["id"]

                analyze_response = client.post(
                    f"/api/configurations/"
                    f"{configuration_id}/analyze",
                    headers=headers,
                )

                if analyze_response.status_code != 200:
                    print(
                        f"{expected_vendor:<24}"
                        f"{'ANALYZE ERROR':<24}"
                        f"{'-':<10}"
                        f"{'-':<22}"
                        f"{'-':<24}"
                        f"FAIL"
                    )
                    print(
                        f"  Analyze HTTP "
                        f"{analyze_response.status_code}: "
                        f"{analyze_response.text}"
                    )
                    continue

                result = analyze_response.json()

                # -------------------------------------------------------
                # Device intelligence
                # -------------------------------------------------------

                device_intelligence = result.get(
                    "device_intelligence",
                    {},
                )

                detected_vendor = device_intelligence.get(
                    "vendor"
                )

                confidence = device_intelligence.get(
                    "confidence",
                    0.0,
                )

                # -------------------------------------------------------
                # Parser
                # -------------------------------------------------------

                parser = result.get("parser") or {}

                parser_name = parser.get("name")
                parser_status = parser.get("status")

                # -------------------------------------------------------
                # Security baseline
                # -------------------------------------------------------

                baseline = result.get(
                    "security_baseline",
                    {},
                )

                baseline_vendor = baseline.get(
                    "vendor"
                )

                # -------------------------------------------------------
                # Compliance
                # -------------------------------------------------------

                compliance = result.get(
                    "compliance",
                    {},
                )

                compliance_percentage = compliance.get(
                    "compliance_percentage"
                )

                # -------------------------------------------------------
                # Risk
                # -------------------------------------------------------

                risk = result.get(
                    "risk",
                    {},
                )

                risk_score = risk.get(
                    "risk_score"
                )

                # -------------------------------------------------------
                # Remediation
                # -------------------------------------------------------

                remediation = result.get(
                    "remediation",
                    {},
                )

                remediation_vendor = remediation.get(
                    "vendor"
                )

                # -------------------------------------------------------
                # Assertions
                # -------------------------------------------------------

                expected_parser = EXPECTED_PARSERS[
                    expected_vendor
                ]

                ok = (
                    detected_vendor == expected_vendor
                    and parser_name == expected_parser
                    and parser_status == "PARSED"
                    and baseline_vendor == expected_vendor
                    and remediation_vendor == expected_vendor
                    and isinstance(confidence, (int, float))
                    and confidence > 0.0
                    and compliance_percentage is not None
                    and risk_score is not None
                )

                if ok:
                    passed += 1

                print(
                    f"{expected_vendor:<24}"
                    f"{str(detected_vendor):<24}"
                    f"{str(confidence):<10}"
                    f"{str(parser_name):<22}"
                    f"{str(baseline_vendor):<24}"
                    f"{'PASS' if ok else 'FAIL'}"
                )

                if not ok:
                    print("  DETAILS:")
                    print(
                        f"    expected vendor     : "
                        f"{expected_vendor}"
                    )
                    print(
                        f"    detected vendor     : "
                        f"{detected_vendor}"
                    )
                    print(
                        f"    expected parser     : "
                        f"{expected_parser}"
                    )
                    print(
                        f"    actual parser       : "
                        f"{parser_name}"
                    )
                    print(
                        f"    parser status       : "
                        f"{parser_status}"
                    )
                    print(
                        f"    baseline vendor     : "
                        f"{baseline_vendor}"
                    )
                    print(
                        f"    remediation vendor  : "
                        f"{remediation_vendor}"
                    )
                    print(
                        f"    device confidence   : "
                        f"{confidence}"
                    )
                    print(
                        f"    compliance          : "
                        f"{compliance_percentage}"
                    )
                    print(
                        f"    risk score          : "
                        f"{risk_score}"
                    )

            except Exception as exc:
                print(
                    f"{expected_vendor:<24}"
                    f"{'EXCEPTION':<24}"
                    f"{'-':<10}"
                    f"{'-':<22}"
                    f"{'-':<24}"
                    f"FAIL"
                )
                print(
                    f"  {type(exc).__name__}: {exc}"
                )

        print()
        print("=" * 110)
        print(
            f"API END-TO-END RESULT: "
            f"{passed}/{total} PASSED"
        )
        print("=" * 110)

        return 0 if passed == total else 1

    finally:
        for session_patch in reversed(session_patches):
            session_patch.stop()


if __name__ == "__main__":
    raise SystemExit(main())
