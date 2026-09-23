from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.services.network_device_mapping import get_netmiko_device_type


client = TestClient(app)


def test_vendor_driver_mapping():
    expected = {
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

    for vendor, driver in expected.items():
        assert get_netmiko_device_type(vendor) == driver


def test_unknown_vendor_does_not_fallback_to_cisco():
    assert get_netmiko_device_type("Unknown Vendor") is None
    assert get_netmiko_device_type(None) is None


def test_live_scan_uses_vendor_driver_and_analysis_pipeline():
    """
    Verify the live-scan endpoint:
      1. Resolves the device's vendor to the correct Netmiko driver.
      2. Passes that driver to scan_ssh_device.
      3. Accepts multiple compliance frameworks.
      4. Normalizes framework aliases.
      5. Runs the production configuration analysis pipeline.
    """

    token_response = client.post(
        "/api/auth/login",
        json={
            "username": "admin",
            "password": "ChangeThisAdminPassword123!",
        },
    )

    assert token_response.status_code == 200, token_response.text

    token = token_response.json()["access_token"]

    headers = {
        "Authorization": f"Bearer {token}",
    }

    device_response = client.get(
        "/api/devices/2",
        headers=headers,
    )

    assert device_response.status_code == 200, device_response.text

    device = device_response.json()

    assert device["vendor"] == "Cisco"

    fake_configuration = """version 17.9
hostname LIVE-SCAN-TEST
aaa new-model
enable secret 5 TEST
ip ssh version 2
line vty 0 4
 transport input ssh
logging buffered 16384
logging 10.0.0.10
service timestamps log datetime msec
service password-encryption
access-list 10 permit 10.0.0.0 0.0.0.255
"""

    fake_scan_result = {
        "success": True,
        "hostname": "LIVE-SCAN-TEST#",
        "configuration": fake_configuration,
        "device_type": "cisco_ios",
    }

    with patch(
        "app.api.devices.scan_ssh_device",
        return_value=fake_scan_result,
    ) as mock_scan, patch(
        "app.api.devices.analyze_configuration_content"
    ) as mock_analysis:

        mock_analysis.return_value = {
            "device_intelligence": {
                "vendor": "Cisco",
                "product": "Catalyst 8000",
                "platform": "IOS-XE",
                "model": "C8000V",
                "firmware": "17.9",
                "serial_number": "TEST-SERIAL",
                "device_type": "router",
            },
            "parser": {
                "type": "vendor_specific",
                "name": "cisco_ios",
                "status": "PARSED",
            },
            "security_baseline": {},
            "compliance": {
                "framework": "MULTI",
                "compliance_percentage": 100.0,
            },
            "framework_results": {
                "CIS": {
                    "compliance_percentage": 100.0,
                },
                "NIST": {
                    "compliance_percentage": 100.0,
                },
                "DISA_STIG": {
                    "compliance_percentage": 100.0,
                },
                "ISO_27001": {
                    "compliance_percentage": 100.0,
                },
            },
            "selected_frameworks": [
                "CIS",
                "NIST",
                "DISA_STIG",
                "ISO_27001",
            ],
            "risk": {
                "risk_score": 0.0,
                "risk_level": "MINIMAL",
                "critical_findings": 0,
                "findings": [],
            },
            "remediation": [],
        }

        response = client.post(
            "/api/devices/2/scan",
            headers=headers,
            json={
                "username": "test-user",
                "password": "test-password",
                "port": 22,
                "frameworks": [
                    "CIS",
                    "NIST",
                    "DISA STIG",
                    "ISO/IEC 27001",
                ],
            },
        )

    assert response.status_code == 200, response.text

    body = response.json()

    assert body["status"] == "SUCCESS"
    assert body["netmiko_device_type"] == "cisco_ios"

    assert body["selected_frameworks"] == [
        "CIS",
        "NIST",
        "DISA_STIG",
        "ISO_27001",
    ]

    mock_scan.assert_called_once()

    scan_kwargs = mock_scan.call_args.kwargs

    assert scan_kwargs["host"] == device["management_ip"]
    assert scan_kwargs["device_type"] == "cisco_ios"
    assert scan_kwargs["port"] == 22

    mock_analysis.assert_called_once()

    analysis_kwargs = mock_analysis.call_args.kwargs

    assert analysis_kwargs["content"] == fake_configuration

    assert analysis_kwargs["frameworks"] == [
        "CIS",
        "NIST",
        "DISA_STIG",
        "ISO_27001",
    ]


if __name__ == "__main__":
    print("=" * 80)
    print("LIVE SCAN REGRESSION")
    print("=" * 80)

    test_vendor_driver_mapping()
    print("15-vendor Netmiko mapping: PASS")

    test_unknown_vendor_does_not_fallback_to_cisco()
    print("Unknown vendor safety: PASS")

    test_live_scan_uses_vendor_driver_and_analysis_pipeline()
    print("Live scan driver + multi-framework analysis pipeline: PASS")

    print("=" * 80)
    print("LIVE SCAN REGRESSION: PASS")
    print("=" * 80)