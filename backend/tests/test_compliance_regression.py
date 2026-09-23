from app.services.compliance_engine import evaluate_compliance
from app.services.security_baseline import build_security_baseline
from app.services.vendor_parsers.cisco import parse_cisco
from app.services.framework_rules import ComplianceRule


def test_cisco_remote_syslog_host_is_detected():
    config = """
!
version 17.9
hostname TEST-CAT8KV
!
logging buffered 16384
logging host 10.10.10.50
service timestamps log datetime msec
!
end
"""

    parsed = parse_cisco(config)
    parameters = parsed["security_parameters"]

    assert parameters["logging"]["local_buffered_logging"] is True
    assert parameters["logging"]["remote_syslog"] is True
    assert parameters["logging"]["timestamps"] is True


def test_unknown_configuration_preserves_unknown_security_state():
    config = """
!
version 17.9
hostname TEST-CAT8KV
!
end
"""

    parsed = parse_cisco(config)
    parsed["security_parameters"]["vendor"] = "Unknown"

    baseline = build_security_baseline(parsed)

    assert baseline["management"]["enable_secret"] is None
    assert baseline["authentication"]["aaa_new_model"] is None
    assert baseline["remote_access"]["ssh_enabled"] is None
    assert baseline["remote_access"]["ssh_version"] is None
    assert baseline["remote_access"]["telnet_enabled"] is None
    assert baseline["crypto"]["password_encryption"] is None
    assert baseline["logging"]["local_buffered_logging"] is None
    assert baseline["logging"]["remote_syslog"] is None
    assert baseline["logging"]["timestamps"] is None
    assert baseline["monitoring"]["logging_configured"] is None


def test_explicit_negative_evidence_remains_false():
    config = """
!
version 17.9
hostname TEST-CAT8KV
!
no aaa new-model
no service password-encryption
!
line vty 0 4
 transport input telnet
!
end
"""

    parsed = parse_cisco(config)

    baseline = build_security_baseline(parsed)

    assert baseline["authentication"]["aaa_new_model"] is False
    assert baseline["crypto"]["password_encryption"] is False
    assert baseline["remote_access"]["telnet_enabled"] is True


def test_compliance_treats_none_as_na():
    rule = ComplianceRule(
        rule_id="TEST-001",
        framework="TEST",
        title="Unknown control",
        category="Test",
        severity="HIGH",
        description="Test rule",
        baseline_path="test.value",
        expected_value=True,
        remediation_required=True,
    )

    baseline = {
        "test": {
            "value": None,
        }
    }

    result = evaluate_compliance(
        baseline=baseline,
        rules=[rule],
    )

    assert result["total_rules"] == 1
    assert result["pass_count"] == 0
    assert result["fail_count"] == 0
    assert result["na_count"] == 1
    assert result["compliance_percentage"] == 0.0

    assert result["results"][0]["status"] == "N/A"
    assert result["results"][0]["actual_value"] is None
