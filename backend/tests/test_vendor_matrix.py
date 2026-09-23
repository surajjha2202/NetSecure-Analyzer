import pytest

from app.services.vendor_detectors import detect_vendor
from app.services.vendor_parsers import parser_registry
from app.services.security_baseline import build_security_baseline


VENDOR_CONFIGS = {
    "Cisco": """
version 17.9
hostname CISCO-TEST
aaa new-model
enable secret test-secret
ip ssh version 2
logging buffered 16384
logging host 10.10.10.50
service timestamps log datetime msec
service password-encryption
line vty 0 4
 transport input ssh
""",

    "Fortinet": """
config system global
    set hostname FORTI-TEST
end
config system interface
    edit "port1"
        set ip 192.168.1.1/24
    next
end
""",

    "Juniper": """
system {
    host-name JUNIPER-TEST;
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 192.168.1.1/24;
            }
        }
    }
}
""",

    "Arista": """
!
hostname ARISTA-TEST
!
interface Ethernet1
   description TEST
   ip address 192.168.1.1/24
!
router bgp 65001
!
""",

    "Palo Alto Networks": """
set deviceconfig system hostname PA-TEST
set network interface ethernet ethernet1/1 layer3 ip 192.168.1.1/24
""",

    "Aruba": """
hostname ARUBA-TEST
!
interface 1/1/1
    no shutdown
    vlan access 10
!
""",

    "MikroTik": """
/system identity
set name=MIKROTIK-TEST
/ip address
add address=192.168.1.1/24 interface=ether1
""",

    "Huawei": """
sysname HUAWEI-TEST
interface GigabitEthernet0/0/1
 ip address 192.168.1.1 255.255.255.0
 undo shutdown
""",

    "Nokia": """
configure
    system
        name "NOKIA-TEST"
    exit
exit all
""",

    "HPE Comware": """
system-view
sysname HPE-TEST
interface GigabitEthernet1/0/1
 ip address 192.168.1.1 255.255.255.0
 undo shutdown
quit
return
""",

    "Extreme Networks": """
configure vlan default ipaddress 192.168.1.1/24
configure snmp sysName "EXTREME-TEST"
""",

    "Dell Networking": """
hostname DELL-TEST
interface ethernet1/1/1
 no shutdown
 ip address 192.168.1.1/24
""",

    "Check Point": """
set hostname CHECKPOINT-TEST
set interface eth0 ipv4-address 192.168.1.1 mask-length 24
""",

    "VyOS": """
set system host-name 'VYOS-TEST'
set interfaces ethernet eth0 address '192.168.1.1/24'
""",

    "NVIDIA Cumulus": """
hostname CUMULUS-TEST
auto swp1
iface swp1
    address 192.168.1.1/24
""",
}


EXPECTED_PARSER_NAMES = {
    "Cisco": "cisco",
    "Fortinet": "fortinet",
    "Juniper": "juniper",
    "Arista": "arista",
    "Palo Alto Networks": "palo alto networks",
    "Aruba": "aruba",
    "MikroTik": "mikrotik",
    "Huawei": "huawei",
    "Nokia": "nokia",
    "HPE Comware": "hpe comware",
    "Extreme Networks": "extreme networks",
    "Dell Networking": "dell networking",
    "Check Point": "check point",
    "VyOS": "vyos",
    "NVIDIA Cumulus": "nvidia cumulus",
}


@pytest.mark.parametrize(
    "vendor,configuration",
    VENDOR_CONFIGS.items(),
)
def test_vendor_detection(vendor, configuration):
    result = detect_vendor(configuration)

    assert result["vendor"] == vendor, (
        f"Expected {vendor}, got {result}"
    )


@pytest.mark.parametrize(
    "vendor,configuration",
    VENDOR_CONFIGS.items(),
)
def test_vendor_parser_is_registered(vendor, configuration):
    registry_vendor = EXPECTED_PARSER_NAMES[vendor]

    parser = parser_registry.get(registry_vendor)

    assert parser is not None, (
        f"No parser registered for {vendor}"
    )


@pytest.mark.parametrize(
    "vendor,configuration",
    VENDOR_CONFIGS.items(),
)
def test_vendor_parser_executes(vendor, configuration):
    registry_vendor = EXPECTED_PARSER_NAMES[vendor]

    parser = parser_registry.get(registry_vendor)

    assert parser is not None

    result = parser(configuration)

    assert isinstance(result, dict)
    status = result.get("status") if isinstance(result.get("parser"), str) else result.get("parser", {}).get("status"); assert status == "PARSED"
    assert "security_parameters" in result
    assert isinstance(
        result["security_parameters"],
        dict,
    )


@pytest.mark.parametrize(
    "vendor,configuration",
    VENDOR_CONFIGS.items(),
)
def test_vendor_parser_produces_security_baseline(
    vendor,
    configuration,
):
    registry_vendor = EXPECTED_PARSER_NAMES[vendor]

    parser = parser_registry.get(registry_vendor)

    assert parser is not None

    parsed = parser(configuration)

    parsed["vendor"] = vendor

    baseline = build_security_baseline(parsed)

    assert isinstance(baseline, dict)

    for section in (
        "management",
        "authentication",
        "remote_access",
        "crypto",
        "logging",
        "access_control",
        "firewall",
        "interfaces",
        "routing",
        "monitoring",
    ):
        assert section in baseline, (
            f"{vendor}: missing baseline section "
            f"{section}"
        )
