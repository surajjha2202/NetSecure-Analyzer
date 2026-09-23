from app.services.configuration_parser import parse_configuration


samples = {
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


print("=" * 90)
print("PRODUCTION PARSER PIPELINE")
print("=" * 90)
print(f"{'EXPECTED':<24} {'VENDOR':<22} {'PARSER':<20} {'STATUS'}")
print("-" * 90)

passed = 0

for expected, configuration in samples.items():
    try:
        result = parse_configuration(configuration)

        vendor = result.get("vendor")
        parser = result.get("parser") or {}
        parser_name = parser.get("name")
        parser_status = parser.get("status")

        ok = (
            vendor == expected
            and parser_name is not None
            and parser_status == "PARSED"
        )

        if ok:
            passed += 1

        print(
            f"{expected:<24} "
            f"{str(vendor):<22} "
            f"{str(parser_name):<20} "
            f"{'PASS' if ok else 'FAIL'}"
        )

        if not ok:
            print(
                f"  parser object: {parser}"
            )

    except Exception as exc:
        print(
            f"{expected:<24} "
            f"{'ERROR':<22} "
            f"{'-':<20} "
            f"FAIL"
        )
        print(f"  {type(exc).__name__}: {exc}")


print()
print("=" * 90)
print(f"PRODUCTION PIPELINE RESULT: {passed}/{len(samples)} PASSED")
print("=" * 90)
