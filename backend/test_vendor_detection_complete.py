from app.services.vendor_detectors import detect_vendor


samples = {
    "Cisco": """version 17.15
service timestamps log datetime msec
ip ssh version 2
aaa new-model""",

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


edge_cases = {
    "Unknown": """this is not a known network configuration
random setting something
foo bar baz""",

    "Empty": "",

    "Generic": """hostname TEST
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0""",

    "Ambiguous": """hostname TEST
interface 1/1/1
ip address 10.0.0.1 255.255.255.0
vlan 10""",
}


print("=" * 75)
print("KNOWN VENDOR REGRESSION")
print("=" * 75)
print(f"{'EXPECTED':<24} {'DETECTED':<24} {'CONF':<8} {'STATUS'}")
print("-" * 75)

passed = 0

for expected, configuration in samples.items():
    result = detect_vendor(configuration)
    detected = result.get("vendor")
    confidence = result.get("confidence")

    ok = detected == expected

    if ok:
        passed += 1

    print(
        f"{expected:<24} "
        f"{str(detected):<24} "
        f"{str(confidence):<8} "
        f"{'PASS' if ok else 'FAIL'}"
    )


print()
print("=" * 75)
print("EDGE CASE REGRESSION")
print("=" * 75)

for name, configuration in edge_cases.items():
    result = detect_vendor(configuration)

    print()
    print(f"[{name}]")
    print(f"Vendor     : {result.get('vendor')}")
    print(f"Detected   : {result.get('detected')}")
    print(f"Confidence : {result.get('confidence')}")
    print("Evidence   :")

    for evidence in result.get("evidence", []):
        print(f"  - {evidence}")


print()
print("=" * 75)
print(f"KNOWN VENDOR RESULT: {passed}/{len(samples)} PASSED")
print("=" * 75)
