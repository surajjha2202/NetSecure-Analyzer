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

    "HPE": """sysname HPE-COMWARE-TEST
ssh server enable
undo telnet server enable""",

    "Extreme": """configure snmp add EXTREME-TEST
configure ssh2 enable""",

    "Dell": """hostname DELL-OS10-TEST
interface ethernet1/1/1
 ip address 10.0.0.1/24""",

    "PaloAlto": """<config>
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
}

print(f"{'EXPECTED':<12} {'DETECTED':<20} {'CONFIDENCE':<12}")
print("-" * 45)

for expected, configuration in samples.items():
    result = detect_vendor(configuration)
    print(
        f"{expected:<12} "
        f"{str(result.get('vendor')):<20} "
        f"{result.get('confidence')}"
    )
