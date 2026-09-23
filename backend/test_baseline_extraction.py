from app.services.configuration_parser import parse_configuration


TEST_CONFIGS = {
    "Cisco": """
version 17.9
hostname TEST-CISCO
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
interface GigabitEthernet1
 ip address 10.0.0.1 255.255.255.0
 no shutdown
""",

    "Fortinet": """
config system global
    set hostname TEST-FORTIGATE
end
config system interface
    edit "port1"
        set ip 10.0.0.1/24
    next
end
config system admin
    edit "admin"
    next
end
""",

    "Juniper": """
set system host-name TEST-JUNIPER
set system services ssh
set system syslog host 10.0.0.10 any info
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
set routing-options static route 0.0.0.0/0 next-hop 10.0.0.254
""",

    "Arista": """
hostname TEST-ARISTA
aaa authorization exec default local
management ssh
logging buffered 10000
logging host 10.0.0.10
interface Ethernet1
   ip address 10.0.0.1/24
router ospf 1
""",

    "Aruba": """
hostname TEST-ARUBA
ssh server vrf default
logging 10.0.0.10
interface 1/1/1
    no shutdown
    vlan access 10
""",

    "MikroTik": """
/system identity set name=TEST-MIKROTIK
/ip service set ssh disabled=no
/ip service set telnet disabled=yes
/system logging add topics=info remote=10.0.0.10
/interface ethernet set [find default-name=ether1] disabled=no
/ip route add dst-address=0.0.0.0/0 gateway=10.0.0.254
""",

    "Huawei": """
sysname TEST-HUAWEI
aaa
stelnet server enable
info-center loghost 10.0.0.10
interface GigabitEthernet0/0/1
 ip address 10.0.0.1 255.255.255.0
 undo shutdown
ip route-static 0.0.0.0 0.0.0.0 10.0.0.254
""",

    "Nokia": """
configure system name TEST-NOKIA
configure system security ssh server-admin-state enable
configure system syslog 1 address 10.0.0.10
configure router interface "system" address 10.0.0.1/32
configure router static-route 0.0.0.0/0 next-hop 10.0.0.254
""",

    "HPE Comware": """
sysname TEST-HPE
ssh server enable
info-center loghost 10.0.0.10
interface GigabitEthernet1/0/1
 undo shutdown
 ip address 10.0.0.1 255.255.255.0
ip route-static 0.0.0.0 0.0.0.0 10.0.0.254
""",

    "Extreme Networks": """
configure snmp add 10.0.0.10
configure ssh2 enable
configure vlan default ipaddress 10.0.0.1/24
configure iproute add default 10.0.0.254
""",

    "Dell Networking": """
hostname TEST-DELL
ip ssh server
logging 10.0.0.10
interface ethernet 1/1/1
 no shutdown
 ip address 10.0.0.1/24
ip route 0.0.0.0/0 10.0.0.254
""",

    "Palo Alto Networks": """
<config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>TEST-PA</hostname>
        </system>
      </deviceconfig>
    </entry>
  </devices>
</config>
""",

    "Check Point": """
set hostname TEST-CHECKPOINT
set interface eth0
set static-route
set access-rule
""",

    "VyOS": """
set system host-name TEST-VYOS
set service ssh
set interfaces ethernet eth0 address 10.0.0.1/24
set protocols static route 0.0.0.0/0 next-hop 10.0.0.254
""",

    "NVIDIA Cumulus": """
nv set system hostname TEST-CUMULUS
nv set interface swp1
nv set router static
nv set vlan 10
""",
}


EXPECTED_CATEGORIES = [
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
]


def main():
    print("=" * 110)
    print("15-VENDOR SECURITY BASELINE EXTRACTION AUDIT")
    print("=" * 110)

    total = len(TEST_CONFIGS)
    passed = 0

    for expected_vendor, configuration in TEST_CONFIGS.items():
        try:
            result = parse_configuration(configuration)

            actual_vendor = result.get("vendor")
            params = result.get("security_parameters", {})

            categories_ok = all(
                category in params
                for category in EXPECTED_CATEGORIES
            )

            populated = [
                category
                for category in EXPECTED_CATEGORIES
                if params.get(category)
            ]

            vendor_ok = actual_vendor == expected_vendor

            status = "PASS" if vendor_ok and categories_ok else "FAIL"

            if status == "PASS":
                passed += 1

            print()
            print(f"{expected_vendor:<24} "
                  f"Detected: {str(actual_vendor):<22} "
                  f"Populated: {len(populated):>2}/10 "
                  f"{status}")

            if populated:
                print("  Categories:", ", ".join(populated))
            else:
                print("  Categories: NONE")

            if not vendor_ok:
                print(f"  ERROR: Expected vendor '{expected_vendor}'")

            if not categories_ok:
                missing = [
                    c for c in EXPECTED_CATEGORIES
                    if c not in params
                ]
                print("  Missing:", ", ".join(missing))

        except Exception as exc:
            print()
            print(f"{expected_vendor:<24} ERROR")
            print(f"  {type(exc).__name__}: {exc}")

    print()
    print("=" * 110)
    print(f"BASELINE STRUCTURE RESULT: {passed}/{total} PASSED")
    print("=" * 110)


if __name__ == "__main__":
    main()