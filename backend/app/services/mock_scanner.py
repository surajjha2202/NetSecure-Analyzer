def mock_scan_device(
    host: str,
    device_type: str = "cisco_ios",
) -> dict:
    """
    Simulate an SSH configuration collection for development and testing.
    """

    mock_configuration = """!
version 17.9
hostname LAB-CISCO-01
!
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
!
enable secret 9 MOCK_ENABLE_SECRET
!
username admin privilege 15 secret 9 MOCK_ADMIN_SECRET
!
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
!
line vty 0 4
 login local
 transport input ssh
!
logging buffered 16384
!
no ip http server
no ip http secure-server
!
interface GigabitEthernet1/0/1
 description UPLINK
 no shutdown
!
end
"""

    return {
        "success": True,
        "hostname": "LAB-CISCO-01",
        "management_ip": host,
        "device_type": device_type,
        "connection_method": "SSH",
        "configuration": mock_configuration,
        "simulation": True,
    }