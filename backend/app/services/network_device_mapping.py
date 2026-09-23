from __future__ import annotations


VENDOR_DEVICE_TYPES: dict[str, str] = {
    "cisco": "cisco_ios",
    "cisco systems": "cisco_ios",
    "fortinet": "fortinet",
    "fortigate": "fortinet",
    "juniper": "juniper_junos",
    "juniper networks": "juniper_junos",
    "palo alto": "paloalto_panos",
    "palo alto networks": "paloalto_panos",
    "arista": "arista_eos",
    "aruba": "aruba_aoscx",
    "aruba networks": "aruba_aoscx",
    "mikrotik": "mikrotik_routeros",
    "huawei": "huawei_vrp",
    "nokia": "nokia_sros",
    "hpe": "hp_comware",
    "hpe comware": "hp_comware",
    "hewlett packard enterprise": "hp_comware",
    "extreme": "extreme_exos",
    "extreme networks": "extreme_exos",
    "dell": "dell_os10",
    "dell networking": "dell_os10",
    "check point": "checkpoint_gaia",
    "checkpoint": "checkpoint_gaia",
    "nvidia cumulus": "cumulus_linux",
    "cumulus": "cumulus_linux",
    "vyos": "vyos",
    "vyatta": "vyos",
}


def get_netmiko_device_type(
    vendor: str | None,
    device_type: str | None = None,
) -> str | None:
    """
    Resolve the Netmiko driver for a device.

    A known explicit Netmiko device_type takes precedence.
    Otherwise the vendor mapping is used.
    """

    if device_type:
        normalized_type = device_type.strip().lower()

        if normalized_type not in {
            "",
            "router",
            "switch",
            "firewall",
            "unknown",
            "generic",
        }:
            return normalized_type

    if not vendor:
        return None

    return VENDOR_DEVICE_TYPES.get(
        vendor.strip().lower()
    )
