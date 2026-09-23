from __future__ import annotations

import re
from typing import Any


def detect_cisco(configuration: str) -> dict[str, Any]:
    """
    Detect Cisco configuration syntax.
    """

    patterns = [
        r"^\s*version\s+\d+\.\d+",
        r"^\s*enable\s+(?:secret|password)",
        r"^\s*ip\s+ssh\b",
        r"^\s*aaa\s+new-model\b",
        r"^\s*router\s+(?:ospf|bgp|eigrp)\b",
        r"^\s*license\s+udi\s+pid\s+\S+\s+sn\s+\S+",
        r"^\s*crypto\s+pki\s+trustpoint\b",
        r"^\s*line\s+(?:con|aux|vty)\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "Cisco",
        "confidence": round(confidence, 2),
        "evidence": [
            f"Cisco syntax detected ({len(matches)} signature patterns matched)"
        ],
    }

def detect_fortinet(configuration: str) -> dict[str, Any]:
    """
    Detect Fortinet configuration syntax.
    """

    patterns = [
        r"^\s*config\s+system\s+global\b",
        r"^\s*config\s+system\s+interface\b",
        r"^\s*config\s+firewall\s+policy\b",
        r"^\s*config\s+vpn\b",
        r"^\s*config\s+router\b",
        r"^\s*set\s+hostname\s+\S+",
        r"^\s*set\s+vdom\b",
        r"^\s*set\s+version\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "Fortinet",
        "confidence": round(confidence, 2),
        "evidence": [
            f"Fortinet syntax detected ({len(matches)} signature patterns matched)"
        ],
    }

def detect_juniper(configuration: str) -> dict[str, Any]:
    """
    Detect Juniper Junos configuration syntax.
    """

    patterns = [
        r"^\s*system\s*\{",
        r"^\s*interfaces\s*\{",
        r"^\s*security\s*\{",
        r"^\s*protocols\s*\{",
        r"^\s*routing-options\s*\{",
        r"^\s*firewall\s*\{",
        r"^\s*set\s+system\s+host-name\s+\S+",
        r"^\s*set\s+version\s+\S+",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "Juniper",
        "confidence": round(confidence, 2),
        "evidence": [
            f"Juniper Junos syntax detected "
            f"({len(matches)} signature patterns matched)"
        ],
    }

def detect_palo_alto(configuration: str) -> dict[str, Any]:
    """
    Detect Palo Alto Networks PAN-OS configuration syntax.
    """

    patterns = [
        r"^\s*<config>",
        r"^\s*<devices>",
        r"^\s*<entry\s+name=",
        r"^\s*<vsys>",
        r"^\s*<rulebase>",
        r"^\s*<security>",
        r"^\s*<network>",
        r"^\s*<deviceconfig>",
        r"^\s*set\s+deviceconfig\s+system\s+hostname\b",
        r"^\s*set\s+network\s+interface\s+ethernet\b",
        r"^\s*set\s+network\s+virtual-router\b",
        r"^\s*set\s+rulebase\s+security\s+rules\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "Palo Alto Networks",
        "confidence": round(confidence, 2),
        "evidence": [
            f"Palo Alto PAN-OS syntax detected "
            f"({len(matches)} signature patterns matched)"
        ],
    }

def detect_arista(configuration: str) -> dict[str, Any]:
    """
    Detect Arista EOS configuration syntax.
    """

    patterns = [
        r"^\s*hostname\s+\S+",
        r"^\s*ip\s+routing\b",
        r"^\s*router\s+bgp\s+\d+",
        r"^\s*router\s+ospf\b",
        r"^\s*management\s+api\s+http-commands\b",
        r"^\s*daemon\s+TerminAttr\b",
        r"^\s*interface\s+Ethernet\d+",
        r"^\s*interface\s+Management\d+",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "Arista",
        "confidence": round(confidence, 2),
        "evidence": [
            f"Arista EOS syntax detected "
            f"({len(matches)} signature patterns matched)"
        ],
    }

def detect_aruba(configuration: str) -> dict[str, Any]:
    """
    Detect ArubaOS / Aruba configuration syntax.
    """

    patterns = [
        r"^\s*hostname\s+\S+",
        r"^\s*interface\s+\S+",
        r"^\s*ip\s+address\b",
        r"^\s*vlan\s+\d+",
        r"^\s*aaa\s+authentication\b",
        r"^\s*wlan\s+ssid-profile\b",
        r"^\s*ap-group\b",
        r"^\s*arm\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "Aruba",
        "confidence": round(confidence, 2),
        "evidence": [
            f"Aruba syntax detected "
            f"({len(matches)} signature patterns matched)"
        ],
    }

def detect_mikrotik(configuration: str) -> dict[str, Any]:
    """
    Detect MikroTik RouterOS configuration syntax.
    """

    patterns = [
        r"^\s*/system\s+identity\b",
        r"^\s*/interface\b",
        r"^\s*/ip\s+address\b",
        r"^\s*/ip\s+firewall\b",
        r"^\s*/ip\s+route\b",
        r"^\s*/user\b",
        r"^\s*/system\s+package\b",
        r"^\s*/routing\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "MikroTik",
        "confidence": round(confidence, 2),
        "evidence": [
            f"MikroTik RouterOS syntax detected "
            f"({len(matches)} signature patterns matched)"
        ],
    }

def detect_huawei(configuration: str) -> dict[str, Any]:
    """
    Detect Huawei VRP configuration syntax.
    """

    patterns = [
        r"^\s*sysname\s+\S+",
        r"^\s*interface\s+\S+",
        r"^\s*ip\s+address\s+\S+\s+\S+",
        r"^\s*ospf\s+\d+",
        r"^\s*bgp\s+\d+",
        r"^\s*stelnet\s+server\s+enable\b",
        r"^\s*user-interface\s+(?:vty|console)\b",
        r"^\s*undo\s+telnet\s+server\s+enable\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "Huawei",
        "confidence": round(confidence, 2),
        "evidence": [
            f"Huawei VRP syntax detected "
            f"({len(matches)} signature patterns matched)"
        ],
    }

def detect_nokia(configuration: str) -> dict[str, Any]:
    """
    Detect Nokia SR OS configuration syntax.
    """

    patterns = [
        r"^\s*configure\b",
        r"^\s*system\s*\{",
        r"^\s*router\s+",
        r"^\s*service\s+",
        r"^\s*interface\s+",
        r"^\s*port\s+",
        r"^\s*authentication-order\b",
        r"^\s*admin\s+user\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "Nokia",
        "confidence": round(confidence, 2),
        "evidence": [
            f"Nokia SR OS syntax detected "
            f"({len(matches)} signature patterns matched)"
        ],
    }

def detect_hpe_comware(configuration: str) -> dict[str, Any]:
    """
    Detect HPE Comware configuration syntax.
    """

    patterns = [
        r"^\s*system-view\b",
        r"^\s*sysname\s+\S+",
        r"^\s*interface\s+\S+",
        r"^\s*vlan\s+\d+",
        r"^\s*ospf\s+\d+",
        r"^\s*bgp\s+\d+",
        r"^\s*stp\b",
        r"^\s*user-interface\s+(?:vty|console)\b",
        r"^\s*ssh\s+server\s+enable\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "HPE Comware",
        "confidence": round(confidence, 2),
        "evidence": [
            f"HPE Comware syntax detected "
            f"({len(matches)} signature patterns matched)"
        ],
    }

def detect_extreme(configuration: str) -> dict[str, Any]:
    """
    Detect Extreme Networks ExtremeXOS configuration syntax.
    """

    patterns = [
        r"^\s*configure\s+snmp\s+sysName\b",
        r"^\s*configure\s+snmp\s+add\b",
        r"^\s*configure\s+vlan\s+\S+",
        r"^\s*configure\s+vlan\s+\S+\s+tag\s+\d+",
        r"^\s*configure\s+ipaddress\b",
        r"^\s*configure\s+ospf\b",
        r"^\s*configure\s+bgp\b",
        r"^\s*configure\s+ssh2\s+enable\b",
        r"^\s*enable\s+sharing\b",
        r"^\s*create\s+account\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "Extreme Networks",
        "confidence": round(confidence, 2),
        "evidence": [
            f"ExtremeXOS syntax detected "
            f"({len(matches)} signature patterns matched)"
        ],
    }

def detect_dell(configuration: str) -> dict[str, Any]:
    """
    Detect Dell Networking OS configuration syntax.
    """

    patterns = [
        r"^\s*hostname\s+\S+",
        r"^\s*interface\s+ethernet\s*\S+",
        r"^\s*interface\s+ethernet\s*\d+/\d+/\d+(?::\d+)?\b",
        r"^\s*interface\s+(?:fortyGigE|hundredGigE|tengigabitethernet)\s+\S+",
        r"^\s*spanning-tree\s+(?:rstp|mstp)\b",
        r"^\s*switchport\s+(?:mode|access|trunk)\b",
        r"^\s*ip\s+address\s+\S+\s+\S+",
        r"^\s*router\s+ospf\s+\d+",
        r"^\s*router\s+bgp\s+\d+",
        r"^\s*switchport\b",
        r"^\s*vlan\s+\d+",
        r"^\s*spanning-tree\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "Dell Networking",
        "confidence": round(confidence, 2),
        "evidence": [
            f"Dell Networking syntax detected "
            f"({len(matches)} signature patterns matched)"
        ],
    }

def detect_checkpoint(configuration: str) -> dict[str, Any]:
    """
    Detect Check Point Gaia / Security Gateway configuration syntax.
    """

    patterns = [
        r"^\s*set\s+hostname\b",
        r"^\s*set\s+interface\b",
        r"^\s*set\s+static-route\b",
        r"^\s*set\s+snmp\b",
        r"^\s*set\s+ntp\b",
        r"^\s*show\s+configuration\b",
        r"^\s*clish\b",
        r"^\s*save\s+config\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "Check Point",
        "confidence": round(confidence, 2),
        "evidence": [
            f"Check Point Gaia syntax detected "
            f"({len(matches)} signature patterns matched)"
        ],
    }

def detect_vyos(configuration: str) -> dict[str, Any]:
    """
    Detect VyOS configuration syntax.
    """

    patterns = [
        r"^\s*set\s+system\s+host-name\b",
        r"^\s*set\s+interfaces\s+ethernet\b",
        r"^\s*set\s+interfaces\s+bonding\b",
        r"^\s*set\s+protocols\s+static\b",
        r"^\s*set\s+protocols\s+bgp\b",
        r"^\s*set\s+protocols\s+ospf\b",
        r"^\s*set\s+firewall\b",
        r"^\s*set\s+service\s+ssh\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "VyOS",
        "confidence": round(confidence, 2),
        "evidence": [
            f"VyOS configuration syntax detected "
            f"({len(matches)} signature patterns matched)"
        ],
    }

def detect_cumulus(configuration: str) -> dict[str, Any]:
    """
    Detect NVIDIA Cumulus Linux configuration syntax.
    """

    patterns = [
        # Modern NVIDIA Cumulus Linux NVUE syntax.
        r"^\s*nv\s+set\s+system\s+hostname\b",
        r"^\s*nv\s+set\s+interface\b",
        r"^\s*nv\s+set\s+router\b",
        r"^\s*nv\s+set\s+vrf\b",
        r"^\s*nv\s+set\s+bridge\b",
        r"^\s*nv\s+set\s+vlan\b",
        r"^\s*nv\s+set\b",
        # Traditional ifupdown / ifupdown2 syntax.
        r"^\s*auto\s+\S+",
        r"^\s*iface\s+\S+\s+inet\b",
        r"^\s*address\s+\d+\.\d+\.\d+\.\d+/\d+",
        r"^\s*bridge-ports\b",
        r"^\s*bridge-vlan-aware\b",
        r"^\s*vrf-table\s+\d+",
        r"^\s*router\s+bgp\s+\d+",
        r"^\s*net\s+add\b",
    ]

    matches = []

    for pattern in patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            matches.append(pattern)

    if not matches:
        return {
            "detected": False,
            "vendor": None,
            "confidence": 0.0,
            "evidence": [],
        }

    confidence = min(
        0.90,
        0.50 + (len(matches) * 0.05),
    )

    return {
        "detected": True,
        "vendor": "NVIDIA Cumulus",
        "confidence": round(confidence, 2),
        "evidence": [
            f"NVIDIA Cumulus Linux syntax detected "
            f"({len(matches)} signature patterns matched)"
        ],
    }

def detect_vendor(configuration: str) -> dict[str, Any]:
    """
    Detect the most likely network-device vendor.

    Detection strategy:
    1. Run all vendor-specific detectors.
    2. Give highly discriminative syntax additional weight.
    3. Penalize generic signatures that commonly occur across vendors.
    4. Use the strongest candidate rather than blindly trusting the
       highest raw detector confidence.
    5. Return Unknown when the evidence is insufficient or ambiguous.
    """

    if not configuration or not configuration.strip():
        return {
            "detected": False,
            "vendor": "Unknown",
            "confidence": 0.0,
            "evidence": ["Empty configuration"],
        }

    detectors = [
        detect_cisco,
        detect_fortinet,
        detect_juniper,
        detect_palo_alto,
        detect_arista,
        detect_aruba,
        detect_mikrotik,
        detect_huawei,
        detect_nokia,
        detect_hpe_comware,
        detect_extreme,
        detect_dell,
        detect_checkpoint,
        detect_vyos,
        detect_cumulus,
    ]

    results = []

    for detector in detectors:
        try:
            result = detector(configuration)
        except Exception:
            continue

        if result.get("detected"):
            results.append(result)

    if not results:
        return {
            "detected": False,
            "vendor": "Unknown",
            "confidence": 0.0,
            "evidence": [
                "No known vendor syntax detected",
                "Configuration requires AI/NLP semantic matching",
            ],
        }

    import re

    config = configuration.lower()

    # Highly discriminative signatures.
    # These are intentionally stronger than generic patterns such as
    # hostname, interface, ip address, vlan, etc.
    strong_signatures = {
        "Cisco": [
            r"^\s*version\s+\d+(?:\.\d+)+",
            r"^\s*aaa\s+new-model\b",
            r"^\s*ip\s+ssh\s+version\s+\d+",
            r"^\s*service\s+timestamps\s+log\b",
            r"^\s*enable\s+secret\b",
            r"^\s*router\s+(?:ospf|eigrp|bgp)\b",
        ],

        "Fortinet": [
            r"^\s*config\s+system\s+global\b",
            r"^\s*config\s+firewall\s+(?:policy|address|service)\b",
            r"^\s*config\s+vpn\b",
            r"^\s*config\s+router\b",
            r"^\s*set\s+hostname\s+fortigate",
        ],

        "Juniper": [
            r"^\s*set\s+system\s+host-name\b",
            r"^\s*set\s+system\s+services\s+ssh\b",
            r"^\s*set\s+interfaces\s+\S+\s+unit\s+\d+",
            r"^\s*set\s+policy-options\b",
            r"^\s*set\s+routing-options\b",
            r"^\s*system\s*\{",
            r"^\s*interfaces\s*\{",
            r"^\s*routing-options\s*\{",
            r"^\s*security\s*\{",
        ],

        "Palo Alto Networks": [
            r"<config\b",
            r"<devices>",
            r"<deviceconfig>",
            r"<security>",
            r"<virtual-router>",
            r"<panorama>",
            r"^\s*set\s+deviceconfig\s+system\s+hostname\b",
            r"^\s*set\s+network\s+interface\s+ethernet\b",
            r"^\s*set\s+network\s+virtual-router\b",
            r"^\s*set\s+rulebase\s+security\s+rules\b",
        ],

        "Arista": [
            r"^\s*management\s+api\s+http-commands\b",
            r"^\s*management\s+api\s+gnmi\b",
            r"^\s*management\s+ssh\b",
            r"^\s*router\s+bgp\s+\d+",
            r"^\s*daemon\s+terminattr\b",
            r"^\s*transceiver\s+qsfp\b",
        ],

        "Aruba": [
            r"^\s*ssh\s+server\s+vrf\b",
            r"^\s*interface\s+\d+/\d+/\d+\b",
            r"^\s*aaa\s+authentication\s+login\b",
            r"^\s*aaa\s+authorization\s+commands\b",
            r"^\s*vsx\b",
        ],

        "MikroTik": [
            r"^\s*/system\s+identity\b",
            r"^\s*/ip\s+service\b",
            r"^\s*/ip\s+firewall\b",
            r"^\s*/interface\b",
            r"^\s*set\s+(?:ssh|telnet)\s+disabled=(?:yes|no)\b",
        ],

        "Huawei": [
            r"^\s*stelnet\s+server\s+enable\b",
            r"^\s*undo\s+telnet\s+server\s+enable\b",
            r"^\s*local-user\s+\S+\s+password\s+irreversible-cipher\b",
            r"^\s*user-interface\s+vty\b",
            r"^\s*ip\s+route-static\b",
            r"^\s*undo\s+shutdown\b",
            r"^\s*interface\s+GigabitEthernet\d+/\d+/\d+\b",
        ],

        "Nokia": [
            r"^\s*configure\s+system\b",
            r"^\s*configure\s+router\b",
            r"^\s*service\s+ies\b",
            r"^\s*admin\s+display-config\b",
            r"^\s*router-id\s+\d+\.\d+\.\d+\.\d+\b",
        ],

        "HPE Comware": [
            r"^\s*port\s+link-type\b",
            r"^\s*undo\s+shutdown\b",
            r"^\s*user-interface\s+(?:vty|aux|console)\b",
            r"^\s*ssh\s+server\s+enable\b",
            r"^\s*undo\s+telnet\s+server\s+enable\b",
        ],

        "Extreme Networks": [
            r"^\s*configure\s+ssh2\s+enable\b",
            r"^\s*configure\s+snmp\s+add\b",
            r"^\s*create\s+vlan\b",
            r"^\s*configure\s+vlan\b",
            r"^\s*configure\s+iproute\s+add\b",
            r"^\s*enable\s+sharing\b",
        ],

        "Dell Networking": [
            r"^\s*interface\s+ethernet\s*\d+/\d+/\d+(?::\d+)?\b",
            r"^\s*interface\s+port-channel\d+\b",
            r"^\s*interface\s+vlan\d+\b",
            r"^\s*no\s+ip\s+address\b",
            r"^\s*switchport\s+mode\s+(?:access|trunk)\b",
            r"^\s*spanning-tree\s+rstp\b",
        ],

        "Check Point": [
            r"^\s*set\s+hostname\s+\S+",
            r"^\s*set\s+interface\s+\S+",
            r"^\s*set\s+static-route\b",
            r"^\s*set\s+access-rule\b",
            r"^\s*show\s+configuration\b",
        ],

        "VyOS": [
            r"^\s*set\s+system\s+host-name\b",
            r"^\s*set\s+service\s+ssh\b",
            r"^\s*set\s+interfaces\s+ethernet\b",
            r"^\s*set\s+firewall\b",
            r"^\s*commit\b",
        ],

        "NVIDIA Cumulus": [
            r"^\s*nv\s+set\b",
            r"^\s*net\s+add\b",
            r"^\s*net\s+del\b",
            r"^\s*cl-acltool\b",
            r"^\s*/etc/network/interfaces\b",
            r"^\s*auto\s+swp\d+\b",
            r"^\s*iface\s+swp\d+\s+inet\b",
            r"^\s*bridge-ports\b",
            r"^\s*bridge-vlan-aware\b",
        ],
    }

    # Generic syntax receives no additional weight.
    # This prevents common constructs such as hostname/interface/ip address
    # from incorrectly deciding the vendor.
    candidate_scores = {}

    for result in results:
        vendor = result.get("vendor")
        if not vendor:
            continue

        raw_confidence = float(result.get("confidence") or 0.0)
        score = raw_confidence

        matches = []

        for pattern in strong_signatures.get(vendor, []):
            if re.search(pattern, config, re.MULTILINE | re.IGNORECASE):
                matches.append(pattern)

        # Strong vendor-specific syntax is deliberately weighted heavily.
        score += min(len(matches), 4) * 0.15

        candidate_scores[vendor] = {
            "score": min(score, 1.0),
            "raw_confidence": raw_confidence,
            "matches": matches,
            "result": result,
        }

    if not candidate_scores:
        return {
            "detected": False,
            "vendor": "Unknown",
            "confidence": 0.0,
            "evidence": [
                "Vendor detectors produced no usable candidates",
                "Configuration requires AI/NLP semantic matching",
            ],
        }

    ranked = sorted(
        candidate_scores.items(),
        key=lambda item: item[1]["score"],
        reverse=True,
    )

    # Deterministic family signatures resolve known Cisco/Arista/Dell
    # lexical overlap. These are deliberately checked before generic
    # confidence ranking because interface/routing syntax is shared.
    # Dell OS10/OS9 commonly uses three-level Ethernet identifiers such as
    # Ethernet 1/1/1, while Arista EOS uses Ethernet1/1-style interfaces.
    dell_family = re.search(
        r"^\s*interface\s+ethernet\s*\d+/\d+/\d+(?::\d+)?\b",
        config,
        re.MULTILINE | re.IGNORECASE,
    )
    arista_family = any(
        re.search(
            pattern,
            config,
            re.MULTILINE | re.IGNORECASE,
        )
        for pattern in (
            r"^\s*management\s+api\s+(?:http-commands|gnmi)\b",
            r"^\s*daemon\s+terminattr\b",
            r"^\s*transceiver\s+qsfp\b",
        )
    )
    hpe_comware_family = bool(
        re.search(
            r"^\s*system-view\b",
            config,
            re.MULTILINE | re.IGNORECASE,
        )
    )

    # EOS-style two-level Ethernet/Management interfaces are useful only
    # after excluding Dell's three-level interface numbering.  This keeps
    # Cisco Nexus-style Ethernet syntax from becoming a blanket Arista rule.
    arista_interface_family = bool(
        re.search(
            r"^\s*interface\s+(?:Ethernet\d+(?:/\d+)?|Management\d+)\b",
            config,
            re.MULTILINE | re.IGNORECASE,
        )
        and not dell_family
    )

    if dell_family and "Dell Networking" in candidate_scores:
        winner_vendor = "Dell Networking"
        winner = candidate_scores[winner_vendor]
    elif arista_family and "Arista" in candidate_scores:
        winner_vendor = "Arista"
        winner = candidate_scores[winner_vendor]
    elif hpe_comware_family and "HPE Comware" in candidate_scores:
        winner_vendor = "HPE Comware"
        winner = candidate_scores[winner_vendor]
    else:
        winner_vendor, winner = ranked[0]

    # If a highly discriminative signature exists, prefer it over
    # a competing vendor supported only by generic syntax.
    strong_candidates = [
        item for item in ranked
        if len(item[1]["matches"]) >= 1
    ]

    if strong_candidates:
        strong_candidates.sort(
            key=lambda item: (
                len(item[1]["matches"]),
                item[1]["score"],
            ),
            reverse=True,
        )
        winner_vendor, winner = strong_candidates[0]

    # Final vendor-family override.  This must run AFTER strong-signature
    # ranking; otherwise a shared `router bgp`/`version` signature can undo
    # the more specific interface-family decision.
    if dell_family and "Dell Networking" in candidate_scores:
        winner_vendor = "Dell Networking"
        winner = candidate_scores[winner_vendor]
    elif arista_interface_family and "Arista" in candidate_scores:
        winner_vendor = "Arista"
        winner = candidate_scores[winner_vendor]
    elif hpe_comware_family and "HPE Comware" in candidate_scores:
        winner_vendor = "HPE Comware"
        winner = candidate_scores[winner_vendor]

    # Ambiguity protection.
    if len(ranked) > 1:
        second_vendor, second = ranked[1]

        score_gap = winner["score"] - second["score"]

        if (
            len(winner["matches"]) == 0
            and score_gap < 0.10
        ):
            return {
                "detected": False,
                "vendor": "Unknown",
                "confidence": round(winner["score"], 2),
                "evidence": [
                    f"Ambiguous vendor detection: {winner_vendor} vs {second_vendor}",
                    "Configuration contains insufficient vendor-specific syntax",
                    "AI/NLP semantic matching is required",
                ],
            }

    evidence = list(winner["result"].get("evidence") or [])

    if winner["matches"]:
        evidence.append(
            f"Strong vendor-specific signatures matched: "
            f"{len(winner['matches'])}"
        )

    return {
        "detected": True,
        "vendor": winner_vendor,
        "confidence": round(winner["score"], 2),
        "evidence": evidence,
    }
