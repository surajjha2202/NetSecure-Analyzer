from __future__ import annotations

import re
from typing import Any

from app.services.vendor_detectors import detect_vendor


def analyze_device(
    configuration: str,
    existing_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Analyze a network-device configuration and return normalized
    device intelligence with evidence and confidence.
    """

    configuration = configuration.lstrip("\ufeff")

    metadata = existing_metadata or {}

    evidence: list[str] = []

    vendor = metadata.get("vendor")
    product = metadata.get("product")
    platform = metadata.get("platform")
    model = metadata.get("model")
    firmware = metadata.get("firmware")
    serial_number = metadata.get("serial_number")
    device_type = metadata.get("device_type")

    # =========================================================
    # 1. VENDOR DETECTION
    # =========================================================

    vendor_result = detect_vendor(configuration)

    cisco_matches = []

    if vendor_result["vendor"]:
        vendor = vendor_result["vendor"]
        evidence.extend(vendor_result["evidence"])

        # Keep Cisco signature count for the existing
        # confidence calculation.
        if vendor == "Cisco":
            cisco_patterns = [
                r"^\s*version\s+\d+\.\d+",
                r"^\s*enable\s+(?:secret|password)",
                r"^\s*ip\s+ssh\b",
                r"^\s*aaa\s+new-model\b",
                r"^\s*router\s+(?:ospf|bgp|eigrp)\b",
                r"^\s*license\s+udi\s+pid\s+\S+\s+sn\s+\S+",
                r"^\s*crypto\s+pki\s+trustpoint\b",
                r"^\s*line\s+(?:con|aux|vty)\b",
            ]

            for pattern in cisco_patterns:
                if re.search(
                    pattern,
                    configuration,
                    re.MULTILINE | re.IGNORECASE,
                ):
                    cisco_matches.append(pattern)

    # =========================================================
    # 2. CISCO METADATA EXTRACTION
    # =========================================================

    if vendor == "Cisco":

        # -----------------------------------------------------
        # Hostname
        # -----------------------------------------------------

        hostname_match = re.search(
            r"^\s*hostname\s+(\S+)",
            configuration,
            re.MULTILINE | re.IGNORECASE,
        )

        if hostname_match:
            hostname = hostname_match.group(1)

            evidence.append(
                f"Hostname detected: {hostname}"
            )

        # -----------------------------------------------------
        # IOS / IOS-XE version
        # -----------------------------------------------------

        version_match = re.search(
            r"^\s*version\s+(\d+(?:\.\d+)+)",
            configuration,
            re.MULTILINE | re.IGNORECASE,
        )

        if version_match:
            firmware = version_match.group(1)
            platform = platform or "IOS-XE"

            evidence.append(
                f"Firmware version detected: {firmware}"
            )

        # -----------------------------------------------------
        # Cisco License UDI
        # -----------------------------------------------------

        udi_match = re.search(
            r"^\s*license\s+udi\s+pid\s+(\S+)\s+sn\s+(\S+)",
            configuration,
            re.MULTILINE | re.IGNORECASE,
        )

        if udi_match:
            model = udi_match.group(1)
            serial_number = udi_match.group(2)

            evidence.append(
                f"Model detected from UDI: {model}"
            )

            evidence.append(
                f"Serial number detected from UDI: {serial_number}"
            )

        # -----------------------------------------------------
        # Product identification
        # -----------------------------------------------------

        if model and model.upper() == "C8000V":
            product = product or "Catalyst 8000"

    # =========================================================
    # 3. DEVICE TYPE CLASSIFICATION
    # =========================================================

    type_scores = {
        "router": 0,
        "switch": 0,
        "firewall": 0,
        "wireless_controller": 0,
    }

    # =========================================================
    # Router signals
    # =========================================================

    routing_patterns = [
        r"^\s*router\s+ospf\b",
        r"^\s*router\s+bgp\b",
        r"^\s*router\s+eigrp\b",
        r"^\s*router\s+isis\b",
    ]

    routing_matches = 0

    for pattern in routing_patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            routing_matches += 1

    if routing_matches:
        type_scores["router"] += routing_matches * 3

        evidence.append(
            f"Router signals detected: "
            f"{routing_matches} routing protocol configuration(s)"
        )

    # =========================================================
    # Routed interfaces
    # =========================================================

    routed_interfaces = re.findall(
        r"^\s*interface\s+\S+[\s\S]*?(?=^\s*!|\Z)",
        configuration,
        re.MULTILINE | re.IGNORECASE,
    )

    routed_interface_count = 0

    for interface_block in routed_interfaces:

        if re.search(
            r"^\s*ip\s+address\s+\S+\s+\S+",
            interface_block,
            re.MULTILINE | re.IGNORECASE,
        ):
            routed_interface_count += 1

    if routed_interface_count:
        type_scores["router"] += min(
            routed_interface_count,
            3,
        )

        evidence.append(
            f"Routed interfaces detected: "
            f"{routed_interface_count}"
        )

    # =========================================================
    # Switch signals
    # =========================================================

    switch_patterns = [
        r"^\s*switchport\b",
        r"^\s*switchport\s+mode\b",
        r"^\s*spanning-tree\b",
        r"^\s*interface\s+Port-channel\b",
    ]

    switch_matches = 0

    for pattern in switch_patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            switch_matches += 1

    if switch_matches:
        type_scores["switch"] += switch_matches * 2

        evidence.append(
            f"Switch signals detected: {switch_matches}"
        )

    # =========================================================
    # Firewall signals
    # =========================================================

    firewall_patterns = [
        r"^\s*security-level\b",
        r"^\s*access-group\b",
        r"^\s*policy-map\b",
        r"^\s*zone-pair\b",
    ]

    firewall_matches = 0

    for pattern in firewall_patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            firewall_matches += 1

    if firewall_matches:
        type_scores["firewall"] += firewall_matches * 2

        evidence.append(
            f"Firewall signals detected: {firewall_matches}"
        )

    # =========================================================
    # Wireless controller
    # =========================================================

    wireless_patterns = [
        r"^\s*wireless\b",
        r"^\s*wlan\b",
        r"^\s*ap\s+profile\b",
        r"^\s*wireless\s+profile\b",
    ]

    wireless_matches = 0

    for pattern in wireless_patterns:
        if re.search(
            pattern,
            configuration,
            re.MULTILINE | re.IGNORECASE,
        ):
            wireless_matches += 1

    if wireless_matches:
        type_scores["wireless_controller"] += (
            wireless_matches * 2
        )

        evidence.append(
            f"Wireless-controller signals detected: "
            f"{wireless_matches}"
        )

    # =========================================================
    # 4. SELECT DEVICE TYPE
    # =========================================================

    highest_type = max(
        type_scores,
        key=type_scores.get,
    )

    highest_score = type_scores[highest_type]

    if highest_score > 0:
        device_type = highest_type

    # =========================================================
    # 5. CONFIDENCE CALCULATION
    # =========================================================

    confidence = float(
        vendor_result.get("confidence", 0.0)
    )

    # Metadata extraction boosts confidence.
    if firmware:
        confidence += 0.02

    if model:
        confidence += 0.02

    if serial_number:
        confidence += 0.02

    # Device classification boost.
    if device_type:
        confidence += 0.04

    confidence = min(
        confidence,
        0.98,
    )

    confidence = min(
        confidence,
        0.98,
    )

    confidence = round(
        confidence,
        2,
    )

    # =========================================================
    # 6. CONFIDENCE LEVEL
    # =========================================================

    if confidence >= 0.85:
        confidence_level = "HIGH"

    elif confidence >= 0.65:
        confidence_level = "MEDIUM"

    else:
        confidence_level = "LOW"

    evidence.append(
        f"Overall detection confidence: "
        f"{confidence_level} ({confidence:.2f})"
    )

    # =========================================================
    # 7. RETURN NORMALIZED DEVICE INTELLIGENCE
    # =========================================================

    return {
        "vendor": vendor,
        "product": product,
        "platform": platform,
        "model": model,
        "firmware": firmware,
        "serial_number": serial_number,
        "device_type": device_type,
        "confidence": confidence,
        "confidence_level": confidence_level,
        "evidence": evidence,
        "type_scores": type_scores,
    }