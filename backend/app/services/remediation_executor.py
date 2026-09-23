from __future__ import annotations

from typing import Any

from app.services.network_device_mapping import get_netmiko_device_type
from app.services.ssh_scanner import execute_ssh_command


def execute_remediation(
    *,
    device: Any,
    command: str,
    username: str,
    password: str,
    port: int = 22,
    secret: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Execute one approved remediation command.

    Credentials are supplied at execution time and are never persisted.
    """

    if not device:
        return {
            "success": False,
            "status": "FAILED",
            "error": "Device not found.",
        }

    if not device.is_active:
        return {
            "success": False,
            "status": "FAILED",
            "error": "Device is inactive.",
        }

    if not command or not command.strip():
        return {
            "success": False,
            "status": "FAILED",
            "error": "Remediation command is empty.",
        }

    if device.connection_method.upper() != "SSH":
        return {
            "success": False,
            "status": "FAILED",
            "error": (
                "Remediation execution currently supports "
                "SSH devices only."
            ),
        }

    netmiko_device_type = get_netmiko_device_type(
        vendor=device.vendor,
        device_type=device.device_type,
    )

    if not netmiko_device_type:
        return {
            "success": False,
            "status": "FAILED",
            "error": (
                f"Unsupported vendor/device type: "
                f"{device.vendor or 'Unknown'}"
            ),
        }

    normalized_command = command.strip()

    if dry_run:
        return {
            "success": True,
            "status": "DRY_RUN",
            "dry_run": True,
            "device_id": device.id,
            "hostname": device.hostname,
            "management_ip": device.management_ip,
            "vendor": device.vendor,
            "device_type": netmiko_device_type,
            "command": normalized_command,
            "message": (
                "Dry run successful. The command was validated "
                "for execution but was not sent to the device."
            ),
        }

    result = execute_ssh_command(
        host=device.management_ip,
        username=username,
        password=password,
        device_type=netmiko_device_type,
        command=normalized_command,
        port=port,
        secret=secret,
    )

    if not result["success"]:
        return {
            "success": False,
            "status": "FAILED",
            "dry_run": False,
            "device_id": device.id,
            "hostname": device.hostname,
            "vendor": device.vendor,
            "device_type": netmiko_device_type,
            "command": normalized_command,
            "error": result.get("error"),
        }

    return {
        "success": True,
        "status": "EXECUTED",
        "dry_run": False,
        "device_id": device.id,
        "hostname": device.hostname,
        "vendor": device.vendor,
        "device_type": netmiko_device_type,
        "command": normalized_command,
        "output": result.get("output", ""),
    }