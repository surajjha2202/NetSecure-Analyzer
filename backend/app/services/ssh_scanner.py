from __future__ import annotations

from typing import Any

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)


def scan_ssh_device(
    host: str,
    username: str,
    password: str,
    device_type: str = "cisco_ios",
    port: int = 22,
    secret: str | None = None,
) -> dict[str, Any]:
    connection_parameters = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 30,
        "conn_timeout": 30,
        "auth_timeout": 30,
        "banner_timeout": 30,
        "ssh_strict": False,
        "use_keys": False,
        "allow_agent": False,
    }

    if secret:
        connection_parameters["secret"] = secret

    connection = None

    try:
        connection = ConnectHandler(**connection_parameters)

        if secret:
            connection.enable()

        hostname = connection.find_prompt().strip()

        running_config = connection.send_command(
            "show running-config",
            read_timeout=60,
        )

        return {
            "success": True,
            "hostname": hostname,
            "configuration": running_config,
            "device_type": device_type,
        }

    except NetmikoAuthenticationException as exc:
        print(f"[SSH AUTH ERROR] {type(exc).__name__}: {exc}")
        return {
            "success": False,
            "error": "SSH authentication failed.",
            "device_type": device_type,
        }

    except NetmikoTimeoutException:
        return {
            "success": False,
            "error": "SSH connection timed out.",
            "device_type": device_type,
        }

    except Exception as exc:
        return {
            "success": False,
            "error": str(exc),
            "device_type": device_type,
        }

    finally:
        if connection:
            connection.disconnect()


def execute_ssh_command(
    host: str,
    username: str,
    password: str,
    device_type: str,
    command: str,
    port: int = 22,
    secret: str | None = None,
) -> dict[str, Any]:
    """
    Execute one approved configuration command over SSH.

    This function deliberately accepts exactly one command.
    """

    connection_parameters = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 30,
        "conn_timeout": 30,
        "auth_timeout": 30,
        "banner_timeout": 30,
        "ssh_strict": False,
        "use_keys": False,
        "allow_agent": False,
    }

    if secret:
        connection_parameters["secret"] = secret

    connection = None

    try:
        connection = ConnectHandler(**connection_parameters)

        if secret:
            connection.enable()

        output = connection.send_config_set(
            [command],
            read_timeout=60,
        )

        return {
            "success": True,
            "command": command,
            "output": output,
            "device_type": device_type,
        }

    except NetmikoAuthenticationException:
        return {
            "success": False,
            "error": "SSH authentication failed.",
            "command": command,
            "device_type": device_type,
        }

    except NetmikoTimeoutException:
        return {
            "success": False,
            "error": "SSH connection timed out.",
            "command": command,
            "device_type": device_type,
        }

    except Exception as exc:
        return {
            "success": False,
            "error": str(exc),
            "command": command,
            "device_type": device_type,
        }

    finally:
        if connection:
            connection.disconnect()