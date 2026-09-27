from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

app = FastAPI(title="NetSecure SSH Scanner Agent")

SCANNER_TOKEN = os.getenv("SCANNER_TOKEN", "")


class ScanRequest(BaseModel):
    host: str
    username: str
    password: str
    device_type: str = "cisco_ios"
    port: int = Field(default=22, ge=1, le=65535)
    secret: Optional[str] = None


def check_token(token: Optional[str]) -> None:
    if not SCANNER_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="SCANNER_TOKEN is not configured.",
        )

    if token != SCANNER_TOKEN:
        raise HTTPException(
            status_code=401,
            detail="Invalid scanner token.",
        )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "netsecure-scanner-agent",
    }


@app.post("/scan")
def scan(
    request: ScanRequest,
    x_scanner_token: Optional[str] = Header(default=None),
):
    check_token(x_scanner_token)

    connection = None

    connection_parameters = {
        "device_type": request.device_type,
        "host": request.host,
        "username": request.username,
        "password": request.password,
        "port": request.port,
        "timeout": 30,
        "conn_timeout": 30,
        "auth_timeout": 30,
        "banner_timeout": 30,
        "ssh_strict": False,
        "use_keys": False,
        "allow_agent": False,
    }

    if request.secret:
        connection_parameters["secret"] = request.secret

    try:
        connection = ConnectHandler(**connection_parameters)

        if request.secret:
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
            "device_type": request.device_type,
        }

    except NetmikoAuthenticationException:
        return {
            "success": False,
            "error": "SSH authentication failed.",
            "device_type": request.device_type,
        }

    except NetmikoTimeoutException:
        return {
            "success": False,
            "error": "SSH connection timed out.",
            "device_type": request.device_type,
        }

    except Exception as exc:
        return {
            "success": False,
            "error": str(exc),
            "device_type": request.device_type,
        }

    finally:
        if connection:
            connection.disconnect()
