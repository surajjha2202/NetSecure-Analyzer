from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


def scan_ssh_device_via_agent(
    host: str,
    username: str,
    password: str,
    device_type: str = "cisco_ios",
    port: int = 22,
    secret: str | None = None,
) -> dict[str, Any]:
    agent_url = os.getenv("SCAN_AGENT_URL", "").rstrip("/")
    scanner_token = os.getenv("SCANNER_TOKEN", "")

    if not agent_url:
        return {
            "success": False,
            "error": "SCAN_AGENT_URL is not configured.",
            "device_type": device_type,
        }

    if not scanner_token:
        return {
            "success": False,
            "error": "SCANNER_TOKEN is not configured.",
            "device_type": device_type,
        }

    payload = {
        "host": host,
        "username": username,
        "password": password,
        "device_type": device_type,
        "port": port,
        "secret": secret,
    }

    request = urllib.request.Request(
        url=f"{agent_url}/scan",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Scanner-Token": scanner_token,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=95) as response:
            body = response.read().decode("utf-8")
            result = json.loads(body)

        if not isinstance(result, dict):
            return {
                "success": False,
                "error": "Scanner agent returned an invalid response.",
                "device_type": device_type,
            }

        return result

    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8")
            detail = json.loads(body).get("detail", body)
        except Exception:
            detail = str(exc)

        return {
            "success": False,
            "error": f"Scanner agent HTTP error: {detail}",
            "device_type": device_type,
        }

    except urllib.error.URLError as exc:
        return {
            "success": False,
            "error": f"Scanner agent connection failed: {exc.reason}",
            "device_type": device_type,
        }

    except TimeoutError:
        return {
            "success": False,
            "error": "Scanner agent request timed out.",
            "device_type": device_type,
        }

    except json.JSONDecodeError:
        return {
            "success": False,
            "error": "Scanner agent returned invalid JSON.",
            "device_type": device_type,
        }

    except Exception as exc:
        return {
            "success": False,
            "error": f"Scanner agent error: {exc}",
            "device_type": device_type,
        }
