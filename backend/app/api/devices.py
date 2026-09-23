from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from app.db.database import SessionLocal
from app.models import Configuration, Device, User
from app.schemas.device import (
    DeviceCreate,
    DeviceResponse,
    DeviceScanRequest,
)
from app.services.audit_service import create_audit_log
from app.services.permission_dependency import require_permission
from app.services.ssh_scanner import scan_ssh_device
from app.services.device_intelligence import analyze_device
from app.services.network_device_mapping import get_netmiko_device_type
from app.services.analysis_service import analyze_configuration_content
from app.api.configurations import _normalize_frameworks

router = APIRouter(prefix="/devices", tags=["Devices"])


@router.post("", response_model=DeviceResponse)
def create_device(
    device_data: DeviceCreate,
    current_user: User = Depends(
        require_permission("devices.manage")
    ),
):
    db = SessionLocal()

    try:
        existing_device = db.scalar(
            select(Device).where(
                Device.management_ip == device_data.management_ip,
                Device.owner_id == current_user.id,
            )
        )

        if existing_device:
            raise HTTPException(
                status_code=409,
                detail=(
                    "A device with this management IP "
                    "already exists in your account."
                ),
            )

        device = Device(
            owner_id=current_user.id,
            hostname=device_data.hostname,
            management_ip=device_data.management_ip,
            vendor=device_data.vendor,
            product=device_data.product,
            platform=device_data.platform,
            model=device_data.model,
            firmware=device_data.firmware,
            serial_number=device_data.serial_number,
            device_type=device_data.device_type,
            connection_method=device_data.connection_method,
            is_active=True,
        )

        db.add(device)
        db.commit()
        db.refresh(device)

        create_audit_log(
            db=db,
            action="DEVICE_CREATED",
            status="SUCCESS",
            user=current_user,
            resource_type="device",
            resource_id=str(device.id),
            details={
                "hostname": device.hostname,
                "management_ip": device.management_ip,
                "vendor": device.vendor,
                "connection_method": device.connection_method,
            },
        )

        response = DeviceResponse(
            id=device.id,
            hostname=device.hostname,
            management_ip=device.management_ip,
            vendor=device.vendor,
            product=device.product,
            platform=device.platform,
            model=device.model,
            firmware=device.firmware,
            serial_number=device.serial_number,
            device_type=device.device_type,
            connection_method=device.connection_method,
            is_active=device.is_active,
            last_scan_status=device.last_scan_status,
            last_scanned_at=device.last_scanned_at,
            created_at=device.created_at,
            updated_at=device.updated_at,
        )

        return response

    except HTTPException:
        raise

    except Exception:
        db.rollback()

        create_audit_log(
            db=db,
            action="DEVICE_CREATE_FAILED",
            status="FAILED",
            user=current_user,
            details={
                "hostname": device_data.hostname,
                "management_ip": device_data.management_ip,
            },
        )

        raise

    finally:
        db.close()


@router.get("", response_model=list[DeviceResponse])
def list_devices(
    current_user: User = Depends(
        require_permission("devices.view")
    ),
):
    db = SessionLocal()

    try:
        devices = db.scalars(
            select(Device)
            .where(Device.owner_id == current_user.id)
            .order_by(Device.created_at.desc())
        ).all()

        return devices

    finally:
        db.close()


@router.get("/{device_id}", response_model=DeviceResponse)
def get_device(
    device_id: int,
    current_user: User = Depends(
        require_permission("devices.view")
    ),
):
    db = SessionLocal()

    try:
        device = db.scalar(
            select(Device).where(
                Device.id == device_id,
                Device.owner_id == current_user.id,
            )
        )

        if not device:
            raise HTTPException(
                status_code=404,
                detail="Device not found.",
            )

        return device

    finally:
        db.close()


@router.post("/{device_id}/scan")
def scan_device(
    device_id: int,
    scan_request: DeviceScanRequest,
    current_user: User = Depends(
        require_permission("scans.run")
    ),
):
    db = SessionLocal()

    try:
        device = db.scalar(
            select(Device).where(
                Device.id == device_id,
                Device.owner_id == current_user.id,
            )
        )

        if not device:
            raise HTTPException(
                status_code=404,
                detail="Device not found.",
            )

        if not device.is_active:
            raise HTTPException(
                status_code=400,
                detail="Device is inactive.",
            )

        # Resolve the Netmiko driver from the stored vendor/device metadata.
        # Never silently fall back to Cisco for an unknown vendor.
        netmiko_device_type = get_netmiko_device_type(
            vendor=device.vendor,
            device_type=device.device_type,
        )

        if not netmiko_device_type:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Unable to determine a supported Netmiko device type "
                    f"for vendor '{device.vendor or 'Unknown'}'. "
                    "Set a supported vendor before starting a live scan."
                ),
            )

        device.last_scan_status = "SCANNING"
        db.commit()

        result = scan_ssh_device(
            host=device.management_ip,
            username=scan_request.username,
            password=scan_request.password,
            device_type=netmiko_device_type,
            port=scan_request.port,
            secret=scan_request.secret,
        )

        if not result["success"]:
            device.last_scan_status = "FAILED"
            db.commit()

            create_audit_log(
                db=db,
                action="DEVICE_SCAN_FAILED",
                status="FAILED",
                user=current_user,
                resource_type="device",
                resource_id=str(device.id),
                details={
                    "hostname": device.hostname,
                    "management_ip": device.management_ip,
                    "vendor": device.vendor,
                    "netmiko_device_type": netmiko_device_type,
                    "error": result.get("error"),
                },
            )

            return {
                "device_id": device.id,
                "hostname": device.hostname,
                "status": "FAILED",
                "error": result.get("error"),
                "netmiko_device_type": netmiko_device_type,
            }

        running_configuration = result["configuration"]

        # Refresh device intelligence from the actual running configuration.
        intelligence = analyze_device(
            configuration=running_configuration,
            existing_metadata={
                "vendor": device.vendor,
                "product": device.product,
                "platform": device.platform,
                "model": device.model,
                "firmware": device.firmware,
                "serial_number": device.serial_number,
                "device_type": device.device_type,
            },
        )

        device.vendor = intelligence["vendor"]
        device.product = intelligence["product"]
        device.platform = intelligence["platform"]
        device.model = intelligence["model"]
        device.firmware = intelligence["firmware"]
        device.serial_number = intelligence["serial_number"]
        device.device_type = intelligence["device_type"]

        # Run the same production analysis pipeline used by uploaded
        # configurations.
        selected_frameworks = _normalize_frameworks(
            scan_request.frameworks
        )

        analysis = analyze_configuration_content(
            content=running_configuration,
            frameworks=selected_frameworks,
        )

        configuration = Configuration(
            original_filename=f"{device.hostname}_running_config.cfg",
            file_extension=".cfg",
            file_size=len(
                running_configuration.encode("utf-8")
            ),
            content=running_configuration,
            upload_status="LIVE_SCAN",
            uploaded_by=current_user.id,
        )

        db.add(configuration)

        device.last_scan_status = "SUCCESS"
        device.last_scanned_at = datetime.utcnow()

        db.commit()
        db.refresh(configuration)

        create_audit_log(
            db=db,
            action="DEVICE_SCAN_SUCCESS",
            status="SUCCESS",
            user=current_user,
            resource_type="device",
            resource_id=str(device.id),
            details={
                "hostname": device.hostname,
                "management_ip": device.management_ip,
                "vendor": device.vendor,
                "netmiko_device_type": netmiko_device_type,
                "configuration_id": configuration.id,
                "compliance_percentage": analysis["compliance"].get(
                    "compliance_percentage"
                ),
                "risk_score": analysis["risk"].get(
                    "risk_score"
                ),
            },
        )

        return {
            "device_id": device.id,
            "hostname": device.hostname,
            "status": "SUCCESS",
            "configuration_id": configuration.id,
            "configuration_size": configuration.file_size,
            "netmiko_device_type": netmiko_device_type,
            "device_intelligence": analysis["device_intelligence"],
            "parser": analysis["parser"],
            "security_baseline": analysis["security_baseline"],
            "compliance": analysis["compliance"],
            "framework_results": analysis["framework_results"],
            "selected_frameworks": analysis["selected_frameworks"],
            "risk": analysis["risk"],
            "remediation": analysis["remediation"],
            "message": "Configuration collected and analyzed successfully.",
        }

    except HTTPException:
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()
