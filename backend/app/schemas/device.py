from datetime import datetime

from pydantic import BaseModel, Field


SUPPORTED_SCAN_FRAMEWORKS = {
    "CIS",
    "NIST",
    "DISA_STIG",
    "ISO_27001",
}


class DeviceCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    management_ip: str = Field(min_length=1, max_length=255)

    vendor: str | None = Field(default=None, max_length=100)
    product: str | None = Field(default=None, max_length=100)
    platform: str | None = Field(default=None, max_length=100)
    model: str | None = Field(default=None, max_length=100)
    firmware: str | None = Field(default=None, max_length=100)
    serial_number: str | None = Field(default=None, max_length=100)
    device_type: str | None = Field(default=None, max_length=100)

    connection_method: str = Field(min_length=1, max_length=50)


class DeviceResponse(BaseModel):
    id: int
    hostname: str
    management_ip: str

    vendor: str | None
    product: str | None
    platform: str | None
    model: str | None
    firmware: str | None
    serial_number: str | None
    device_type: str | None

    connection_method: str
    is_active: bool
    last_scan_status: str | None
    last_scanned_at: datetime | None
    created_at: datetime
    updated_at: datetime


class DeviceScanRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    secret: str | None = None
    frameworks: list[str] = Field(
        default_factory=lambda: ["CIS"],
        min_length=1,
    )
