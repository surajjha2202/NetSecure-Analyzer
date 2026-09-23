import { useEffect, useState } from "react";
import {
  createDevice,
  getDevices,
} from "../api/devices";
import StatusBadge from "../components/StatusBadge";

function valueOrUnknown(value) {
  return value === null || value === undefined || value === ""
    ? "Unknown"
    : value;
}

const emptyDeviceForm = {
  hostname: "",
  management_ip: "",
  vendor: "Cisco",
  product: "",
  platform: "",
  model: "",
  firmware: "",
  serial_number: "",
  device_type: "router",
  connection_method: "ssh",
};

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [registering, setRegistering] =
    useState(false);

  const [registerToast, setRegisterToast] =
    useState(null);

  const [showRegisterForm, setShowRegisterForm] =
    useState(false);

  const [deviceForm, setDeviceForm] =
    useState(emptyDeviceForm);

  async function loadDevices() {
    try {
      setLoading(true);
      setError(null);

      const response = await getDevices();

      const data = Array.isArray(response)
        ? response
        : response.devices || response.items || [];

      setDevices(data);
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          "Unable to load registered devices."
      );
    } finally {
      setLoading(false);
    }
  }

async function handleRegisterDevice(event) {
  event.preventDefault();

  try {
    setRegistering(true);
    setError(null);
    setRegisterToast(null);

    const payload = {
      ...deviceForm,
      vendor: deviceForm.vendor || null,
      product: deviceForm.product || null,
      platform: deviceForm.platform || null,
      model: deviceForm.model || null,
      firmware: deviceForm.firmware || null,
      serial_number:
        deviceForm.serial_number || null,
      device_type: deviceForm.device_type || null,
    };

    const device = await createDevice(payload);

    setDeviceForm(emptyDeviceForm);
    setShowRegisterForm(false);

    await loadDevices();

    setRegisterToast({
      type: "success",
      title: "Device added successfully",
      message: `${
        device.hostname || "The device"
      } has been registered successfully.`,
    });
  } catch (err) {
    console.error(err);

    const message =
      err.response?.data?.detail ||
      "Unable to register device.";

    setRegisterToast({
      type: "error",
      title: "Device registration failed",
      message,
    });
  } finally {
    setRegistering(false);
  }
}

  useEffect(() => {
    loadDevices();
  }, []);

  useEffect(() => {
    if (!registerToast) {
      return undefined;
    }

    const timeout = window.setTimeout(() => {
      setRegisterToast(null);
    }, 5000);

    return () => {
      window.clearTimeout(timeout);
    };
  }, [registerToast]);

  return (
    <div className="module-page">
      {registerToast && (
        <div
          className={`device-toast device-toast-${registerToast.type}`}
          role="alert"
        >
          <div className="device-toast-content">
            <strong>{registerToast.title}</strong>
            <span>{registerToast.message}</span>
          </div>

          <button
            type="button"
            className="device-toast-close"
            aria-label="Close notification"
            onClick={() => setRegisterToast(null)}
          >
            ×
          </button>
        </div>
      )}
      <div className="page-heading">
        <div>
          <span className="eyebrow">
            SECURITY OPERATIONS
          </span>

          <h1>Devices</h1>

          <p>
            Manage registered network devices and monitor
            their latest security scan state.
          </p>
        </div>

        <button
          className="secondary-button"
          onClick={loadDevices}
          disabled={loading}
        >
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="error">
          {error}
        </div>
      )}

      <section className="stats-grid">
        <div className="dashboard-card">
          <span className="eyebrow">REGISTERED</span>
          <h2>{loading ? "—" : devices.length}</h2>
          <p>Monitored network devices</p>
        </div>

        <div className="dashboard-card">
          <span className="eyebrow">SUCCESSFUL</span>
          <h2>
            {loading
              ? "—"
              : devices.filter(
                  (device) =>
                    String(
                      device.last_scan_status ||
                        device.status ||
                        ""
                    ).toUpperCase() === "SUCCESS"
                ).length}
          </h2>
          <p>Devices with successful latest scans</p>
        </div>

        <div className="dashboard-card">
          <span className="eyebrow">FAILED</span>
          <h2>
            {loading
              ? "—"
              : devices.filter((device) =>
                  ["FAILED", "ERROR"].includes(
                    String(
                      device.last_scan_status ||
                        device.status ||
                        ""
                    ).toUpperCase()
                  )
                ).length}
          </h2>
          <p>Devices requiring investigation</p>
        </div>
      </section>

      {showRegisterForm && (
      <section className="dashboard-card">
        <div className="card-heading">
          <div>
            <h2>Register Device</h2>

            <p>
              Add a network device before running live SSH
              compliance scans.
            </p>
          </div>

          <button
            type="button"
            className="secondary-button"
            onClick={() => {
              const shouldDiscard = window.confirm(
                "Discard device registration?\n\nAny information entered in this form will be lost."
              );

              if (!shouldDiscard) {
                return;
              }

              setDeviceForm(emptyDeviceForm);
              setShowRegisterForm(false);
              setRegisterToast(null);
              setError(null);
            }}
          >
            Cancel
          </button>
        </div>

        <form
          onSubmit={handleRegisterDevice}
          className="device-registration-form"
          autoComplete="off"
        >
          <div className="device-registration-grid">
            <label>
              Hostname
              <input
                type="text"
                value={deviceForm.hostname}
                onChange={(event) =>
                  setDeviceForm({
                    ...deviceForm,
                    hostname: event.target.value,
                  })
                }
                placeholder="Example: c8000v-sandbox"
                required
              />
            </label>

            <label>
              Management IP / Hostname
              <input
                type="text"
                value={deviceForm.management_ip}
                onChange={(event) =>
                  setDeviceForm({
                    ...deviceForm,
                    management_ip: event.target.value,
                  })
                }
                placeholder="SSH hostname or IP"
                required
              />
            </label>

            <label>
              Vendor
              <input
                type="text"
                value={deviceForm.vendor}
                onChange={(event) =>
                  setDeviceForm({
                    ...deviceForm,
                    vendor: event.target.value,
                  })
                }
              />
            </label>

            <label>
              Product
              <input
                type="text"
                value={deviceForm.product}
                onChange={(event) =>
                  setDeviceForm({
                    ...deviceForm,
                    product: event.target.value,
                  })
                }
                placeholder="Example: Catalyst 8000V"
              />
            </label>

            <label>
              Platform
              <input
                type="text"
                value={deviceForm.platform}
                onChange={(event) =>
                  setDeviceForm({
                    ...deviceForm,
                    platform: event.target.value,
                  })
                }
                placeholder="Example: IOS-XE"
                autoComplete="new-password"
              />
            </label>

            <label>
              Model
              <input
                type="text"
                value={deviceForm.model}
                onChange={(event) =>
                  setDeviceForm({
                    ...deviceForm,
                    model: event.target.value,
                  })
                }
                placeholder="Example: C8000V"
              />
            </label>

            <label>
              Firmware
              <input
                type="text"
                value={deviceForm.firmware}
                onChange={(event) =>
                  setDeviceForm({
                    ...deviceForm,
                    firmware: event.target.value,
                  })
                }
                placeholder="Optional"
              />
            </label>

            <label>
              Serial Number
              <input
                type="text"
                value={deviceForm.serial_number}
                onChange={(event) =>
                  setDeviceForm({
                    ...deviceForm,
                    serial_number: event.target.value,
                  })
                }
                placeholder="Optional"
              />
            </label>

            <label>
              Device Type
              <input
                type="text"
                value={deviceForm.device_type}
                onChange={(event) =>
                  setDeviceForm({
                    ...deviceForm,
                    device_type: event.target.value,
                  })
                }
                placeholder="router"
              />
            </label>

            <label>
              Connection Method
              <input
                type="text"
                value={deviceForm.connection_method}
                onChange={(event) =>
                  setDeviceForm({
                    ...deviceForm,
                    connection_method: event.target.value,
                  })
                }
                required
              />
            </label>
          </div>

          <button
            type="submit"
            className="primary-button"
            disabled={registering}
          >
            {registering
              ? "Registering..."
              : "Register Device"}
          </button>
        </form>
      </section>
      )}

      <section className="dashboard-card">
        <div className="card-heading">
          <div>
            <h2>Registered Devices</h2>
            <p>
              Devices currently known to
              NetSecure Analyzer.
            </p>
          </div>

          <button
            type="button"
            className="primary-button"
            onClick={() => {
              setDeviceForm(emptyDeviceForm);
              setRegisterToast(null);
              setError(null);
              setShowRegisterForm(true);
            }}
          >
            Add Device
          </button>
        </div>

        {loading ? (
          <p className="muted">Loading devices...</p>
        ) : devices.length === 0 ? (
          <p className="muted">
            No devices are currently registered.
          </p>
        ) : (
          <div className="device-table">
            <div className="device-table-header">
              <span>Device</span>
              <span>Vendor</span>
              <span>Platform</span>
              <span>Status</span>
            </div>

            {devices.map((device) => (
              <div
                className="device-table-row"
                key={device.id}
              >
                <div>
                  <strong>
                    {valueOrUnknown(
                      device.hostname
                    )}
                  </strong>

                  <small>
                    Device ID: {device.id}
                  </small>
                </div>

                <span>
                  {valueOrUnknown(device.vendor)}
                </span>

                <span>
                  {valueOrUnknown(
                    device.platform
                  )}
                </span>

                <StatusBadge
                  status={
                    device.last_scan_status ||
                    device.status ||
                    "NOT_SCANNED"
                  }
                />
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
