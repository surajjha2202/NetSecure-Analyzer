import { useEffect, useMemo, useState } from "react";
import api from "../api/client";
import { getDevices } from "../api/devices";
import { getConfigurations } from "../api/configurations";
import { getRemediationRequests } from "../api/remediation";

const FRAMEWORKS = [
  "CIS",
  "NIST",
  "DISA_STIG",
  "ISO_27001",
];

function frameworkName(name) {
  if (name === "DISA_STIG") return "DISA STIG";
  if (name === "ISO_27001") return "ISO/IEC 27001";
  return name;
}

function formatDate(value) {
  if (!value) return "Not available";

  const raw = String(value);
  const normalized = /(?:Z|[+-]\d{2}:\d{2})$/.test(raw)
    ? raw
    : `${raw}Z`;
  const date = new Date(normalized);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: true,
  });
}

function normalizeArray(response, keys = []) {
  if (Array.isArray(response)) {
    return response;
  }

  for (const key of keys) {
    if (Array.isArray(response?.[key])) {
      return response[key];
    }
  }

  return [];
}

function getRemediationStatus(request) {
  return String(
    request?.execution_status ||
      request?.state ||
      "UNKNOWN"
  ).toUpperCase();
}

function statusLabel(status) {
  return String(status || "UNKNOWN")
    .replaceAll("_", " ")
    .replaceAll("EXECUTED UNVERIFIED", "EXECUTED / UNVERIFIED");
}

function statusClass(status) {
  const normalized = String(status || "").toUpperCase();

  if (
    [
      "VERIFIED",
      "SUCCESS",
      "PASS",
      "EXECUTED",
      "APPROVED",
    ].includes(normalized)
  ) {
    return "status-success";
  }

  if (
    [
      "PENDING",
      "DRY_RUN",
      "NOT_SCANNED",
      "UNKNOWN",
    ].includes(normalized)
  ) {
    return "status-warning";
  }

  if (
    [
      "FAILED",
      "ERROR",
      "REJECTED",
      "EXECUTED_UNVERIFIED",
    ].includes(normalized)
  ) {
    return "status-danger";
  }

  return "status-neutral";
}

function Icon({ type }) {
  const common = {
    width: 20,
    height: 20,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": true,
  };

  if (type === "devices") {
    return (
      <svg {...common}>
        <rect x="3" y="4" width="18" height="12" rx="2" />
        <path d="M8 20h8" />
        <path d="M12 16v4" />
      </svg>
    );
  }

  if (type === "scan") {
    return (
      <svg {...common}>
        <path d="M4 7V5a1 1 0 0 1 1-1h2" />
        <path d="M17 4h2a1 1 0 0 1 1 1v2" />
        <path d="M20 17v2a1 1 0 0 1-1 1h-2" />
        <path d="M7 20H5a1 1 0 0 1-1-1v-2" />
        <circle cx="12" cy="12" r="3" />
      </svg>
    );
  }

  if (type === "alert") {
    return (
      <svg {...common}>
        <path d="M12 3 2.8 19a1 1 0 0 0 .9 1.5h16.6a1 1 0 0 0 .9-1.5L12 3Z" />
        <path d="M12 9v4" />
        <path d="M12 17h.01" />
      </svg>
    );
  }

  if (type === "config") {
    return (
      <svg {...common}>
        <path d="M4 5h16" />
        <path d="M4 12h16" />
        <path d="M4 19h16" />
        <circle cx="9" cy="5" r="2" />
        <circle cx="15" cy="12" r="2" />
        <circle cx="11" cy="19" r="2" />
      </svg>
    );
  }

  if (type === "shield") {
    return (
      <svg {...common}>
        <path d="M12 3 20 6v5c0 5-3.2 8.6-8 10-4.8-1.4-8-5-8-10V6l8-3Z" />
        <path d="m8.5 12 2.2 2.2 4.8-4.8" />
      </svg>
    );
  }

  if (type === "clock") {
    return (
      <svg {...common}>
        <circle cx="12" cy="12" r="8.5" />
        <path d="M12 7v5l3.5 2" />
      </svg>
    );
  }

  if (type === "activity") {
    return (
      <svg {...common}>
        <path d="M3 12h4l2-6 4 12 2-6h6" />
      </svg>
    );
  }

  return (
    <svg {...common}>
      <circle cx="12" cy="12" r="8.5" />
    </svg>
  );
}

function MetricCard({
  label,
  value,
  description,
  icon,
  variant = "",
}) {
  return (
    <article className={`dashboard-metric ${variant}`}>
      <div className="dashboard-metric-top">
        <div className="dashboard-metric-icon">
          <Icon type={icon} />
        </div>

        <span>{label}</span>
      </div>

      <strong className="dashboard-metric-value">
        {value}
      </strong>

      <p>{description}</p>
    </article>
  );
}

function StatusPill({ status }) {
  return (
    <span
      className={`dashboard-status-pill ${statusClass(
        status
      )}`}
    >
      {statusLabel(status)}
    </span>
  );
}

function SectionHeader({ title, description }) {
  return (
    <div className="dashboard-section-header">
      <div>
        <h2>{title}</h2>

        {description && <p>{description}</p>}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [devices, setDevices] = useState([]);
  const [configurations, setConfigurations] = useState([]);
  const [remediationRequests, setRemediationRequests] =
    useState([]);
  const [auditLogs, setAuditLogs] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function loadDashboard() {
      try {
        setLoading(true);
        setError(null);

        const [
          devicesResponse,
          configurationsResponse,
          remediationResponse,
          auditResponse,
        ] = await Promise.all([
          getDevices(),
          getConfigurations(),
          getRemediationRequests({
            limit: 20,
            offset: 0,
          }),
          api.get("/api/audit/logs", {
            params: {
              page: 1,
              page_size: 8,
            },
          }),
        ]);

        if (cancelled) return;

        setDevices(
          normalizeArray(devicesResponse, [
            "devices",
            "items",
          ])
        );

        setConfigurations(
          normalizeArray(configurationsResponse, [
            "configurations",
            "items",
          ])
        );

        setRemediationRequests(
          normalizeArray(remediationResponse, [
            "requests",
            "items",
          ])
        );

        setAuditLogs(
          normalizeArray(auditResponse?.data, [
            "logs",
            "items",
          ])
        );
      } catch (err) {
        console.error(err);

        if (cancelled) return;

        setError(
          err.response?.data?.detail ||
            "Unable to load dashboard data."
        );
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadDashboard();

    return () => {
      cancelled = true;
    };
  }, []);

  const deviceStats = useMemo(() => {
    const successful = devices.filter(
      (device) =>
        String(device.last_scan_status || "")
          .toUpperCase() === "SUCCESS"
    ).length;

    const failed = devices.filter((device) =>
      ["FAILED", "ERROR"].includes(
        String(device.last_scan_status || "")
          .toUpperCase()
      )
    ).length;

    const notScanned = devices.filter((device) => {
      const status = String(
        device.last_scan_status || ""
      ).toUpperCase();

      return !status || status === "NOT_SCANNED";
    }).length;

    return {
      successful,
      failed,
      notScanned,
    };
  }, [devices]);

  const remediationStats = useMemo(() => {
    const stats = {
      pending: 0,
      approved: 0,
      executed: 0,
      unverified: 0,
      verified: 0,
      failed: 0,
    };

    remediationRequests.forEach((request) => {
      const state = String(
        request?.state || ""
      ).toUpperCase();

      const executionStatus = String(
        request?.execution_status || ""
      ).toUpperCase();

      if (state === "PENDING") {
        stats.pending += 1;
      }

      if (state === "APPROVED") {
        stats.approved += 1;
      }

      if (
        state === "EXECUTED" ||
        executionStatus === "EXECUTED"
      ) {
        stats.executed += 1;
      }

      if (executionStatus === "EXECUTED_UNVERIFIED") {
        stats.unverified += 1;
      }

      if (executionStatus === "VERIFIED") {
        stats.verified += 1;
      }

      if (
        [
          "FAILED",
          "EXECUTED_UNVERIFIED",
        ].includes(executionStatus) ||
        state === "REJECTED"
      ) {
        stats.failed += 1;
      }
    });

    return stats;
  }, [remediationRequests]);

  const recentRemediations = useMemo(() => {
    return [...remediationRequests]
      .sort((a, b) => {
        const first = new Date(
          a?.created_at ||
            a?.executed_at ||
            0
        ).getTime();

        const second = new Date(
          b?.created_at ||
            b?.executed_at ||
            0
        ).getTime();

        return second - first;
      })
      .slice(0, 5);
  }, [remediationRequests]);

  const recentDevices = useMemo(() => {
    return [...devices]
      .sort((a, b) => {
        const first = new Date(
          a?.last_scanned_at || 0
        ).getTime();

        const second = new Date(
          b?.last_scanned_at || 0
        ).getTime();

        return second - first;
      })
      .slice(0, 5);
  }, [devices]);

  const recentConfigurations = useMemo(() => {
    return [...configurations]
      .sort((a, b) => {
        const first = new Date(
          a?.created_at ||
            a?.uploaded_at ||
            0
        ).getTime();

        const second = new Date(
          b?.created_at ||
            b?.uploaded_at ||
            0
        ).getTime();

        return second - first;
      })
      .slice(0, 5);
  }, [configurations]);

  const latestConfiguration =
    recentConfigurations[0] || null;

  const latestAnalysis =
    latestConfiguration?.latest_analysis || null;

  const latestAnalysisAvailable =
    Boolean(
      latestAnalysis &&
      latestAnalysis.status === "COMPLETED"
    );

  const selectedFrameworks =
    latestAnalysis?.selected_frameworks || [];

  const platformState =
    error
      ? "Attention Required"
      : loading
        ? "Checking Services"
        : "Operational";

  return (
    <div className="dashboard-page dashboard-page-modern">
      <div className="dashboard-hero">
        <div>
          <span className="eyebrow">
            SECURITY OPERATIONS
          </span>

          <h1>Security Operations Center</h1>

          <p>
            Monitor device health, configuration
            inventory, remediation workflow and
            security operations activity.
          </p>
        </div>

        <div
          className={`dashboard-platform-state ${
            error
              ? "dashboard-platform-error"
              : ""
          }`}
        >
          <span className="dashboard-platform-dot" />

          {platformState}
        </div>
      </div>

      {error && (
        <div className="error dashboard-error">
          {error}
        </div>
      )}

      <section className="dashboard-metrics">
        <MetricCard
          label="Monitored Devices"
          value={loading ? "—" : devices.length}
          description="Registered network devices"
          icon="devices"
        />

        <MetricCard
          label="Successful Scans"
          value={
            loading
              ? "—"
              : deviceStats.successful
          }
          description="Latest scan completed successfully"
          icon="scan"
          variant="dashboard-metric-success"
        />

        <MetricCard
          label="Failed Scans"
          value={
            loading
              ? "—"
              : deviceStats.failed
          }
          description="Devices requiring investigation"
          icon="alert"
          variant={
            deviceStats.failed > 0
              ? "dashboard-metric-danger"
              : ""
          }
        />

        <MetricCard
          label="Configurations"
          value={
            loading
              ? "—"
              : configurations.length
          }
          description="Stored configuration snapshots"
          icon="config"
        />
      </section>

      <section className="dashboard-primary-grid">
        <div className="dashboard-panel dashboard-posture-panel">
          <SectionHeader
            title="Security Posture"
            description="Current operational state derived from registered devices and security workflow data."
          />

          <div className="dashboard-posture-main">
            <div className="dashboard-posture-score">
              <span>Scan Success Rate</span>

              <strong>
                {loading || devices.length === 0
                  ? "—"
                  : `${Math.round(
                      (deviceStats.successful /
                        devices.length) *
                        100
                    )}%`}
              </strong>

              <small>
                Based on latest device scan status
              </small>
            </div>

            <div className="dashboard-posture-stats">
              <div>
                <span>Successful</span>
                <strong>
                  {loading
                    ? "—"
                    : deviceStats.successful}
                </strong>
              </div>

              <div>
                <span>Failed</span>
                <strong>
                  {loading
                    ? "—"
                    : deviceStats.failed}
                </strong>
              </div>

              <div>
                <span>Not scanned</span>
                <strong>
                  {loading
                    ? "—"
                    : deviceStats.notScanned}
                </strong>
              </div>
            </div>
          </div>

          <div className="dashboard-posture-note">
            <Icon type="shield" />

            <div>
              <strong>
                Latest Compliance Analysis
              </strong>

              {latestAnalysisAvailable ? (
                <>
                  <p>
                    Configuration #
                    {latestConfiguration.id} was analyzed against{" "}
                    {selectedFrameworks.length} security frameworks.
                  </p>

                  <div className="dashboard-posture-stats">
                    <div>
                      <span>Compliance</span>

                      <strong>
                        {latestAnalysis.compliance_percentage !==
                        null &&
                        latestAnalysis.compliance_percentage !==
                          undefined
                          ? `${latestAnalysis.compliance_percentage}%`
                          : "—"}
                      </strong>
                    </div>

                    <div>
                      <span>Risk Score</span>

                      <strong>
                        {latestAnalysis.risk_score ??
                          "—"}
                      </strong>
                    </div>

                    <div>
                      <span>Risk Level</span>

                      <strong>
                        {latestAnalysis.risk_level
                          ? String(
                              latestAnalysis.risk_level
                            ).replaceAll("_", " ")
                          : "—"}
                      </strong>
                    </div>
                  </div>
                </>
              ) : (
                <p>
                  Compliance and risk scores are shown after
                  a configuration or live device scan is
                  analyzed.
                </p>
              )}
            </div>
          </div>
        </div>

        <div className="dashboard-panel">
          <SectionHeader
            title="Remediation Queue"
            description="Current change-management workflow."
          />

          <div className="dashboard-remediation-grid">
            <div>
              <span>Pending approval</span>
              <strong>
                {loading
                  ? "—"
                  : remediationStats.pending}
              </strong>
            </div>

            <div>
              <span>Approved</span>
              <strong>
                {loading
                  ? "—"
                  : remediationStats.approved}
              </strong>
            </div>

            <div>
              <span>Unverified</span>
              <strong>
                {loading
                  ? "—"
                  : remediationStats.unverified}
              </strong>
            </div>

            <div>
              <span>Verified</span>
              <strong>
                {loading
                  ? "—"
                  : remediationStats.verified}
              </strong>
            </div>
          </div>

          <div className="dashboard-queue-status">
            <Icon
              type={
                remediationStats.failed > 0
                  ? "alert"
                  : "shield"
              }
            />

            <div>
              <strong>
                {remediationStats.failed > 0
                  ? `${remediationStats.failed} remediation action${
                      remediationStats.failed === 1
                        ? ""
                        : "s"
                    } need attention`
                  : "No failed remediation actions"}
              </strong>

              <p>
                Review remediation history for
                execution and verification details.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="dashboard-secondary-grid">
        <div className="dashboard-panel">
          <SectionHeader
            title="Compliance Frameworks"
            description="Supported assessment frameworks."
          />

          <div className="dashboard-framework-list">
            {FRAMEWORKS.map((framework) => (
              <div
                className="dashboard-framework-row"
                key={framework}
              >
                <div className="dashboard-framework-mark">
                  <Icon type="shield" />
                </div>

                <div className="dashboard-framework-info">
                  <strong>
                    {frameworkName(framework)}
                  </strong>

                  <span>
                    Security assessment framework
                  </span>
                </div>

               <span className="dashboard-framework-state">
                {latestAnalysisAvailable &&
                selectedFrameworks.includes(framework)
                  ? "Analyzed"
                  : latestAnalysisAvailable
                    ? "Not included"
                    : "Awaiting analysis"}
              </span>
              </div>
            ))}
          </div>
        </div>

        <div className="dashboard-panel">
          <SectionHeader
            title="Latest Configuration"
            description="Most recent configuration snapshot."
          />

          {latestConfiguration ? (
            <div className="dashboard-latest-config">
              <div className="dashboard-config-icon">
                <Icon type="config" />
              </div>

              <div>
                <strong>
                  {latestConfiguration.filename ||
                    `Configuration #${latestConfiguration.id}`}
                </strong>

                <span>
                  Configuration #
                  {latestConfiguration.id}
                </span>

                <span>
                  {latestConfiguration.status ||
                    "Stored"}
                  {" · "}
                  {formatDate(
                    latestConfiguration.created_at ||
                      latestConfiguration.uploaded_at
                  )}
                </span>
              </div>
            </div>
          ) : (
            <div className="dashboard-empty">
              <Icon type="config" />

              <strong>
                No configurations available
              </strong>

              <p>
                Upload or collect a device
                configuration to begin analysis.
              </p>
            </div>
          )}
        </div>
      </section>

      <section className="dashboard-secondary-grid">
        <div className="dashboard-panel">
          <SectionHeader
            title="Device Security"
            description="Latest registered network devices."
          />

          {loading ? (
            <div className="dashboard-empty">
              <p>Loading device inventory...</p>
            </div>
          ) : recentDevices.length === 0 ? (
            <div className="dashboard-empty">
              <Icon type="devices" />

              <strong>
                No devices registered
              </strong>

              <p>
                Register a network device to begin
                authenticated security scanning.
              </p>
            </div>
          ) : (
            <div className="dashboard-device-list">
              {recentDevices.map((device) => {
                const status =
                  device.last_scan_status ||
                  device.status ||
                  "NOT_SCANNED";

                return (
                  <div
                    className="dashboard-device-row"
                    key={device.id}
                  >
                    <div className="dashboard-device-main">
                      <div className="dashboard-device-icon">
                        <Icon type="devices" />
                      </div>

                      <div>
                        <strong>
                          {device.hostname ||
                            `Device #${device.id}`}
                        </strong>

                        <span>
                          {device.vendor ||
                            "Unknown vendor"}
                          {" · "}
                          {device.platform ||
                            "Unknown platform"}
                        </span>
                      </div>
                    </div>

                    <div className="dashboard-device-status">
                      <StatusPill status={status} />

                      <small>
                        {device.last_scanned_at
                          ? formatDate(
                              device.last_scanned_at
                            )
                          : "Never scanned"}
                      </small>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="dashboard-panel">
          <SectionHeader
            title="Recent Remediation Activity"
            description="Latest change-management actions."
          />

          {recentRemediations.length === 0 ? (
            <div className="dashboard-empty">
              <Icon type="activity" />

              <strong>
                No remediation activity
              </strong>

              <p>
                Remediation requests will appear here
                after findings are submitted.
              </p>
            </div>
          ) : (
            <div className="dashboard-remediation-list">
              {recentRemediations.map((request) => {
                const status =
                  getRemediationStatus(request);

                return (
                  <div
                    className="dashboard-remediation-row"
                    key={request.id}
                  >
                    <div>
                      <strong>
                        {request.rule_id ||
                          "Security control"}
                      </strong>

                      <span>
                        {request.vendor ||
                          "Unknown vendor"}
                        {" · "}
                        {request.command ||
                          "Remediation action"}
                      </span>
                    </div>

                    <div>
                      <StatusPill status={status} />

                      <small>
                        {formatDate(
                          request.executed_at ||
                            request.created_at
                        )}
                      </small>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </section>

      <section className="dashboard-panel dashboard-activity-panel">
        <SectionHeader
          title="Recent Security Activity"
          description="Latest events recorded in the security audit trail."
        />

        {auditLogs.length === 0 ? (
          <div className="dashboard-empty">
            <Icon type="activity" />

            <strong>
              No recent audit events
            </strong>

            <p>
              Security operations activity will
              appear here as the platform is used.
            </p>
          </div>
        ) : (
          <div className="dashboard-audit-list">
            {auditLogs.slice(0, 8).map((log) => (
              <div
                className="dashboard-audit-row"
                key={log.id}
              >
                <div className="dashboard-audit-icon">
                  <Icon type="activity" />
                </div>

                <div className="dashboard-audit-content">
                  <strong>
                    {log.action ||
                      log.resource_type ||
                      "Security activity"}
                  </strong>

                  <span>
                    {log.resource_type
                      ? `${log.resource_type}${
                          log.resource_id
                            ? ` #${log.resource_id}`
                            : ""
                        }`
                      : "System activity"}
                    {" · "}
                    {log.username ||
                      "System user"}
                  </span>
                </div>

                <div className="dashboard-audit-meta">
                  <StatusPill
                    status={
                      log.status || "UNKNOWN"
                    }
                  />

                  <small>
                    {formatDate(log.created_at)}
                  </small>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
