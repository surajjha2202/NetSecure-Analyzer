import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { getConfigurations } from "../api/configurations";

import { API_URL } from "../api/client";

const FRAMEWORKS = ["CIS", "NIST", "DISA_STIG", "ISO_27001"];

function formatFramework(name) {
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

function normalizeFindings(compliance) {
  if (!compliance) return [];
  if (Array.isArray(compliance.results)) return compliance.results;
  if (Array.isArray(compliance.findings)) return compliance.findings;
  return [];
}

function getFrameworkStats(report) {
  const frameworkResults = report?.framework_results;

  if (
    !frameworkResults ||
    typeof frameworkResults !== "object"
  ) {
    return FRAMEWORKS.map((framework) => ({
      framework,
      available: false,
      pass: 0,
      fail: 0,
      na: 0,
      score: null,
    }));
  }

  return FRAMEWORKS.map((framework) => {
    const result = frameworkResults[framework];

    if (!result) {
      return {
        framework,
        available: false,
        pass: 0,
        fail: 0,
        na: 0,
        score: null,
      };
    }

    const pass = Number(result.pass_count ?? 0);
    const fail = Number(result.fail_count ?? 0);
    const na = Number(result.na_count ?? 0);

    const applicable = pass + fail;

    const score =
      result.compliance_percentage != null
        ? Number(result.compliance_percentage)
        : applicable
          ? (pass / applicable) * 100
          : 0;

    return {
      framework,
      available: true,
      pass,
      fail,
      na,
      score,
    };
  });
}

export default function Reports({ token, onLogout }) {
  const [configurations, setConfigurations] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [report, setReport] = useState(null);
  const [generatedAt, setGeneratedAt] = useState(null);
  const [loadingConfigurations, setLoadingConfigurations] = useState(true);
  const [loadingReport, setLoadingReport] = useState(false);
  const [error, setError] = useState(null);
  const [frameworkFilter, setFrameworkFilter] = useState("ALL");

  async function loadConfigurations() {
    if (!token) return;

    try {
      setLoadingConfigurations(true);
      setError(null);

      const response = await axios.get(
        `${API_URL}/api/configurations`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      const items = Array.isArray(response.data?.configurations)
        ? response.data.configurations
        : [];

      setConfigurations(items);
    } catch (err) {
      console.error(err);

      if (err.response?.status === 401) {
        onLogout?.();
        return;
      }

      setError(
        err.response?.data?.detail ||
          "Unable to load configurations for reporting."
      );
    } finally {
      setLoadingConfigurations(false);
    }
  }

  useEffect(() => {
    loadConfigurations();
  }, [token]);

  async function generateReport(event) {
    event?.preventDefault();

    if (!selectedId) {
      setError("Select a configuration before generating a report.");
      return;
    }

    try {
      setLoadingReport(true);
      setError(null);
      setReport(null);

      const response = await axios.post(
        `${API_URL}/api/configurations/${selectedId}/analyze`,
        null,
        {
          params: new URLSearchParams([
          ["frameworks", "CIS"],
          ["frameworks", "NIST"],
          ["frameworks", "DISA_STIG"],
          ["frameworks", "ISO_27001"],
        ]),
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      setReport(response.data);
      setGeneratedAt(new Date().toISOString());
    } catch (err) {
      console.error(err);

      if (err.response?.status === 401) {
        onLogout?.();
        return;
      }

      setError(
        err.response?.data?.detail ||
          "Unable to generate the compliance report."
      );
    } finally {
      setLoadingReport(false);
    }
  }

  const compliance = report?.compliance || {};
  const risk = report?.risk || {};
  const device = report?.device_intelligence || {};
  const findings = normalizeFindings(compliance);

  const filteredFindings = useMemo(() => {
    if (frameworkFilter === "ALL") return findings;

    return findings.filter((finding) => {
      if (finding.framework === frameworkFilter) return true;

      return Array.isArray(finding.frameworks)
        ? finding.frameworks.some(
            (item) => item?.framework === frameworkFilter
          )
        : false;
    });
  }, [findings, frameworkFilter]);

  const frameworkStats = getFrameworkStats(report);

  function printReport() {
    if (!report) return;
    window.print();
  }
  function clearReport() {
  setSelectedId("");
  setReport(null);
  setGeneratedAt(null);
  setError(null);
  setFrameworkFilter("ALL");
}

  return (
    <section className="reports-page">
      <div className="section-heading report-toolbar">
        <div>
          <span className="eyebrow">GOVERNANCE</span>
          <h2>Security Reports</h2>
          <p>
            Generate and review evidence-backed configuration security
            reports from the analyzer.
          </p>
        </div>

        <button
          type="button"
          className="secondary-button report-print-button"
          onClick={printReport}
          disabled={!report}
        >
          Print / Save PDF
        </button>
      </div>

      {error && <div className="error">{error}</div>}

      <section className="result-card-large report-generator-card">
        <div>
          <h3>Generate Report</h3>
          <p className="muted">
            Select a stored configuration and run the existing analyzer.
            The resulting report can be printed or saved as PDF from the
            browser.
          </p>
        </div>

        <form onSubmit={generateReport}>
          <div className="form-grid">
            <label>
              Configuration
              <select
                value={selectedId}
                  onChange={(event) => {
                    const value = event.target.value;

                    setSelectedId(value);
                    setReport(null);
                    setGeneratedAt(null);
                    setError(null);
                    setFrameworkFilter("ALL");
                  }}
                disabled={loadingConfigurations || loadingReport}
              >
                <option value="">Select configuration</option>
                {configurations.map((configuration) => (
                  <option
                    key={configuration.id}
                    value={configuration.id}
                  >
                    #{configuration.id} —{" "}
                    {configuration.filename ||
                      configuration.name ||
                      "Configuration"}
                  </option>
                ))}
              </select>
            </label>

            <label>
              Framework View
              <select
                value={frameworkFilter}
                onChange={(event) =>
                  setFrameworkFilter(event.target.value)
                }
                disabled={!report}
              >
                <option value="ALL">All Frameworks</option>
                {FRAMEWORKS.map((framework) => (
                  <option key={framework} value={framework}>
                    {formatFramework(framework)}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className="report-generator-actions">
            <button
              type="submit"
              className="primary-button"
              disabled={!selectedId || loadingReport}
            >
              {loadingReport ? "Analyzing..." : "Generate Report"}
            </button>

            <button
              type="button"
              className="secondary-button"
              onClick={clearReport}
              disabled={!selectedId && !report && !error}
            >
              Clear
            </button>
          </div>
        </form>
      </section>

      {!report ? (
        <section className="result-card-large empty-state">
          <h3>No report selected</h3>
          <p>
            Select a configuration and generate a report to review its
            compliance, risk and remediation posture.
          </p>
        </section>
      ) : (
        <div className="report-document" id="print-report">
          <section className="report-header-card">
            <div>
              <span className="eyebrow">NETSECURE ANALYZER</span>

              <span className="report-classification">
                CONFIGURATION SECURITY ASSESSMENT
              </span>
              <h2>Network Security Compliance Report</h2>
              <p className="report-file-name">
                {report.filename ||
                  report.configuration_name ||
                  "Configuration Analysis"}
              </p>
            </div>

            <div className="report-generated-meta">
              <span>Configuration ID</span>
              <strong>{report.configuration_id ?? "—"}</strong>
              <span>Generated</span>
              <strong>{formatDate(generatedAt)}</strong>
            </div>
          </section>

          <section className="result-card-large">
            <h3>Device Profile</h3>

            <div className="remediation-meta-grid">
              <div>
                <span>Vendor</span>
                <strong>{device.vendor || "Unknown"}</strong>
              </div>

              <div>
                <span>Platform</span>
                <strong>{device.platform || "Unknown"}</strong>
              </div>

              <div>
                <span>Product</span>
                <strong>{device.product || "Unknown"}</strong>
              </div>

              <div>
                <span>Model</span>
                <strong>{device.model || "Unknown"}</strong>
              </div>

              <div>
                <span>Device Type</span>
                <strong>{device.device_type || "Unknown"}</strong>
              </div>

              <div>
                <span>Firmware</span>
                <strong>{device.firmware || "Unknown"}</strong>
              </div>

              <div>
                <span>Serial Number</span>
                <strong>{device.serial_number || "Unknown"}</strong>
              </div>
            </div>
          </section>

          <section className="result-card-large">
            <h3>Security Posture</h3>

            <div className="report-stat-grid">
              <div className="report-stat">
                <span>Compliance</span>
                <strong>
                  {compliance.compliance_percentage == null
                    ? "—"
                    : `${Number(compliance.compliance_percentage).toFixed(1)}%`}
                </strong>
              </div>
              <div className="report-stat">
                <span>Rules</span>
                <strong>{compliance.total_rules ?? "—"}</strong>
              </div>

              <div className="report-stat">
                <span>Passed</span>
                <strong>{compliance.pass_count ?? "—"}</strong>
              </div>

              <div className="report-stat">
                <span>Failed</span>
                <strong>{compliance.fail_count ?? "—"}</strong>
              </div>

              <div className="report-stat">
                <span>Not Applicable</span>
                <strong>{compliance.na_count ?? "—"}</strong>
              </div>
              <div className="report-stat">
                <span>Risk Score</span>
                <strong>
                  {risk.risk_score == null
                    ? "—"
                    : Number(risk.risk_score).toFixed(1)}
                </strong>
              </div>
              <div className="report-stat">
                <span>Risk Level</span>
                <strong>{risk.risk_level || "—"}</strong>
              </div>
            </div>
          </section>

          <section className="result-card-large">
            <div className="audit-table-header">
              <div>
                <h3>Framework Coverage</h3>
                <p className="muted">
                  Framework-specific data is shown when returned by the
                  analyzer response.
                </p>
              </div>
            </div>

            <div className="framework-report-grid">
              {frameworkStats.map((item) => (
                <article
                  className="framework-report-card"
                  key={item.framework}
                >
                  <span className="eyebrow">
                    {formatFramework(item.framework)}
                  </span>

                  {item.available ? (
                    <>
                      <strong>
                        {item.score == null
                          ? "—"
                          : `${item.score.toFixed(1)}%`}
                      </strong>
                      <div className="framework-report-meta">
                        <span>PASS {item.pass}</span>
                        <span>FAIL {item.fail}</span>
                        <span>N/A {item.na}</span>
                      </div>
                    </>
                  ) : (
                    <p className="muted">
                      No framework-specific finding metadata in this
                      analysis.
                    </p>
                  )}
                </article>
              ))}
            </div>
          </section>

          <section className="result-card-large">
            <div className="audit-table-header">
              <div>
                <h3>Compliance Findings</h3>
                <p className="muted">
                  {filteredFindings.length} finding
                  {filteredFindings.length === 1 ? "" : "s"}
                </p>
              </div>
            </div>

            {filteredFindings.length === 0 ? (
              <div className="empty-state">
                <p>No findings match the selected framework.</p>
              </div>
            ) : (
              <div className="report-findings-list">
                {filteredFindings.map((finding, index) => (
                  <article
                    className="report-finding"
                    key={
                      finding.rule_id ||
                      `${finding.title || "finding"}-${index}`
                    }
                  >
                    <div>
                      <span className="audit-event-action">
                        {finding.rule_id || "CONTROL"}
                      </span>
                      <h4>{finding.title || "Security control"}</h4>

                      {finding.evidence && (
                        <div className="report-evidence">
                          <span className="report-evidence-label">
                            Evidence
                          </span>

                          <pre>{String(finding.evidence)}</pre>
                        </div>
                      )}
                    </div>

                    <div className="finding-meta">
                      <span
                        className={`finding-badge severity-${String(
                          finding.severity || "unknown"
                        ).toLowerCase()}`}
                      >
                        {finding.severity || "—"}
                      </span>

                      <span
                        className={`finding-badge status-${String(
                          finding.status || "unknown"
                        )
                          .toLowerCase()
                          .replace("/", "-")}`}
                      >
                        {finding.status || "—"}
                      </span>

                      <span className="finding-badge">
                        Confidence{" "}
                        {finding.confidence == null
                          ? "—"
                          : Number(finding.confidence).toFixed(2)}
                      </span>
                    </div>
                  </article>
                ))}
              </div>
            )}
          </section>

          <section className="result-card-large">
            <h3>Remediation Recommendations</h3>

            {(!Array.isArray(report.remediation) ||
              report.remediation.length === 0) ? (
              <p className="muted">
                No remediation recommendations were returned for this
                analysis.
              </p>
            ) : (
              <div className="report-findings-list">
                {report.remediation.map((item, index) => {
                  const remediation = item?.remediation || item;
                  const commands = Array.isArray(remediation?.commands)
                    ? remediation.commands
                    : [];

                  return (
                    <article
                      className="report-finding"
                      key={
                        item?.rule_id ||
                        remediation?.rule_id ||
                        `remediation-${index}`
                      }
                    >
                      <div>
                        <span className="audit-event-action">
                          {item?.rule_id ||
                            remediation?.rule_id ||
                            "REMEDIATION"}
                        </span>
                        <h4>
                          {item?.title ||
                            item?.description ||
                            remediation?.explanation ||
                            "Recommended security change"}
                        </h4>

                        {commands.length > 0 && (
                          <pre>{commands.join("\n")}</pre>
                        )}
                      </div>

                      <div className="finding-meta">
                        <span>
                          {remediation?.vendor || device.vendor || "—"}
                        </span>
                        <span>
                          {remediation?.approval_required
                            ? "Approval required"
                            : "Review required"}
                        </span>
                      </div>
                    </article>
                  );
                })}
              </div>
            )}
          </section>

          <section className="result-card-large report-notes">
            <h3>Report Notes</h3>
            <p>
              Compliance decisions are based on deterministic rules
              implemented by NetSecure Analyzer.
            </p>
            <p>
              Framework references are engineering reference mappings and
              do not constitute benchmark certification.
            </p>
            <p>
              Vendor-specific remediation commands are provided only when
              the corresponding compliance rule has an applicable
              remediation definition.
            </p>
          </section>
        </div>
      )}
    </section>
  );
}
