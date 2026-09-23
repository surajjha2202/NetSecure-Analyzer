import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { API_URL } from "../api/client";

const FRAMEWORKS = [
  {
    key: "CIS",
    name: "CIS",
    description: "Center for Internet Security",
  },
  {
    key: "NIST",
    name: "NIST",
    description: "National Institute of Standards and Technology",
  },
  {
    key: "DISA_STIG",
    name: "DISA STIG",
    description: "Defense Information Systems Agency",
  },
  {
    key: "ISO_27001",
    name: "ISO/IEC 27001",
    description: "Information security management controls",
  },
];

function frameworkDisplayName(name) {
  if (name === "DISA_STIG") return "DISA STIG";
  if (name === "ISO_27001") return "ISO/IEC 27001";
  return name;
}

function statusClass(status) {
  const value = String(status || "").toUpperCase();

  if (value === "PASS") return "status-pass";
  if (value === "FAIL") return "status-fail";
  if (value === "N/A") return "status-na";

  return "status-na";
}

function normalizeConfigurations(response) {
  if (Array.isArray(response)) return response;

  return (
    response?.configurations ||
    response?.items ||
    []
  );
}

export default function Compliance({ token }) {
  const [configurations, setConfigurations] = useState([]);
  const [selectedConfigurationId, setSelectedConfigurationId] = useState("");
  const [compliance, setCompliance] = useState(null);
  const [frameworkResults, setFrameworkResults] = useState([]);
  const [selectedFramework, setSelectedFramework] = useState("CIS");

  const [loadingConfigurations, setLoadingConfigurations] = useState(true);
  const [loadingAnalysis, setLoadingAnalysis] = useState(false);
  const [error, setError] = useState(null);

  const api = useMemo(() => {
    return axios.create({
      baseURL: API_URL,
      headers: token
        ? {
            Authorization: `Bearer ${token}`,
          }
        : {},
    });
  }, [token]);

  async function loadConfigurations({ clearSelection = false } = {}) {
    try {
      setLoadingConfigurations(true);
      setError(null);

      const response = await api.get("/api/configurations");

      const items = normalizeConfigurations(response.data);

      setConfigurations(items);

      if (clearSelection) {
        setSelectedConfigurationId("");
        setCompliance(null);
        setFrameworkResults([]);
        setSelectedFramework("CIS");
      }

      return items;
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          "Unable to load configurations."
      );

      return [];
    } finally {
      setLoadingConfigurations(false);
    }
  }

  async function analyzeConfiguration(configurationId = selectedConfigurationId) {
    if (!configurationId) {
      setError("Select a configuration first.");
      return;
    }

    try {
      setLoadingAnalysis(true);
      setError(null);

      const frameworks = [
        "CIS",
        "NIST",
        "DISA_STIG",
        "ISO_27001",
      ];

      const params = new URLSearchParams();

      frameworks.forEach((framework) => {
        params.append("frameworks", framework);
      });

      const response = await api.post(
        `/api/configurations/${configurationId}/analyze?${params.toString()}`
      );

      const data = response.data;

        setCompliance(data.compliance || null);

        const normalizedFrameworkResults = Object.entries(
          data.framework_results || {}
        ).map(([framework, result]) => ({
          framework,
          ...result,
        }));

        setFrameworkResults(normalizedFrameworkResults);
    } catch (err) {
      console.error("Compliance analysis failed:", err);

      const detail = err.response?.data?.detail;

      let errorMessage =
        "Unable to analyze the selected configuration.";

      if (typeof detail === "string") {
        errorMessage = detail;
      } else if (Array.isArray(detail)) {
        errorMessage = detail
          .map((item) => item?.msg || JSON.stringify(item))
          .join("; ");
      } else if (detail && typeof detail === "object") {
        errorMessage =
          detail.msg ||
          JSON.stringify(detail);
      }

      setError(errorMessage);
    } finally {
      setLoadingAnalysis(false);
    }
  }

  useEffect(() => {
    loadConfigurations();
  }, []);

  const selectedFrameworkResult =
    frameworkResults.find(
      (item) =>
        String(item.framework || "").toUpperCase() ===
        selectedFramework
    ) || null;

  const summary =
    selectedFrameworkResult ||
    (
      String(compliance?.framework || "").toUpperCase() ===
      selectedFramework
        ? compliance
        : null
    );

  const results = summary?.results || [];

  return (
    <section className="module-page compliance-page">
      <div className="module-page-header">
        <div>
          <span className="eyebrow">SECURITY OPERATIONS</span>

          <h1>Compliance</h1>

          <p>
            Assess network configurations against active
            security compliance frameworks.
          </p>
        </div>

        <button
          className="secondary-button"
          onClick={() =>
            loadConfigurations({ clearSelection: true })
          }
          disabled={loadingConfigurations}
        >
          {loadingConfigurations ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="module-error">
          {error}
        </div>
      )}

      <div className="module-card compliance-selector">
        <div>
          <h2>Configuration Assessment</h2>

          <p>
            Choose a configuration to assess against the
            active security frameworks.
          </p>
        </div>

        <div className="compliance-selector-row">
          <select
            value={selectedConfigurationId}
            onChange={(event) => {
              setSelectedConfigurationId(event.target.value);
              setCompliance(null);
              setFrameworkResults([]);
              setSelectedFramework("CIS");
              setError(null);
            }}
            disabled={loadingConfigurations}
          >
            <option value="">
              {loadingConfigurations
                ? "Loading configurations..."
                : "Choose configuration"}
            </option>

            {configurations.map((configuration) => (
              <option
                key={configuration.id}
                value={configuration.id}
              >
                #{configuration.id} —{" "}
                {configuration.filename}
              </option>
            ))}
          </select>

          <button
            className="primary-button"
            onClick={() => analyzeConfiguration()}
            disabled={
              loadingAnalysis ||
              !selectedConfigurationId
            }
          >
            {loadingAnalysis
              ? "Analyzing..."
              : "Run Compliance Analysis"}
          </button>
        </div>
      </div>

      <div className="framework-grid">
        {FRAMEWORKS.map((framework) => {
          const result =
            frameworkResults.find(
              (item) =>
                String(item.framework || "").toUpperCase() ===
                framework.key
            );

          const percentage =
            result?.compliance_percentage;

          return (
            <button
              key={framework.key}
              className={`framework-card ${
                selectedFramework === framework.key
                  ? "framework-card-active"
                  : ""
              }`}
              onClick={() =>
                setSelectedFramework(framework.key)
              }
            >
              <div className="framework-card-top">
                <strong>{framework.name}</strong>

                {result && (
                  <span className="framework-percentage">
                    {Number(percentage || 0).toFixed(0)}%
                  </span>
                )}
              </div>

              <span>{framework.description}</span>

              {result ? (
                <div className="framework-mini-stats">
                  <span>
                    PASS {result.pass_count ?? 0}
                  </span>

                  <span>
                    FAIL {result.fail_count ?? 0}
                  </span>

                  <span>
                    N/A {result.na_count ?? 0}
                  </span>
                </div>
              ) : (
                <div className="framework-awaiting">
                  Awaiting assessment
                </div>
              )}
            </button>
          );
        })}
      </div>

      {summary && (
        <>
          <div className="compliance-summary-grid">
            <div className="stat-card">
              <span className="stat-label">
                FRAMEWORK
              </span>

              <strong>
                {frameworkDisplayName(
                  summary.framework
                )}
              </strong>

              <span>
                {summary.total_rules ?? 0} controls
              </span>
            </div>

            <div className="stat-card">
              <span className="stat-label">
                COMPLIANCE
              </span>

              <strong>
                {Number(
                  summary.compliance_percentage || 0
                ).toFixed(0)}
                %
              </strong>

              <span>
                Applicable controls
              </span>
            </div>

            <div className="stat-card">
              <span className="stat-label">
                PASS
              </span>

              <strong className="text-pass">
                {summary.pass_count ?? 0}
              </strong>

              <span>
                Controls passing
              </span>
            </div>

            <div className="stat-card">
              <span className="stat-label">
                FAIL
              </span>

              <strong className="text-fail">
                {summary.fail_count ?? 0}
              </strong>

              <span>
                Controls requiring attention
              </span>
            </div>

            <div className="stat-card">
              <span className="stat-label">
                N/A
              </span>

              <strong>
                {summary.na_count ?? 0}
              </strong>

              <span>
                Controls not applicable
              </span>
            </div>
          </div>

          <div className="module-card compliance-results">
            <div className="module-card-header">
              <div>
                <h2>
                  {frameworkDisplayName(
                    summary.framework
                  )}{" "}
                  Controls
                </h2>

                <p>
                  Detailed results for the selected
                  compliance framework.
                </p>
              </div>
            </div>

            {results.length === 0 ? (
              <div className="empty-state">
                No control results returned.
              </div>
            ) : (
              <div className="compliance-table-wrapper">
                <table className="compliance-table">
                  <thead>
                    <tr>
                      <th>CONTROL</th>
                      <th>STATUS</th>
                      <th>TITLE</th>
                      <th>EXPECTED</th>
                      <th>ACTUAL</th>
                      <th>CONFIDENCE</th>
                    </tr>
                  </thead>

                  <tbody>
                    {results.map((result, index) => (
                      <tr
                        key={
                          result.rule_id ||
                          `${selectedFramework}-${index}`
                        }
                      >
                        <td>
                          <strong>
                            {result.rule_id || "—"}
                          </strong>
                        </td>

                        <td>
                          <span
                            className={`compliance-status ${statusClass(
                              result.status
                            )}`}
                          >
                            {result.status || "N/A"}
                          </span>
                        </td>

                        <td>
                          {result.title ||
                            result.description ||
                            "—"}
                        </td>

                        <td>
                          {String(
                            result.expected_value ?? "—"
                          )}
                        </td>

                        <td>
                          {String(
                            result.actual_value ?? "N/A"
                          )}
                        </td>

                        <td>
                          {result.confidence != null
                            ? Number(
                                result.confidence
                              ).toFixed(2)
                            : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      {!summary && !loadingAnalysis && (
        <div className="module-card empty-state">
          Select a configuration and run a compliance
          analysis to view CIS, NIST, DISA STIG and
          ISO/IEC 27001 results.
        </div>
      )}
    </section>
  );
}