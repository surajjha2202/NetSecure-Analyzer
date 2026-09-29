import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { API_URL } from "../api/client";
import { createRemediationRequest } from "../api/remediation";

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

  const [analysisData, setAnalysisData] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [remediationParameters, setRemediationParameters] = useState({});
  const [remediationCreating, setRemediationCreating] = useState(null);
  const [remediationMessage, setRemediationMessage] = useState(null);
  const [remediationError, setRemediationError] = useState(null);
  const [createdRemediationRules, setCreatedRemediationRules] = useState([]);
  const [showRemediation, setShowRemediation] = useState(false);

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
        setRemediation(null);
        setAnalysisData(null);
        setRemediationParameters({});
        setRemediationMessage(null);
        setRemediationError(null);
        setCreatedRemediationRules([]);
        setShowRemediation(false);


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
      setAnalysisData(null);
      setRemediation(null);
      setRemediationParameters({});
      setRemediationMessage(null);
      setRemediationError(null);
      setCreatedRemediationRules([]);

      setShowRemediation(false);



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

        
      setAnalysisData(data);
      setRemediation(data.remediation || null);
      setRemediationParameters({});
      setRemediationMessage(null);
      setRemediationError(null);
      setCreatedRemediationRules([]);

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

  async function createRemediation(
    item,
    remediationObject
  ) {
    try {
      setRemediationCreating(
        item?.rule_id ||
          remediationObject?.rule_id
      );

      setRemediationError(null);
      setRemediationMessage(null);

      const ruleId =
        item?.rule_id ||
        remediationObject?.rule_id;

      if (!ruleId) {
        throw new Error(
          "Remediation rule ID is missing."
        );
      }

      const vendor =
        remediationObject?.vendor ||
        item?.vendor ||
        analysisData?.device_intelligence?.vendor ||
        analysisData?.vendor ||
        remediation?.vendor ||
        "Unknown";

      const commands =
        Array.isArray(
          remediationObject?.commands
        )
          ? remediationObject.commands
          : [];

      if (!commands.length) {
        throw new Error(
          "No remediation command is available."
        );
      }

      const command = commands[0];

      const parameters = {};

      const placeholderMatches =
        command.match(/<([^>]+)>/g) || [];

      for (const placeholder of placeholderMatches) {
        const parameterName =
          placeholder.slice(1, -1);

        const value =
          remediationParameters[
            `${ruleId}:${parameterName}`
          ];

        if (!value?.trim()) {
          throw new Error(
            `Enter a value for ${parameterName}.`
          );
        }

        parameters[parameterName] =
          value.trim();
      }

      const payload = {
        configuration_id:
          Number(selectedConfigurationId),

        device_id:
          analysisData?.device_id ?? null,

        rule_id: ruleId,

        control:
          remediationObject?.control ||
          remediationObject?.canonical_control ||
          null,

        vendor,

        command,

        explanation:
          remediationObject?.explanation ||
          item?.description ||
          item?.title ||
          null,

        remediation: remediationObject,

        parameters:
          Object.keys(parameters).length > 0
            ? parameters
            : null,
      };

      await createRemediationRequest(payload);

      setCreatedRemediationRules(
        (current) =>
          current.includes(ruleId)
            ? current
            : [...current, ruleId]
      );

      setRemediationMessage(
        `Remediation request created for ${ruleId}. Open the Remediation page to review and approve it.`
      );

      setRemediationParameters(
        (current) => {
          const next = { ...current };

          Object.keys(parameters).forEach(
            (parameterName) => {
              delete next[
                `${ruleId}:${parameterName}`
              ];
            }
          );

          return next;
        }
      );
    } catch (err) {
      console.error(err);

      setRemediationError(
        err.response?.data?.detail ||
          err.message ||
          "Unable to create remediation request."
      );
    } finally {
      setRemediationCreating(null);
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

  const remediationItems = useMemo(() => {
    const raw = remediation;

    if (Array.isArray(raw)) {
      return raw;
    }

    if (Array.isArray(raw?.remediations)) {
      return raw.remediations;
    }

    return raw ? [raw] : [];
  }, [remediation]);

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
              setAnalysisData(null);
              setRemediation(null);
              setRemediationParameters({});
              setRemediationMessage(null);
              setRemediationError(null);
              setCreatedRemediationRules([]);
              setShowRemediation(false);


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
                #{configuration.id} â€”{" "}
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

            <div className="stat-card compliance-fail-card">
              <span className="stat-label">
                FAIL
              </span>

              <strong className="text-fail">
                {summary.fail_count ?? 0}
              </strong>

              <span>
                Controls requiring attention
              </span>

              {remediationItems.length > 0 && (
                <button
                  type="button"
                  className="secondary-button compliance-remediation-toggle"
                  onClick={() => {
                    if (showRemediation) {
                      setShowRemediation(false);
                      return;
                    }

                    setShowRemediation(true);

                    window.setTimeout(() => {
                      document
                        .getElementById("compliance-remediation-section")
                        ?.scrollIntoView({
                          behavior: "smooth",
                          block: "start",
                        });
                    }, 50);
                  }}
                >
                  {showRemediation
                    ? "Hide Remediation ↑"
                    : "View Remediation ↓"}
                </button>
              )}
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
                            {result.rule_id || "â€”"}
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
                            "â€”"}
                        </td>

                        <td>
                          {String(
                            result.expected_value ?? "â€”"
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
                            : "â€”"}
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

      {summary && remediationItems.length > 0 && showRemediation && (
        <div
          className="result-card-large"
          id="compliance-remediation-section"
        >
          <div
            className="module-card-header"
            style={{
              display: "flex",
              alignItems: "flex-start",
              justifyContent: "space-between",
              gap: "16px",
            }}
          >
            <div>
              <h3>
                Remediation Recommendations
              </h3>

              <p className="muted">
                Review the recommended vendor-specific
                corrections and create remediation requests
                for administrator approval.
              </p>
            </div>

            <button
              type="button"
              className="secondary-button"
              onClick={() => setShowRemediation(false)}
            >
              Hide Remediation ↑
            </button>
          </div>

          {remediationMessage && (
            <div className="module-success">
              {remediationMessage}
            </div>
          )}

          {remediationError && (
            <div className="module-error">
              {remediationError}
            </div>
          )}

          <div className="finding-list">
            {remediationItems.map(
              (item, index) => {
                const remediationObject =
                  item?.remediation ||
                  item;

                const commands =
                  Array.isArray(
                    remediationObject?.commands
                  )
                    ? remediationObject.commands
                    : [];

                const ruleId =
                  item?.rule_id ||
                  remediationObject?.rule_id ||
                  "";

                const alreadyCreated =
                  createdRemediationRules.includes(
                    ruleId
                  );

                const placeholders = [
                  ...new Set(
                    commands.flatMap((command) =>
                      (
                        command.match(
                          /<([^>]+)>/g
                        ) || []
                      ).map((value) =>
                        value.slice(1, -1)
                      )
                    )
                  ),
                ];

                return (
                  <div
                    className="finding-item"
                    key={
                      ruleId ||
                      `compliance-remediation-${index}`
                    }
                  >
                    <div>
                      <strong>
                        {ruleId || "Remediation"}
                      </strong>

                      {remediationObject?.vendor && (
                        <p>
                          Vendor:{" "}
                          {
                            remediationObject.vendor
                          }
                        </p>
                      )}

                      {item?.title && (
                        <p>
                          {item.title}
                        </p>
                      )}

                      {item?.description && (
                        <p>
                          {item.description}
                        </p>
                      )}

                      {commands.length > 0 ? (
                        <>
                          <pre>
                            {commands.join("\n")}
                          </pre>

                          {placeholders.length > 0 && (
                            <div className="remediation-parameters">
                              <strong>
                                Required parameters
                              </strong>

                              {placeholders.map(
                                (parameterName) => (
                                  <label
                                    key={parameterName}
                                  >
                                    {parameterName}

                                    <input
                                      type="text"
                                      value={
                                        remediationParameters[
                                          `${ruleId}:${parameterName}`
                                        ] || ""
                                      }
                                      onChange={(event) =>
                                        setRemediationParameters(
                                          (current) => ({
                                            ...current,
                                            [`${ruleId}:${parameterName}`]:
                                              event.target.value,
                                          })
                                        )
                                      }
                                      placeholder={`Enter ${parameterName}`}
                                    />
                                  </label>
                                )
                              )}
                            </div>
                          )}

                          {alreadyCreated ? (
                            <div className="finding-meta">
                              <span>
                                REQUEST CREATED
                              </span>
                            </div>
                          ) : (
                            <button
                              type="button"
                              className="primary-button"
                              disabled={
                                remediationCreating ===
                                ruleId
                              }
                              onClick={() =>
                                createRemediation(
                                  item,
                                  remediationObject
                                )
                              }
                            >
                              {remediationCreating ===
                              ruleId
                                ? "Creating..."
                                : "Create Remediation Request"}
                            </button>
                          )}
                        </>
                      ) : (
                        <p className="muted">
                          Remediation details were
                          returned without CLI commands.
                        </p>
                      )}
                    </div>
                  </div>
                );
              }
            )}
          </div>
        </div>
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