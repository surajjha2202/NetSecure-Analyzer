import { useEffect, useMemo, useState } from "react";

import {
  getRemediationRequests,
  approveRemediationRequest,
  rejectRemediationRequest,
  executeRemediationRequest,
} from "../api/remediation";

function statusClass(status) {
  if (!status) return "status-badge";

  const normalized = String(status).toUpperCase();

  if (
    normalized === "VERIFIED" ||
    normalized === "APPROVED" ||
    normalized === "PASS" ||
    normalized === "DRY_RUN"
  ) {
    return "status-badge status-success";
  }

  if (
    normalized === "PENDING" ||
    normalized === "EXECUTED"
  ) {
    return "status-badge status-warning";
  }

  if (
    normalized === "REJECTED" ||
    normalized === "EXECUTED_UNVERIFIED" ||
    normalized === "FAILED"
  ) {
    return "status-badge status-danger";
  }

  return "status-badge";
}


function getRequestsFromResponse(data) {
  if (Array.isArray(data)) {
    return data;
  }

  if (Array.isArray(data?.requests)) {
    return data.requests;
  }

  if (Array.isArray(data?.items)) {
    return data.items;
  }

  return [];
}

function extractParameters(request) {
  if (!request?.parameters) {
    return [];
  }

  if (Array.isArray(request.parameters)) {
    return request.parameters;
  }

  return Object.entries(request.parameters).map(
    ([name, value]) => ({
      name,
      value,
    })
  );
}

function getParameterNames(request) {
  const parameters = extractParameters(request);

  return parameters
    .map((parameter) => {
      if (typeof parameter === "string") {
        return parameter;
      }

      return (
        parameter.name ||
        parameter.key ||
        parameter.parameter ||
        null
      );
    })
    .filter(Boolean);
}

function getInitialParameterValues(request) {
  const parameters = extractParameters(request);

  const values = {};

  parameters.forEach((parameter) => {
    if (typeof parameter === "string") {
      values[parameter] = "";
      return;
    }

    const name =
      parameter.name ||
      parameter.key ||
      parameter.parameter;

    if (name) {
      values[name] =
        parameter.value ??
        parameter.default ??
        "";
    }
  });

  return values;
}

function VerificationResult({ verification }) {
  if (!verification) {
    return null;
  }

  const verified = verification.verified === true;

  return (
    <div
      className={
        verified
          ? "remediation-verification verification-success"
          : "remediation-verification verification-warning"
      }
    >
      <div className="verification-header">
        <strong>
          {verified
            ? "Remediation verified"
            : "Remediation not verified"}
        </strong>

        <span className={statusClass(
          verified ? "VERIFIED" : "EXECUTED_UNVERIFIED"
        )}>
          {verified ? "VERIFIED" : "UNVERIFIED"}
        </span>
      </div>

      {verification.reason && (
        <p>{verification.reason}</p>
      )}

      {verification.before_configuration_id && (
        <div className="verification-meta">
          Before configuration:{" "}
          <strong>
            #{verification.before_configuration_id}
          </strong>
        </div>
      )}

      {verification.after_configuration_id && (
        <div className="verification-meta">
          After configuration:{" "}
          <strong>
            #{verification.after_configuration_id}
          </strong>
        </div>
      )}

      {verification.scan_error && (
        <div className="error-message">
          Post-execution scan error:{" "}
          {verification.scan_error}
        </div>
      )}
    </div>
  );
}

function ExecuteForm({
  request,
  onExecute,
  disabled,
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [port, setPort] = useState("22");
  const [secret, setSecret] = useState("");
  const [dryRun, setDryRun] = useState(true);

  const [showPassword, setShowPassword] =
    useState(false);

  async function handleSubmit(event) {
    event.preventDefault();

    await onExecute(request.id, {
      username,
      password,
      port: Number(port),
      secret: secret || null,
      dry_run: dryRun,
    });
  }

  return (
    <form
      className="remediation-execute-form"
      onSubmit={handleSubmit}
    >
      <h4>Execute approved remediation</h4>

      <div className="form-grid">
        <label>
          SSH Username
          <input
            type="text"
            value={username}
            onChange={(event) =>
              setUsername(event.target.value)
            }
            placeholder="admin"
            required
          />
        </label>

        <label>
          SSH Password
          <div className="password-field">
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(event) =>
                setPassword(event.target.value)
              }
              placeholder="SSH password"
              required
            />

            <button
              type="button"
              className="secondary-button small-button"
              onClick={() =>
                setShowPassword((value) => !value)
              }
            >
              {showPassword ? "Hide" : "Show"}
            </button>
          </div>
        </label>

        <label>
          SSH Port
          <input
            type="number"
            min="1"
            max="65535"
            value={port}
            onChange={(event) =>
              setPort(event.target.value)
            }
            required
          />
        </label>

        <label>
          Enable Secret
          <input
            type="password"
            value={secret}
            onChange={(event) =>
              setSecret(event.target.value)
            }
            placeholder="Optional"
          />
        </label>
      </div>

      <label className="checkbox-row">
        <input
          type="checkbox"
          checked={dryRun}
          onChange={(event) =>
            setDryRun(event.target.checked)
          }
        />

        <span>
          Dry run — validate the remediation without
          changing the device
        </span>
      </label>

      <button
        type="submit"
        className="primary-button"
        disabled={disabled}
      >
        {disabled
          ? "Executing..."
          : dryRun
            ? "Run Dry Test"
            : "Execute Remediation"}
      </button>
    </form>
  );
}

function RemediationCard({

  request,
  onApprove,
  onReject,
  onExecute,
  actionLoading,
}) {
  const parameters = getParameterNames(request);

  const unresolvedPlaceholders =
    request.command?.match(/<[^>]+>/g) || [];

  const executionStatus =
    request.execution_status;

  const verification =
    request.verification_result ||
    request.verification;

  const isPending =
    String(request.state).toUpperCase() ===
    "PENDING";

  const isApproved =
    String(request.state).toUpperCase() ===
    "APPROVED";

  const [expanded, setExpanded] =
    useState(isPending || isApproved);

  async function handleApprove() {
    await onApprove(request.id);
  }

  async function handleReject() {
    await onReject(request.id);
  }

  return (
    <article className="dashboard-card remediation-card">
      <div className="remediation-card-header">
        <div>
          <div className="remediation-rule">
            {request.rule_id || "Unknown rule"}
          </div>

          <h3>
            {request.title ||
              request.description ||
              "Remediation request"}
          </h3>
        </div>

        <div className="remediation-statuses">
          <span className={statusClass(request.state)}>
            {request.state || "UNKNOWN"}
          </span>

          {executionStatus && (
            <span
              className={statusClass(
                executionStatus
              )}
            >
              {executionStatus}
            </span>
          )}
        </div>
      </div>

      <div className="remediation-meta-grid">
        <div>
          <span>Vendor</span>
          <strong>{request.vendor || "Unknown"}</strong>
        </div>

        <div>
          <span>Configuration</span>
          <strong>
            {request.configuration_id
              ? `#${request.configuration_id}`
              : "—"}
          </strong>
        </div>

        <div>
          <span>Requested by</span>
          <strong>
            {request.requested_by || "—"}
          </strong>
        </div>

        <div>
          <span>Created</span>

          <strong>
            {request.requested_at
              ? new Date(request.requested_at).toLocaleString("en-IN", {
                timeZone: "Asia/Kolkata",
                day: "2-digit",
                month: "2-digit",
                year: "numeric",
                hour: "2-digit",
                minute: "2-digit",
                hour12: true,
              })
              : "—"}
          </strong>
        </div>
      </div>

      <button
        type="button"
        className="secondary-button"
        onClick={() =>
          setExpanded((value) => !value)
        }
      >
        {expanded ? "Hide details" : "Show details"}
      </button>

      {expanded && (
        <div className="remediation-details">
          {request.description && (
            <div className="remediation-description">
              <strong>Description</strong>
              <p>{request.description}</p>
            </div>
          )}

          <div className="command-section">
            <strong>Command</strong>

            <pre>
              <code>
                {request.command || "No command available"}
              </code>
            </pre>
          </div>
          {unresolvedPlaceholders.length > 0 && (
            <div className="remediation-parameter-warning">
              <strong>Required parameter missing</strong>

              <p>
                This remediation contains unresolved parameters:{" "}
                {unresolvedPlaceholders.join(", ")}
              </p>

              <span>
                Provide the required value before execution.
              </span>
            </div>
          )}

          {parameters.length > 0 && (
            <div className="parameter-section">
              <strong>Remediation parameters</strong>

              <p className="muted-text">
              This remediation contains parameters that must be
              resolved when the request is created.
            </p>

              {parameters.map((name) => {
                const parameter = extractParameters(request).find(
                  (item) =>
                    typeof item !== "string" &&
                    (item.name === name ||
                      item.key === name ||
                      item.parameter === name)
                );

                const value =
                  typeof parameter === "object"
                    ? parameter.value ??
                      parameter.default ??
                      ""
                    : "";

                return (
                  <div
                    className="remediation-parameter-row"
                    key={name}
                  >
                    <span>{name}</span>

                    <code>
                      {value || "Value not supplied"}
                    </code>
                  </div>
                );
              })}
            </div>
          )}
          {isPending && (
            <div className="approval-actions">
              <button
                type="button"
                className="primary-button"
                disabled={actionLoading}
                onClick={handleApprove}
              >
                {actionLoading
                  ? "Processing..."
                  : "Approve"}
              </button>

              <button
                type="button"
                className="danger-button"
                disabled={actionLoading}
                onClick={handleReject}
              >
                Reject
              </button>
            </div>
          )}

          {isApproved && (
            <div>
              {unresolvedPlaceholders.length > 0 ? (
                <div className="remediation-execution-blocked">
                  <strong>Execution blocked</strong>

                  <p>
                    This remediation cannot be executed because
                    required parameters are still unresolved.
                  </p>

                  <span>
                    Resolve {unresolvedPlaceholders.join(", ")} before
                    execution.
                  </span>
                </div>
              ) : (
                <ExecuteForm
                  request={request}
                  onExecute={onExecute}
                  disabled={actionLoading}
                />
              )}
            </div>
          )}

          <VerificationResult
            verification={verification}
          />

          {request.output && (
            <div className="command-section">
              <strong>Execution output</strong>

              <pre className="execution-output">
                {request.output}
              </pre>
            </div>
          )}
        </div>
      )}
    </article>
  );
}

export default function Remediation({
  latestAnalysis,
}) {
  const [requests, setRequests] =
    useState([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState(null);

  const [message, setMessage] =
    useState(null);

  const [actionLoading, setActionLoading] =
    useState(null);

  useEffect(() => {
    loadRequests();
  }, []);

  async function loadRequests() {
    try {
      setLoading(true);
      setError(null);

      const data =
        await getRemediationRequests();

      setRequests(
        getRequestsFromResponse(data)
      );
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          "Unable to load remediation requests."
      );
    } finally {
      setLoading(false);
    }
  }

  async function runAction(
    requestId,
    action,
    callback
  ) {
    try {
      setActionLoading(requestId);
      setError(null);
      setMessage(null);

      await callback(requestId);

      setMessage(
        `Remediation request #${requestId} ${action}.`
      );

      await loadRequests();
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          `Unable to ${action} remediation request.`
      );
    } finally {
      setActionLoading(null);
    }
  }

  async function handleApprove(requestId) {
    await runAction(
      requestId,
      "approved",
      approveRemediationRequest
    );
  }

  async function handleReject(requestId) {
    await runAction(
      requestId,
      "rejected",
      rejectRemediationRequest
    );
  }

  async function handleExecute(
    requestId,
    payload
  ) {
    try {
      setActionLoading(requestId);
      setError(null);
      setMessage(null);

      const result =
        await executeRemediationRequest(
          requestId,
          payload
        );

      if (
        result.execution_status ===
        "VERIFIED"
      ) {
        setMessage(
          `Remediation #${requestId} executed and verified successfully.`
        );
      } else if (
        result.execution_status ===
        "DRY_RUN"
      ) {
        setMessage(
          `Dry run for remediation #${requestId} completed.`
        );
      } else {
        setMessage(
          `Remediation #${requestId} executed, but verification requires review.`
        );
      }

      await loadRequests();
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          "Unable to execute remediation request."
      );
    } finally {
      setActionLoading(null);
    }
  }

  const stats = useMemo(() => {
    const pending = requests.filter(
      (request) =>
        String(request.state).toUpperCase() ===
        "PENDING"
    ).length;

    const approved = requests.filter(
      (request) =>
        String(request.state).toUpperCase() ===
        "APPROVED"
    ).length;

    const verified = requests.filter(
      (request) =>
        String(
          request.execution_status
        ).toUpperCase() === "VERIFIED"
    ).length;

    const unverified = requests.filter(
      (request) =>
        String(
          request.execution_status
        ).toUpperCase() ===
        "EXECUTED_UNVERIFIED"
    ).length;

    return {
      total: requests.length,
      pending,
      approved,
      verified,
      unverified,
    };
  }, [requests]);

  return (
    <main className="module-page">
      <div className="page-heading">
        <div>
          <h1>Remediation</h1>

          <p>
            Review findings, approve security changes,
            execute remediation commands, and verify
            the resulting device configuration.
          </p>
        </div>

        <button
          type="button"
          className="secondary-button"
          onClick={loadRequests}
          disabled={loading}
        >
          Refresh
        </button>
      </div>

      {message && (
        <div className="success-message">
          {message}
        </div>
      )}

      {error && (
        <div className="error-message">
          {error}
        </div>
      )}

      <section className="remediation-overview">
        <div className="remediation-overview-header">
          <div>
            <span className="remediation-section-label">
              REMEDIATION OPERATIONS
            </span>

            <h2>Remediation Overview</h2>

            <p>
              Track security changes from approval through execution
              and post-change verification.
            </p>
          </div>
        </div>

        <div className="remediation-stats-grid">
          <div className="remediation-stat-card">
            <div className="remediation-stat-top">
              <span className="remediation-stat-label">
                Total Requests
              </span>
              <span className="remediation-stat-icon">↗</span>
            </div>

            <strong className="remediation-stat-value">
              {stats.total}
            </strong>

            <span className="remediation-stat-detail">
              All remediation activity
            </span>
          </div>

          <div className="remediation-stat-card">
            <div className="remediation-stat-top">
              <span className="remediation-stat-label">
                Pending Approval
              </span>
              <span className="remediation-stat-icon">◷</span>
            </div>

            <strong className="remediation-stat-value">
              {stats.pending}
            </strong>

            <span className="remediation-stat-detail">
              Awaiting authorization
            </span>
          </div>

          <div className="remediation-stat-card">
            <div className="remediation-stat-top">
              <span className="remediation-stat-label">
                Approved
              </span>
              <span className="remediation-stat-icon">✓</span>
            </div>

            <strong className="remediation-stat-value">
              {stats.approved}
            </strong>

            <span className="remediation-stat-detail">
              Authorized changes
            </span>
          </div>

          <div className="remediation-stat-card">
            <div className="remediation-stat-top">
              <span className="remediation-stat-label">
                Verified
              </span>
              <span className="remediation-stat-icon">✓</span>
            </div>

            <strong className="remediation-stat-value">
              {stats.verified}
            </strong>

            <span className="remediation-stat-detail">
              Successfully validated
            </span>
          </div>

          <div className="remediation-stat-card">
            <div className="remediation-stat-top">
              <span className="remediation-stat-label">
                Unverified
              </span>
              <span className="remediation-stat-icon">!</span>
            </div>

            <strong className="remediation-stat-value">
              {stats.unverified}
            </strong>

            <span className="remediation-stat-detail">
              Require investigation
            </span>
          </div>
        </div>
      </section>

      {latestAnalysis && (
        <div className="dashboard-card remediation-source-card">
          <h2>Latest analysis</h2>

          <p>
            Configuration #
            {latestAnalysis.configuration_id ??
              "—"}{" "}
            was analyzed. Failed controls can be
            converted into remediation requests from
            the analysis results.
          </p>

          <div className="remediation-analysis-summary">
            {latestAnalysis.compliance && (
              <span>
                Compliance analysis available
              </span>
            )}

            {latestAnalysis.risk && (
              <span>
                Risk assessment available
              </span>
            )}
          </div>
        </div>
      )}

      {loading ? (
        <div className="dashboard-card">
          Loading remediation requests...
        </div>
      ) : requests.length === 0 ? (
        <div className="dashboard-card empty-state">
          <h2>No remediation requests</h2>

          <p>
            Remediation requests created from failed
            compliance findings will appear here.
          </p>
        </div>
      ) : (
        <div className="remediation-list">
          {requests.map((request) => (
            <RemediationCard
              key={request.id}
              request={request}
              onApprove={handleApprove}
              onReject={handleReject}
              onExecute={handleExecute}
              actionLoading={
                actionLoading === request.id
              }
            />
          ))}
        </div>
      )}
    </main>
  );
}
