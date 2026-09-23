import { useEffect, useState } from "react";
import {
  getConfigurations,
  uploadConfiguration,
  analyzeConfiguration,
  analyzeBulkConfigurations,
  deleteConfiguration,
  deleteConfigurationHistory,
} from "../api/configurations";

function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) {
    return "Unknown";
  }

  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
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

function statusClass(status) {
  return String(status || "UNKNOWN")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-");
}

function normalizeConfigurations(response) {
  if (Array.isArray(response)) {
    return response;
  }

  return (
    response?.configurations ||
    response?.items ||
    []
  );
}

export default function Configurations() {
  const [configurations, setConfigurations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [analyzingId, setAnalyzingId] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [bulkUploading, setBulkUploading] = useState(false);
  const [bulkResult, setBulkResult] = useState(null);
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(null);
  const [analysisToast, setAnalysisToast] = useState(null);
  const [deletingId, setDeletingId] = useState(null);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [showDeleteHistoryModal, setShowDeleteHistoryModal] =
  useState(false);

  async function loadConfigurations() {
    try {
      setLoading(true);
      setError(null);

      const response = await getConfigurations();

      setConfigurations(
        normalizeConfigurations(response)
      );
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          "Unable to load configurations."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadConfigurations();
  }, []);
  useEffect(() => {
    if (!analysisToast) {
      return undefined;
    }

    const timer = window.setTimeout(() => {
      setAnalysisToast(null);
    }, 6000);

    return () => {
      window.clearTimeout(timer);
    };
  }, [analysisToast]);

  async function handleUpload(event) {
    event.preventDefault();

    if (!selectedFile) {
      setError("Please select a configuration file.");
      return;
    }

    try {
      setUploading(true);
      setError(null);
      setMessage(null);

      await uploadConfiguration(selectedFile);

      setSelectedFile(null);
      event.target.reset();

      setMessage(
        "Configuration uploaded successfully."
      );

      await loadConfigurations();
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          "Configuration upload failed."
      );
    } finally {
      setUploading(false);
    }
  }

  async function handleAnalyze(configurationId) {
    const configuration = configurations.find(
      (item) => item.id === configurationId
    );

    const filename =
      configuration?.filename ||
      `Configuration #${configurationId}`;

    try {
      setAnalyzingId(configurationId);
      setError(null);
      setMessage(null);
      setAnalysisToast(null);

      await analyzeConfiguration(configurationId);

      setAnalysisToast({
        type: "success",
        message: `${filename} analyzed successfully.`,
      });

      await loadConfigurations();
    } catch (err) {
      console.error(err);

      setError(null);
      setMessage(null);

      setAnalysisToast({
        type: "error",
        message: `Analysis failed for ${filename}.`,
      });
    } finally {
      setAnalyzingId(null);
    }
  }

    async function handleBulkUpload() {
    if (!selectedFiles.length) {
      setError("Please select configuration files.");
      return;
    }

    if (selectedFiles.length > 500) {
      setError("A maximum of 500 configuration files can be processed.");
      return;
    }

    try {
      setBulkUploading(true);
      setError(null);
      setMessage(null);
      setBulkResult(null);

      const configurationIds = [];
      const uploadFailures = [];

      for (const file of selectedFiles) {
        try {
          const uploaded = await uploadConfiguration(file);

          if (uploaded?.id) {
            configurationIds.push(uploaded.id);
          } else {
            uploadFailures.push({
              filename: file.name,
              error: "Upload succeeded but no configuration ID was returned.",
            });
          }
        } catch (err) {
          if (err.response?.status === 401) {
            throw err;
          }

          uploadFailures.push({
            filename: file.name,
            error:
              err.response?.data?.detail ||
              "Configuration upload failed.",
          });
        }
      }

      if (!configurationIds.length) {
        setError("None of the selected configuration files could be uploaded.");
        return;
      }

      const result = await analyzeBulkConfigurations(configurationIds);

      setBulkResult({
        ...result,
        uploadFailures,
      });

      setSelectedFiles([]);

      setMessage(
        `${configurationIds.length} configuration${
          configurationIds.length === 1 ? "" : "s"
        } uploaded and analyzed.`
      );

      await loadConfigurations();
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          "Bulk configuration processing failed."
      );
    } finally {
      setBulkUploading(false);
    }
  }

  async function handleDeleteConfiguration(configurationId) {
    try {
      setDeletingId(configurationId);
      setError(null);
      setMessage(null);

      const result = await deleteConfiguration(configurationId);

      setDeleteTarget(null);

      setMessage(
        result?.message ||
          `Configuration #${configurationId} deleted successfully.`
      );

      await loadConfigurations();
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          `Unable to delete configuration #${configurationId}.`
      );
    } finally {
      setDeletingId(null);
    }
  }

  async function handleDeleteHistory() {
    try {
      setDeletingId("history");
      setError(null);
      setMessage(null);

      const result = await deleteConfigurationHistory();

      setShowDeleteHistoryModal(false);

      setMessage(
        result?.message ||
          "Configuration history deleted successfully."
      );

      await loadConfigurations();
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          "Unable to delete configuration history."
      );
    } finally {
      setDeletingId(null);
    }
  }

  const analyzedCount = configurations.filter(
    (configuration) =>
      String(configuration.status || "")
        .toUpperCase() === "ANALYZED"
  ).length;

  const liveScanCount = configurations.filter(
    (configuration) =>
      String(configuration.status || "")
        .toUpperCase() === "LIVE_SCAN"
  ).length;

    return (
    <div className="module-page configurations-page">
      {analysisToast && (
        <div
          className={`analysis-toast ${analysisToast.type}`}
          role="status"
          aria-live="polite"
        >
          <div className="analysis-toast-icon">
            {analysisToast.type === "success" ? "✓" : "!"}
          </div>

          <div className="analysis-toast-content">
            <strong>
              {analysisToast.type === "success"
                ? "Analysis completed"
                : "Analysis failed"}
            </strong>

            <span>{analysisToast.message}</span>
          </div>

          <button
            type="button"
            className="analysis-toast-close"
            onClick={() => setAnalysisToast(null)}
            aria-label="Close notification"
          >
            &times;
          </button>
        </div>
      )}
      <div className="config-page-header">
        <div>
          <span className="eyebrow">SECURITY OPERATIONS</span>
          <h1>Configurations</h1>
          <p>
            Store, analyze and manage network-device configuration
            snapshots from one workspace.
          </p>
        </div>

        <button
          className="secondary-button"
          onClick={loadConfigurations}
          disabled={loading}
        >
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="error config-alert">
          {error}
        </div>
      )}

      {message && (
        <div className="success-message config-alert">
          {message}
        </div>
      )}

      <section className="config-overview-grid">
        <div className="config-metric-card">
          <div>
            <span className="config-metric-label">
              TOTAL CONFIGURATIONS
            </span>
            <strong>
              {loading ? "—" : configurations.length}
            </strong>
            <p>Stored configuration snapshots</p>
          </div>
        </div>

        <div className="config-metric-card">
          <div>
            <span className="config-metric-label">
              ANALYZED
            </span>
            <strong>
              {loading ? "—" : analyzedCount}
            </strong>
            <p>Configurations processed by the engine</p>
          </div>
        </div>

        <div className="config-metric-card">
          <div>
            <span className="config-metric-label">
              LIVE CAPTURES
            </span>
            <strong>
              {loading ? "—" : liveScanCount}
            </strong>
            <p>Configurations captured from devices</p>
          </div>
        </div>
      </section>

      <section className="config-ingestion-workspace">
        <div className="config-ingestion-header">
          <div>
            <span className="config-section-kicker">
              CONFIGURATION INGESTION
            </span>
            <h2>Collect network configurations</h2>
            <p>
              Upload a single configuration for targeted analysis or
              process multiple configurations together through the bulk
              analysis engine.
            </p>
          </div>

          <div className="config-ingestion-capabilities">
            <span>CFG</span>
            <span>CONF</span>
            <span>TXT</span>
            <span>5 MB / file</span>
          </div>
        </div>

        <div className="config-ingestion-modes">
          <article className="config-ingestion-mode">
            <div className="config-ingestion-mode-header">
              <div>
                <span>SINGLE CONFIGURATION</span>
                <h3>Upload one file</h3>
              </div>
            </div>

            <p className="config-ingestion-mode-description">
              Store a configuration snapshot and analyze it whenever
              you are ready.
            </p>

            <form
              className="config-ingestion-form"
              onSubmit={handleUpload}
            >
              <label
                className={`config-ingestion-dropzone ${
                  selectedFile ? "has-file" : ""
                }`}
                htmlFor="configuration-file"
              >
                <input
                  id="configuration-file"
                  type="file"
                  accept=".cfg,.conf,.txt"
                  onChange={(event) =>
                    setSelectedFile(
                      event.target.files?.[0] || null
                    )
                  }
                />

                <div className="config-ingestion-upload-icon">
                  {selectedFile ? "✓" : "↑"}
                </div>

                <div className="config-ingestion-dropzone-copy">
                  <strong>
                    {selectedFile
                      ? selectedFile.name
                      : "Choose a configuration file"}
                  </strong>
                  <span>
                    {selectedFile
                      ? `${formatBytes(selectedFile.size)} · Ready to upload`
                      : "Browse from your computer"}
                  </span>
                </div>

                <span className="config-ingestion-browse">
                  Browse
                </span>
              </label>

              <div className="config-ingestion-actions">
                <span>
                  {selectedFile
                    ? "File ready for ingestion."
                    : "Select one file to continue."}
                </span>

                <button
                  type="submit"
                  className="primary-button"
                  disabled={uploading || !selectedFile}
                >
                  {uploading
                    ? "Uploading..."
                    : "Upload Configuration"}
                </button>
              </div>
            </form>
          </article>

          <article className="config-ingestion-mode bulk">
            <div className="config-ingestion-mode-header">
              <div>
                <span>BULK CONFIGURATION</span>
                <h3>Upload and analyze a batch</h3>
              </div>
            </div>

            <p className="config-ingestion-mode-description">
              Select multiple configuration snapshots, store them in
              your workspace and analyze them as one batch.
            </p>

            <div className="config-ingestion-form">
              <label
                className={`config-ingestion-dropzone ${
                  selectedFiles.length ? "has-file" : ""
                }`}
                htmlFor="bulk-configuration-files"
              >
                <input
                  id="bulk-configuration-files"
                  type="file"
                  multiple
                  accept=".cfg,.conf,.txt"
                  onChange={(event) => {
                    const newFiles = Array.from(
                      event.target.files || []
                    );

                    setSelectedFiles((currentFiles) => [
                      ...currentFiles,
                      ...newFiles,
                    ]);

                    event.target.value = "";
                  }}
                />

                <div className="config-ingestion-upload-icon">
                  {selectedFiles.length ? "✓" : "↑"}
                </div>

                <div className="config-ingestion-dropzone-copy">
                  <strong>
                    {selectedFiles.length
                      ? `${selectedFiles.length} file${
                          selectedFiles.length === 1 ? "" : "s"
                        } selected`
                      : "Choose multiple configuration files"}
                  </strong>
                  <span>
                    {selectedFiles.length
                      ? "Ready for bulk ingestion and analysis"
                      : "Select several files at once"}
                  </span>
                </div>

                <span className="config-ingestion-browse">
                  Browse
                </span>
              </label>              {selectedFiles.length > 0 && (
                <div className="config-ingestion-file-list">
                  {selectedFiles.map((file, index) => (
                    <div
                      className="config-ingestion-file-item"
                      key={`${file.name}-${file.size}-${file.lastModified}-${index}`}
                    >
                      <div className="config-ingestion-file-name">
                        <span>{file.name}</span>
                        <span>{formatBytes(file.size)}</span>
                      </div>

                      <button
                        type="button"
                        className="config-ingestion-file-remove"
                        onClick={() =>
                          setSelectedFiles((currentFiles) =>
                            currentFiles.filter(
                              (_, currentIndex) =>
                                currentIndex !== index
                            )
                          )
                        }
                        aria-label={`Remove ${file.name}`}
                        title={`Remove ${file.name}`}
                      >
                        &times;
                      </button>
                    </div>
                  ))}
                  </div>
              )}

              <div className="config-ingestion-actions">
                <span>
                  {selectedFiles.length
                    ? `${selectedFiles.length} file${
                        selectedFiles.length === 1 ? "" : "s"
                      } ready for processing.`
                    : "Select multiple files to continue."}
                </span>

                <button
                  type="button"
                  className="primary-button"
                  disabled={
                    bulkUploading || !selectedFiles.length
                  }
                  onClick={handleBulkUpload}
                >
                  {bulkUploading
                    ? "Processing..."
                    : "Upload & Analyze Batch"}
                </button>
              </div>

              {bulkResult && (
                <div className="config-ingestion-result">
                  <div className="config-ingestion-result-header">
                    <div>
                      <span>RESULT</span>
                      <strong>
                        Bulk analysis completed
                      </strong>
                    </div>

                    <span className="config-ingestion-job">
                      Job #{bulkResult.job_id}
                    </span>
                  </div>

                  <div className="config-ingestion-result-stats">
                    <div>
                      <span>Successful</span>
                      <strong>
                        {bulkResult.successful || 0}
                      </strong>
                    </div>

                    <div>
                      <span>Failed</span>
                      <strong>
                        {bulkResult.failed || 0}
                      </strong>
                    </div>

                    <div>
                      <span>Compliance</span>
                      <strong>
                        {Number(
                          bulkResult.summary
                            ?.average_compliance_percentage ?? 0
                        ).toFixed(1)}
                        %
                      </strong>
                    </div>

                    <div>
                      <span>Risk</span>
                      <strong>
                        {Number(
                          bulkResult.summary
                            ?.average_risk_score ?? 0
                        ).toFixed(1)}
                      </strong>
                    </div>
                  </div>

                  {bulkResult.uploadFailures?.length > 0 && (
                    <div className="config-ingestion-failures">
                      <strong>Upload issues</strong>

                      {bulkResult.uploadFailures.map((item) => (
                        <div key={item.filename}>
                          <span>{item.filename}</span>
                          <span>{item.error}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </article>
        </div>
      </section>

      <section className="config-inventory-card">
        <div className="config-inventory-header">
          <div>
            <span className="config-section-kicker">
              CONFIGURATION INVENTORY
            </span>
            <h2>Configuration History</h2>
            <p>
              Review stored snapshots and their latest analysis
              state.
            </p>
          </div>

          {configurations.length > 0 && (
            <button
              type="button"
              className="danger-button compact-button"
              onClick={() =>
                setShowDeleteHistoryModal(true)
              }
              disabled={
                deletingId === "history" ||
                Boolean(analyzingId)
              }
            >
              Delete History
            </button>
          )}
        </div>

        {loading ? (
          <div className="config-empty-state">
            <div className="config-empty-icon">…</div>
            <strong>Loading configurations</strong>
            <p>
              Retrieving your stored configuration snapshots.
            </p>
          </div>
        ) : configurations.length === 0 ? (
          <div className="config-empty-state">
            <div className="config-empty-icon">+</div>
            <strong>No configurations yet</strong>
            <p>
              Upload your first network-device configuration to
              begin security analysis.
            </p>
          </div>
        ) : (
          <div className="config-list">
            {configurations.map((configuration) => {
              const status =
                configuration.status || "UNKNOWN";

              const analysis =
                configuration.latest_analysis;

              return (
                <article
                  className="config-list-item"
                  key={configuration.id}
                >
                  <div className="config-list-main">
                    <div className="config-file-title-row">
                      <div>
                        <h3>
                          {configuration.filename ||
                            `Configuration #${configuration.id}`}
                        </h3>

                        <span className="config-file-meta">
                          Configuration #{configuration.id}
                          <span>·</span>
                          {configuration.extension ||
                            "Unknown type"}
                        </span>
                      </div>

                      <span
                        className={`configuration-status ${statusClass(
                          status
                        )}`}
                      >
                        {status}
                      </span>
                    </div>

                    <div className="config-details-grid">
                      <div>
                        <span>SIZE</span>
                        <strong>
                          {formatBytes(configuration.size)}
                        </strong>
                      </div>

                      <div>
                        <span>CREATED</span>
                        <strong>
                          {formatDate(
                            configuration.created_at
                          )}
                        </strong>
                      </div>

                      <div>
                        <span>SOURCE</span>
                        <strong>
                          {String(status).toUpperCase() ===
                          "LIVE_SCAN"
                            ? "Live device"
                            : "Uploaded"}
                        </strong>
                      </div>
                    </div>

                    <div className="config-analysis-panel">
                      <div className="config-analysis-heading">
                        <div>
                          <span className="config-analysis-label">
                            LATEST ANALYSIS
                          </span>
                          <strong>
                            {analysis
                              ? analysis.status || "Analyzed"
                              : "Pending analysis"}
                          </strong>
                        </div>

                        {analysis &&
                          analysis.compliance_percentage !==
                            null &&
                          analysis.compliance_percentage !==
                            undefined && (
                            <div className="config-compliance">
                              <span>COMPLIANCE</span>
                              <strong>
                                {analysis.compliance_percentage}%
                              </strong>
                            </div>
                          )}
                      </div>

                      {analysis ? (
                        <div className="config-analysis-meta">
                          <div>
                            <span>FRAMEWORKS</span>
                            <strong>
                              {(
                                analysis.selected_frameworks ||
                                []
                              ).join(" · ") || "Not specified"}
                            </strong>
                          </div>

                          <div>
                            <span>ANALYZED</span>
                            <strong>
                              {formatDate(
                                analysis.created_at
                              )}
                            </strong>
                          </div>
                        </div>
                      ) : (
                        <p>
                          This configuration has not been analyzed
                          yet.
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="config-list-actions">
                    <button
                      type="button"
                      className="primary-button compact-button"
                      onClick={() =>
                        handleAnalyze(configuration.id)
                      }
                      disabled={
                        analyzingId === configuration.id ||
                        deletingId === configuration.id
                      }
                    >
                      {analyzingId === configuration.id
                        ? "Analyzing..."
                        : analysis
                        ? "Re-analyze"
                        : "Analyze"}
                    </button>

                    <button
                      type="button"
                      className="danger-button compact-button"
                      onClick={() =>
                        setDeleteTarget(configuration)
                      }
                      disabled={
                        analyzingId === configuration.id ||
                        deletingId === configuration.id
                      }
                    >
                      Delete
                    </button>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>

      {deleteTarget && (
        <div
          className="modal-backdrop"
          onClick={() => {
            if (!deletingId) {
              setDeleteTarget(null);
            }
          }}
        >
          <div
            className="confirmation-modal"
            onClick={(event) =>
              event.stopPropagation()
            }
          >
            <div className="modal-icon danger">
              !
            </div>

            <h2>Delete Configuration?</h2>

            <p>
              You are about to permanently delete:
            </p>

            <strong>
              {deleteTarget.filename ||
                `Configuration #${deleteTarget.id}`}
            </strong>

            <div className="modal-warning">
              <strong>This will remove:</strong>

              <ul>
                <li>Configuration snapshot</li>
                <li>Stored analysis runs</li>
                <li>
                  Training candidates generated from it
                </li>
              </ul>

              <p>
                Remediation history and audit records will be
                preserved.
              </p>

              <p>
                Global AI learned mappings will not be affected.
              </p>
            </div>

            <div className="modal-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() =>
                  setDeleteTarget(null)
                }
                disabled={Boolean(deletingId)}
              >
                Cancel
              </button>

              <button
                type="button"
                className="danger-button"
                onClick={() =>
                  handleDeleteConfiguration(deleteTarget.id)
                }
                disabled={Boolean(deletingId)}
              >
                {deletingId
                  ? "Deleting..."
                  : "Delete Permanently"}
              </button>
            </div>
          </div>
        </div>
      )}

      {showDeleteHistoryModal && (
        <div
          className="modal-backdrop"
          onClick={() => {
            if (deletingId !== "history") {
              setShowDeleteHistoryModal(false);
            }
          }}
        >
          <div
            className="confirmation-modal"
            onClick={(event) =>
              event.stopPropagation()
            }
          >
            <div className="modal-icon danger">
              !
            </div>

            <h2>Delete Configuration History?</h2>

            <p>
              You are about to permanently delete
              <strong>
                {" "}
                all of your configuration history.
              </strong>
            </p>

            <div className="modal-warning">
              <strong>This will remove:</strong>

              <ul>
                <li>
                  All stored configuration snapshots
                </li>
                <li>All stored analysis runs</li>
                <li>
                  Training candidates generated from those
                  configurations
                </li>
              </ul>

              <p>
                Remediation history and audit records will be
                preserved.
              </p>

              <p>
                Global AI learned mappings will not be affected.
              </p>
            </div>

            <div className="modal-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() =>
                  setShowDeleteHistoryModal(false)
                }
                disabled={deletingId === "history"}
              >
                Cancel
              </button>

              <button
                type="button"
                className="danger-button"
                onClick={handleDeleteHistory}
                disabled={deletingId === "history"}
              >
                {deletingId === "history"
                  ? "Deleting..."
                  : "Delete All History"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
