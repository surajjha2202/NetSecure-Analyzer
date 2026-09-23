import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { API_URL } from "../api/client";

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

function formatAction(action) {
  if (!action) return "—";
  return String(action)
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function statusClass(status) {
  return String(status || "").toUpperCase() === "SUCCESS"
    ? "status-success"
    : "status-danger";
}

export default function AuditTrail({ token, onLogout }) {
  const [logs, setLogs] = useState([]);
  const [filters, setFilters] = useState({
    action: "",
    status: "",
    username: "",
    resource_type: "",
  });
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [totalCount, setTotalCount] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expandedId, setExpandedId] = useState(null);

  async function loadLogs(nextPage = page) {
    if (!token) return;

    try {
      setLoading(true);
      setError(null);

      const params = {
        page: nextPage,
        page_size: pageSize,
      };

      Object.entries(filters).forEach(([key, value]) => {
        if (value.trim()) params[key] = value.trim();
      });

      const response = await axios.get(`${API_URL}/api/audit/logs`, {
        params,
        headers: { Authorization: `Bearer ${token}` },
      });

      const data = response.data || {};
      setLogs(Array.isArray(data.logs) ? data.logs : []);
      setTotalCount(Number(data.total_count ?? data.count ?? 0));
      setTotalPages(Math.max(1, Number(data.total_pages ?? 1)));
      setPage(Number(data.page ?? nextPage));
    } catch (err) {
      console.error(err);

      if (err.response?.status === 401) {
        onLogout?.();
        return;
      }

      setError(
        err.response?.data?.detail ||
          "Unable to load the audit trail."
      );
      setLogs([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadLogs(1);
    // Filters are intentionally handled by the Apply button.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  function applyFilters(event) {
    event?.preventDefault();
    loadLogs(1);
  }

  function clearFilters() {
    const empty = {
      action: "",
      status: "",
      username: "",
      resource_type: "",
    };
    setFilters(empty);
    setPage(1);

    // Load immediately with cleared filters instead of waiting for state.
    if (!token) return;

    axios
      .get(`${API_URL}/api/audit/logs`, {
        params: { page: 1, page_size: pageSize },
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((response) => {
        const data = response.data || {};
        setLogs(Array.isArray(data.logs) ? data.logs : []);
        setTotalCount(Number(data.total_count ?? data.count ?? 0));
        setTotalPages(Math.max(1, Number(data.total_pages ?? 1)));
      })
      .catch((err) => {
        if (err.response?.status === 401) {
          onLogout?.();
        } else {
          setError(
            err.response?.data?.detail ||
              "Unable to clear the audit filters."
          );
        }
      });
  }

  const rangeText = useMemo(() => {
    if (!totalCount || !logs.length) return "0 events";
    const start = (page - 1) * pageSize + 1;
    const end = Math.min(start + logs.length - 1, totalCount);
    return `${start}–${end} of ${totalCount} events`;
  }, [logs.length, page, pageSize, totalCount]);

  return (
    <section className="audit-page">
      <div className="section-heading">
        <div>
          <span className="eyebrow">GOVERNANCE</span>
          <h2>Audit Trail</h2>
          <p>
            Review security operations and user activity recorded by
            NetSecure Analyzer.
          </p>
        </div>

        <button
          type="button"
          className="secondary-button"
          onClick={() => loadLogs(page)}
          disabled={loading}
        >
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {error && <div className="error">{error}</div>}

      <section className="result-card-large audit-filters-card">
        <form onSubmit={applyFilters}>
          <div className="form-grid">
            <label>
              Action
              <input
                value={filters.action}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    action: event.target.value,
                  }))
                }
                placeholder="e.g. REMEDIATION_EXECUTED"
              />
            </label>

            <label>
              Status
              <select
                value={filters.status}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    status: event.target.value,
                  }))
                }
              >
                <option value="">All statuses</option>
                <option value="SUCCESS">SUCCESS</option>
                <option value="FAILED">FAILED</option>
              </select>
            </label>

            <label>
              Username
              <input
                value={filters.username}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    username: event.target.value,
                  }))
                }
                placeholder="admin"
              />
            </label>

            <label>
              Resource Type
              <input
                value={filters.resource_type}
                onChange={(event) =>
                  setFilters((current) => ({
                    ...current,
                    resource_type: event.target.value,
                  }))
                }
                placeholder="remediation_request"
              />
            </label>
          </div>

          <div className="audit-filter-actions">
            <button type="submit" className="primary-button">
              Apply Filters
            </button>
            <button
              type="button"
              className="secondary-button"
              onClick={clearFilters}
            >
              Clear
            </button>
          </div>
        </form>
      </section>

      <section className="result-card-large">
        <div className="audit-table-header">
          <div>
            <h3>Security Activity</h3>
            <p className="muted">{rangeText}</p>
          </div>
          <span className="module-status">
            {totalCount} Total
          </span>
        </div>

        {loading && logs.length === 0 ? (
          <div className="empty-state">
            <p>Loading audit events...</p>
          </div>
        ) : logs.length === 0 ? (
          <div className="empty-state">
            <h3>No audit events found</h3>
            <p>Try clearing the filters or performing a security operation.</p>
          </div>
        ) : (
          <div className="audit-event-list">
            {logs.map((log) => {
              const expanded = expandedId === log.id;

              return (
                <article className="audit-event-card" key={log.id}>
                  <div className="audit-event-main">
                    <div className="audit-event-icon" aria-hidden="true">
                      <svg
                        viewBox="0 0 24 24"
                        width="16"
                        height="16"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.8"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      >
                        <path d="M12 3 5 6v5c0 4.4 2.8 8.3 7 10 4.2-1.7 7-5.6 7-10V6l-7-3Z" />
                        <path d="m9.5 12 1.7 1.7 3.6-3.6" />
                      </svg>
                    </div>

                    <div className="audit-event-content">
                      <div className="audit-event-top">
                        <div>
                          <span className="audit-event-action">
                            {formatAction(log.action)}
                          </span>
                          <h3>
                            {log.resource_type || "System activity"}
                            {log.resource_id
                              ? ` #${log.resource_id}`
                              : ""}
                          </h3>
                        </div>

                        <span
                          className={`status-badge ${statusClass(
                            log.status
                          )}`}
                        >
                          {log.status || "UNKNOWN"}
                        </span>
                      </div>

                      <div className="remediation-meta-grid">
                        <div>
                          <span>User</span>
                          <strong>{log.username || `User ${log.user_id ?? "—"}`}</strong>
                        </div>
                        <div>
                          <span>Timestamp</span>
                          <strong>{formatDate(log.created_at)}</strong>
                        </div>
                        <div>
                          <span>Resource</span>
                          <strong>{log.resource_type || "—"}</strong>
                        </div>
                        <div>
                          <span>Source</span>
                          <strong>{log.ip_address || "Not recorded"}</strong>
                        </div>
                      </div>

                      {expanded && (
                        <div className="audit-event-details">
                          <h4>Event Details</h4>
                          <pre>
                            {JSON.stringify(log.details || {}, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  </div>

                  <button
                    type="button"
                    className="secondary-button small-button"
                    onClick={() =>
                      setExpandedId(expanded ? null : log.id)
                    }
                  >
                    {expanded ? "Hide Details" : "View Details"}
                  </button>
                </article>
              );
            })}
          </div>
        )}

        {totalPages > 1 && (
          <div className="audit-pagination">
            <button
              type="button"
              className="secondary-button"
              disabled={page <= 1 || loading}
              onClick={() => loadLogs(page - 1)}
            >
              Previous
            </button>

            <span>
              Page {page} of {totalPages}
            </span>

            <button
              type="button"
              className="secondary-button"
              disabled={page >= totalPages || loading}
              onClick={() => loadLogs(page + 1)}
            >
              Next
            </button>
          </div>
        )}
      </section>
    </section>
  );
}
