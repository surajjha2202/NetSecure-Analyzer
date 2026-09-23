export default function StatusBadge({ status }) {
  const normalized = String(status || "")
    .toUpperCase();

  let className = "status-badge neutral";

  if (
    ["ONLINE", "HEALTHY", "SUCCESS", "PASS", "ACTIVE"].includes(
      normalized
    )
  ) {
    className = "status-badge success";
  }

  if (
    ["FAIL", "FAILED", "ERROR", "CRITICAL", "OFFLINE"].includes(
      normalized
    )
  ) {
    className = "status-badge danger";
  }

  if (
    ["WARNING", "PENDING", "ANALYZING"].includes(
      normalized
    )
  ) {
    className = "status-badge warning";
  }

  if (normalized === "N/A") {
    className = "status-badge neutral";
  }

  return (
    <span className={className}>
      {status || "UNKNOWN"}
    </span>
  );
}
