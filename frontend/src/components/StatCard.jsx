export default function StatCard({
  label,
  value,
  description,
  icon,
  variant = "",
}) {
  return (
    <div className={`stat-card ${variant}`}>
      <div className="stat-card-top">
        <span className="stat-icon">{icon}</span>
        <span className="stat-label">{label}</span>
      </div>

      <strong className="stat-value">
        {value}
      </strong>

      {description && (
        <span className="stat-description">
          {description}
        </span>
      )}
    </div>
  );
}
