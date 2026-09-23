const navigation = [
  {
    id: "dashboard",
    label: "Dashboard",
    icon: "dashboard",
  },
  {
    id: "devices",
    label: "Devices",
    icon: "devices",
  },
  {
    id: "configurations",
    label: "Configurations",
    icon: "configurations",
  },
  {
    id: "compliance",
    label: "Compliance",
    icon: "compliance",
  },
  {
    id: "live-scan",
    label: "Live Scan",
    icon: "live-scan",
  },
  {
    id: "remediation",
    label: "Remediation",
    icon: "remediation",
  },
  {
    id: "training",
    label: "AI Training",
    icon: "training",
  },
  {
    id: "audit",
    label: "Audit Trail",
    icon: "audit",
  },
  {
    id: "reports",
    label: "Reports",
    icon: "reports",
  },
];

function SidebarIcon({ type }) {
  const common = {
    width: 18,
    height: 18,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": "true",
  };

  switch (type) {
    case "dashboard":
      return (
        <svg {...common}>
          <rect x="3" y="3" width="7" height="7" rx="1" />
          <rect x="14" y="3" width="7" height="7" rx="1" />
          <rect x="3" y="14" width="7" height="7" rx="1" />
          <rect x="14" y="14" width="7" height="7" rx="1" />
        </svg>
      );

    case "devices":
      return (
        <svg {...common}>
          <rect x="3" y="4" width="18" height="13" rx="2" />
          <path d="M8 21h8" />
          <path d="M12 17v4" />
          <path d="M7 8h4" />
          <path d="M7 11h7" />
        </svg>
      );

    case "configurations":
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

    case "compliance":
      return (
        <svg {...common}>
          <path d="M12 3l7 3v5c0 4.6-2.9 8.1-7 10-4.1-1.9-7-5.4-7-10V6l7-3z" />
          <path d="M8.5 12l2.2 2.2 4.8-5" />
        </svg>
      );

    case "live-scan":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="7" />
          <path d="M12 8v4l3 2" />
          <path d="M5 5l-2 2" />
          <path d="M19 5l2 2" />
        </svg>
      );

    case "remediation":
      return (
        <svg {...common}>
          <path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L4 17v3h3l5.3-5.3a4 4 0 0 0 5.4-5.4l-2.1 2.1-2.5-.5-.5-2.5 2.1-2.1z" />
          <path d="M17 17l4 4" />
        </svg>
      );

    case "training":
      return (
        <svg {...common}>
          <path d="M3 8l9-4 9 4-9 4-9-4z" />
          <path d="M7 10v5c2.8 2 7.2 2 10 0v-5" />
          <path d="M21 8v6" />
        </svg>
      );

    case "audit":
      return (
        <svg {...common}>
          <path d="M6 3h9l3 3v15H6z" />
          <path d="M15 3v4h4" />
          <path d="M9 11h6" />
          <path d="M9 15h6" />
          <path d="M9 19h4" />
        </svg>
      );

    case "reports":
      return (
        <svg {...common}>
          <path d="M5 20V10" />
          <path d="M12 20V4" />
          <path d="M19 20v-7" />
          <path d="M3 20h18" />
        </svg>
      );

    default:
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="8" />
        </svg>
      );
  }
}

export default function Sidebar({
  activeView,
  onNavigate,
  user,
}) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">N</div>

        <div>
          <strong>NETSECURE</strong>
          <span>ANALYZER</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <span className="sidebar-section">
          OPERATIONS
        </span>

        {navigation.map((item) => (
          <button
            key={item.id}
            type="button"
            className={
              activeView === item.id
                ? "sidebar-link active"
                : "sidebar-link"
            }
            onClick={() => onNavigate(item.id)}
          >
            <span className="sidebar-icon">
              <SidebarIcon type={item.icon} />
            </span>

            <span>{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-bottom">
        <div className="sidebar-user">
          <div className="avatar">
            {user?.username
              ?.charAt(0)
              ?.toUpperCase() || "A"}
          </div>

          <div>
            <strong>
              {user?.username || "Administrator"}
            </strong>

            {String(user?.role || "").toUpperCase() === "ADMIN" && (
              <span>{user?.role}</span>
            )}
          </div>
        </div>
      </div>
    </aside>
  );
}
