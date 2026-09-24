import Devices from "./pages/Devices";
import { useEffect, useState } from "react";
import axios from "axios";

import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import Configurations from "./pages/Configurations";
import Remediation from "./pages/Remediation";
import Compliance from "./pages/Compliance";
import AuditTrail from "./pages/AuditTrail";
import Reports from "./pages/Reports";
import { createRemediationRequest } from "./api/remediation";
import { getDevices } from "./api/devices";
import { API_URL } from "./api/client";

const FRAMEWORKS = [
  "CIS",
  "NIST",
  "DISA_STIG",
  "ISO_27001",
];

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

function formatFrameworkName(name) {
  if (name === "DISA_STIG") return "DISA STIG";
  if (name === "ISO_27001") return "ISO/IEC 27001";
  return name;
}

function App() {
  const [token, setToken] = useState(
    () => localStorage.getItem("netsecure_token")
  );

  const [user, setUser] = useState(null);
  const [activeView, setActiveView] = useState("dashboard");
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  const [system, setSystem] = useState(null);
  const [database, setDatabase] = useState(null);
  const [redis, setRedis] = useState(null);
  const [selectedTrainingCandidateId, setSelectedTrainingCandidateId] =
  useState(null);
  const [mappings, setMappings] = useState([]);
  const [latestAnalysis, setLatestAnalysis] = useState(null);
  const [trainingLoading, setTrainingLoading] = useState(false);
  const [trainingError, setTrainingError] = useState(null);
  const [trainingCandidates, setTrainingCandidates] = useState([]);
  const [trainingStats, setTrainingStats] = useState({
  pending: 0,
  approved: 0,
  rejected: 0,
  total: 0,
});

const [selectedTrainingCandidateIds, setSelectedTrainingCandidateIds] =
  useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [form, setForm] = useState({
    configuration_pattern: "",
    security_category: "",
    baseline_parameter: "",
    expected_value: "",
  });

    useEffect(() => {
    async function checkServices() {
      setLoading(true);
      setError(null);

      const results = await Promise.allSettled([
        axios.get(`${API_URL}/api/health`, {
          timeout: 5000,
        }),

        axios.get(`${API_URL}/api/health/database`, {
          timeout: 5000,
        }),

        axios.get(`${API_URL}/api/health/redis`, {
          timeout: 5000,
        }),
      ]);

      const [
        systemResult,
        databaseResult,
        redisResult,
      ] = results;

      if (systemResult.status === "fulfilled") {
        setSystem(systemResult.value.data);
      } else {
        console.error(
          "FastAPI health check failed:",
          systemResult.reason
        );
        setSystem({
          status: "unhealthy",
          version: "Unavailable",
        });
      }

      if (databaseResult.status === "fulfilled") {
        setDatabase(databaseResult.value.data);
      } else {
        console.error(
          "Database health check failed:",
          databaseResult.reason
        );
        setDatabase({
          status: "unhealthy",
          connection: false,
        });
      }

      if (redisResult.status === "fulfilled") {
        setRedis(redisResult.value.data);
      } else {
        console.error(
          "Redis health check failed:",
          redisResult.reason
        );
        setRedis({
          status: "unhealthy",
          connection: false,
        });
      }

      if (
        systemResult.status === "rejected" &&
        databaseResult.status === "rejected" &&
        redisResult.status === "rejected"
      ) {
        setError(
          "Unable to connect to the NetSecure Analyzer backend."
        );
      }

      setLoading(false);
    }

    checkServices();
  }, []);

  useEffect(() => {
    if (!token) {
      setUser(null);
      return;
    }

    async function loadCurrentUser() {
      try {
        const response = await axios.get(
          `${API_URL}/api/auth/me`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        setUser(response.data);
      } catch (err) {
        console.error(err);

        localStorage.removeItem("netsecure_token");
        setToken(null);
        setUser(null);
      }
    }

    loadCurrentUser();
  }, [token]);

  async function login(username, password) {
    try {
      setError(null);

      const response = await axios.post(
        `${API_URL}/api/auth/login`,
        {
          username,
          password,
        }
      );

      const accessToken = response.data.access_token;

      localStorage.setItem(
        "netsecure_token",
        accessToken
      );

      setToken(accessToken);

      return true;
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          "Invalid username or password."
      );

      return false;
    }
  }

  async function register(username, email, password) {
    try {
      setError(null);

      await axios.post(
        `${API_URL}/api/auth/register`,
        {
          username,
          email,
          password,
        }
      );

      return true;
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          "Unable to create your account."
      );

      return false;
    }
  }

  async function forgotPassword(email) {
    try {
      setError(null);

      await axios.post(
        `${API_URL}/api/auth/forgot-password`,
        {
          email,
        }
      );

      return true;
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          "Unable to process the password reset request."
      );

      return false;
    }
  }

  async function resetPassword(token, newPassword) {
    try {
      setError(null);

      await axios.post(
        `${API_URL}/api/auth/reset-password`,
        {
          token,
          new_password: newPassword,
        }
      );

      return true;
    } catch (err) {
      console.error(err);

      setError(
        err.response?.data?.detail ||
          "Unable to reset your password."
      );

      return false;
    }
  }

  function logout() {
    localStorage.removeItem("netsecure_token");

    // Clear authentication state.
    setToken(null);
    setUser(null);

    // Reset navigation.
    setActiveView("dashboard");

    // Clear account-specific training state.
    setMappings([]);
    setTrainingCandidates([]);
    setTrainingStats({
      pending: 0,
      approved: 0,
      rejected: 0,
      total: 0,
    });
    setSelectedTrainingCandidateId(null);
    setSelectedTrainingCandidateIds([]);
    setTrainingError(null);
    setTrainingLoading(false);

    // Clear account-specific analysis state.
    setLatestAnalysis(null);

    // Clear form state.
    setForm({
      configuration_pattern: "",
      security_category: "",
      baseline_parameter: "",
      expected_value: "",
    });

    // Clear application-level errors.
    setError(null);
  }
    useEffect(() => {
    function handleExpiredToken() {
      logout();
    }

    window.addEventListener(
      "netsecure:logout",
      handleExpiredToken
    );

    return () => {
      window.removeEventListener(
        "netsecure:logout",
        handleExpiredToken
      );
    };
  }, []);

  async function loadMappings() {
    setTrainingError(null);

    if (!token) {
      setTrainingError(
        "You must be logged in to access Human Training."
      );
      return;
    }

    try {
      setTrainingLoading(true);

      const response = await axios.get(
        `${API_URL}/api/training/mappings`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      setMappings(response.data.mappings || []);
    } catch (err) {
      console.error(err);

      if (err.response?.status === 401) {
        logout();
        setTrainingError("Your session has expired.");
      } else {
        setTrainingError(
          "Unable to load learned mappings."
        );
      }
    } finally {
      setTrainingLoading(false);
    }
  }

  async function loadTrainingCandidates() {
    setTrainingError(null);

    if (!token) {
      setTrainingError(
        "You must be logged in to access Human Training."
      );
      return;
    }

    try {
      setTrainingLoading(true);

      const headers = {
        Authorization: `Bearer ${token}`,
      };

      const [
        pendingResponse,
        approvedResponse,
        rejectedResponse,
      ] = await Promise.all([
        axios.get(
          `${API_URL}/api/training/candidates?candidate_status=PENDING`,
          { headers }
        ),
        axios.get(
          `${API_URL}/api/training/candidates?candidate_status=APPROVED`,
          { headers }
        ),
        axios.get(
          `${API_URL}/api/training/candidates?candidate_status=REJECTED`,
          { headers }
        ),
      ]);

      const pendingCount = Number(
        pendingResponse.data.count || 0
      );

      const approvedCount = Number(
        approvedResponse.data.count || 0
      );

      const rejectedCount = Number(
        rejectedResponse.data.count || 0
      );

      setTrainingCandidates(
        pendingResponse.data.candidates || []
      );

      setTrainingStats({
        pending: pendingCount,
        approved: approvedCount,
        rejected: rejectedCount,
        total:
          pendingCount +
          approvedCount +
          rejectedCount,
      });

      setSelectedTrainingCandidateIds([]);
    } catch (err) {
      console.error(err);

      if (err.response?.status === 401) {
        logout();
        return;
      }

      setTrainingError(
        err.response?.data?.detail ||
          "Failed to load training candidates."
      );
    } finally {
      setTrainingLoading(false);
    }
  }

  async function createMapping(event) {
    event.preventDefault();
    setTrainingError(null);

    if (!token) {
      setTrainingError(
        "You must be logged in to create a mapping."
      );
      return;
    }

    if (!form.configuration_pattern.trim()) {
      setTrainingError(
        "Configuration pattern is required."
      );
      return;
    }

    if (!form.security_category) {
      setTrainingError(
        "Select a security category."
      );
      return;
    }

    if (!form.baseline_parameter) {
      setTrainingError(
        "Select a baseline parameter."
      );
      return;
    }

    if (!form.expected_value) {
      setTrainingError(
        "Select an expected value."
      );
      return;
    }

    try {
      setTrainingLoading(true);

      const endpoint = selectedTrainingCandidateId
        ? `${API_URL}/api/training/candidates/${selectedTrainingCandidateId}/approve`
        : `${API_URL}/api/training/mappings`;

      await axios.post(
        endpoint,
        form,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      setForm({
        configuration_pattern: "",
        security_category: "",
        baseline_parameter: "",
        expected_value: "",
      });

      setSelectedTrainingCandidateId(null);

      await Promise.all([
        loadMappings(),
        loadTrainingCandidates(),
      ]);
    } catch (err) {
      console.error(err);

      if (err.response?.status === 401) {
        logout();
        return;
      }

      setTrainingError(
        err.response?.data?.detail ||
          "Unable to save the learned mapping."
      );
    } finally {
      setTrainingLoading(false);
    }
  }

  async function rejectTrainingCandidate(candidateId) {
  setTrainingLoading(true);
  setTrainingError(null);

  if (!token) {
    setTrainingError(
      "You must be logged in to reject a training candidate."
    );
    setTrainingLoading(false);
    return;
  }

  try {
    await axios.post(
      `${API_URL}/api/training/candidates/${candidateId}/reject`,
      null,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    await loadTrainingCandidates();
  } catch (err) {
    console.error(err);

    if (err.response?.status === 401) {
      logout();
      return;
    }

    setTrainingError(
      err.response?.data?.detail ||
        "Failed to reject training candidate."
    );
  } finally {
    setTrainingLoading(false);
  }
}

async function rejectSelectedTrainingCandidates() {
  if (selectedTrainingCandidateIds.length === 0) {
    return;
  }

  setTrainingLoading(true);
  setTrainingError(null);

  if (!token) {
    setTrainingError(
      "You must be logged in to reject training candidates."
    );
    setTrainingLoading(false);
    return;
  }

  try {
    await axios.post(
      `${API_URL}/api/training/candidates/reject-batch`,
      {
        candidate_ids: selectedTrainingCandidateIds,
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );

    await loadTrainingCandidates();
  } catch (err) {
    console.error(err);

    if (err.response?.status === 401) {
      logout();
      return;
    }

    setTrainingError(
      err.response?.data?.detail ||
        "Failed to reject selected candidates."
    );
  } finally {
    setTrainingLoading(false);
  }
}

  async function toggleMapping(mapping) {
    if (!token) {
      setTrainingError(
        "You must be logged in to update mappings."
      );
      return;
    }

    try {
      setTrainingError(null);

      await axios.patch(
        `${API_URL}/api/training/mappings/${mapping.id}/status`,
        null,
        {
          params: {
            is_active: !mapping.is_active,
          },
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      await loadMappings();
    } catch (err) {
      console.error(err);

      if (err.response?.status === 401) {
        logout();
        return;
      }

      setTrainingError(
        err.response?.data?.detail ||
          "Unable to update the mapping status."
      );
    }
  }

  function openTraining() {
    setActiveView("training");
    loadMappings();
    loadTrainingCandidates();
  }
  function teachTrainingCandidate(candidate) {
    setSelectedTrainingCandidateId(candidate.id);
    setForm({
      configuration_pattern:
        candidate.configuration_line || "",

      security_category:
        candidate.suggested_category &&
        candidate.suggested_category !== "None"
          ? candidate.suggested_category
          : "",

      baseline_parameter:
        candidate.suggested_baseline_parameter &&
        candidate.suggested_baseline_parameter !== "None"
          ? candidate.suggested_baseline_parameter
          : "",

      expected_value:
        candidate.suggested_expected_value === "False"
          ? "False"
          : candidate.suggested_expected_value === "True"
            ? "True"
            : "",
    });

    setActiveView("training");
    loadMappings();
  }

  const resetPath = window.location.pathname === "/reset-password";
  const resetToken = new URLSearchParams(
    window.location.search
  ).get("token");

  if (resetPath) {
    return (
      <ResetPasswordScreen
        token={resetToken}
        onResetPassword={resetPassword}
        onBackToLogin={() => {
          window.history.replaceState(
            {},
            "",
            "/"
          );
          window.location.reload();
        }}
      />
    );
  }

  if (loading) {
    return (
      <div className="app">
        <div className="container">
          <h1>NetSecure Analyzer</h1>
          <p>Checking system services...</p>
        </div>
      </div>
    );
  }

  if (!token || !user) {
    return (
      <LoginScreen
        onLogin={login}
        onRegister={register}
        onForgotPassword={forgotPassword}
        onResetPassword={resetPassword}
        error={error}
      />
    );
  }

    return (
      <div className="app dashboard-app">
        <Sidebar
          activeView={activeView}
          mobileOpen={mobileSidebarOpen}
          onMobileClose={() => setMobileSidebarOpen(false)}
          onNavigate={(view) => {
            if (view === "training") {
              openTraining();
              setMobileSidebarOpen(false);
              return;
            }

            setActiveView(view);
            setMobileSidebarOpen(false);
          }}
          user={user}
        />

        <main className="main-content">
          <header className="dashboard-topbar">
            <button
              type="button"
              className="mobile-menu-button"
              onClick={() => setMobileSidebarOpen(true)}
              aria-label="Open navigation menu"
              aria-expanded={mobileSidebarOpen}
            >
              <span></span>
              <span></span>
              <span></span>
            </button>

            <div className="topbar-title">
              <span className="topbar-product">
                NETSECURE ANALYZER
              </span>

              <h1>
                {activeView === "dashboard"
                  ? "Security Operations"
                  : activeView === "training"
                    ? "AI Training"
                    : activeView === "analysis"
                      ? "Configuration Analysis"
                      : activeView === "devices"
                        ? "Devices"
                        : activeView === "configurations"
                          ? "Configurations"
                          : activeView === "compliance"
                            ? "Compliance"
                            : activeView === "live-scan"
                              ? "Live Scan"
                              : activeView === "remediation"
                                ? "Remediation"
                                : activeView === "audit"
                                  ? "Audit Trail"
                                  : activeView === "reports"
                                    ? "Reports"
                                    : "Security Operations"}
              </h1>

              <p>
                {activeView === "dashboard"
                  ? "Network security posture and compliance overview."
                  : activeView === "training"
                    ? "Teach the analyzer unknown configuration semantics."
                    : activeView === "analysis"
                      ? "Upload, analyze and assess network device configurations."
                      : "NetSecure Analyzer security operations."}
              </p>
            </div>

            <div className="topbar-actions">
              <div className="topbar-user">
                <div className="topbar-avatar">
                  {user?.username?.charAt(0)?.toUpperCase() || "A"}
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

              <button
                className="logout-button"
                onClick={logout}
              >
                Logout
              </button>
            </div>
          </header>

          {error && (
            <div className="error dashboard-error">
              {error}
            </div>
          )}

          <div className="page-content">
            {activeView === "dashboard" ? (
              <Dashboard
                onNavigate={(view) => setActiveView(view)}
              />
) : activeView === "compliance" ? (
              <Compliance token={token} />
            ) : activeView === "training" ? (
              <TrainingView
                mappings={mappings}
                trainingCandidates={trainingCandidates}
                trainingStats={trainingStats}
                selectedTrainingCandidateIds={selectedTrainingCandidateIds}
                setSelectedTrainingCandidateIds={setSelectedTrainingCandidateIds}
                form={form}
                setForm={setForm}
                loading={trainingLoading}
                error={trainingError}
                onSubmit={createMapping}
                onToggle={toggleMapping}
                onRefresh={() => {
                  loadMappings();
                  loadTrainingCandidates();
                }}
                onTeach={teachTrainingCandidate}
                onReject={rejectTrainingCandidate}
                onRejectSelected={rejectSelectedTrainingCandidates}
              />
            ) : activeView === "devices" ? (
              <Devices />
            ) : activeView === "configurations" ? (
              <Configurations />
            ) : activeView === "remediation" ? (
              <Remediation latestAnalysis={latestAnalysis} />
            ) : activeView === "analysis" || activeView === "live-scan" ? (
              <ConfigurationAnalysisView
                token={token}
                onLogout={logout}
                onAnalysisComplete={setLatestAnalysis}
              />
            ) : activeView === "audit" ? (
              <AuditTrail
                token={token}
                onLogout={logout}
              />
            ) : activeView === "reports" ? (
              <Reports
                token={token}
                onLogout={logout}
                latestAnalysis={latestAnalysis}
              />
            ) : (
              <ModulePlaceholder
                view={activeView}
              />
            )}
          </div>
        </main>
      </div>
    );
  }

function ResetPasswordScreen({
  token,
  onResetPassword,
  onBackToLogin,
}) {
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] =
    useState("");
  const [showNewPassword, setShowNewPassword] =
    useState(false);
  const [showConfirmPassword, setShowConfirmPassword] =
    useState(false);
  const [loading, setLoading] = useState(false);
  const [formError, setFormError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  const passwordStrength = (() => {
    const value = newPassword;

    if (!value) {
      return {
        score: 0,
        label: "Enter a password",
      };
    }

    let score = 0;

    if (value.length >= 8) score += 1;
    if (/[a-z]/.test(value)) score += 1;
    if (/[A-Z]/.test(value)) score += 1;
    if (/[0-9]|[^A-Za-z0-9]/.test(value)) score += 1;

    return {
      score,
      label:
        score === 1
          ? "Weak"
          : score === 2
            ? "Fair"
            : score === 3
              ? "Good"
              : "Strong",
    };
  })();

  async function handleResetPassword(event) {
    event.preventDefault();
    setFormError("");
    setSuccessMessage("");

    if (!token) {
      setFormError(
        "This password reset link is invalid or incomplete."
      );
      return;
    }

    if (newPassword.length < 8) {
      setFormError(
        "Password must contain at least 8 characters."
      );
      return;
    }

    if (newPassword !== confirmPassword) {
      setFormError("Passwords do not match.");
      return;
    }

    setLoading(true);

    try {
      const reset = await onResetPassword(
        token,
        newPassword
      );

      if (reset) {
        setSuccessMessage(
          "Your password has been reset successfully. You can now sign in."
        );
        setNewPassword("");
        setConfirmPassword("");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-card auth-card">
        <div className="auth-brand">
          <div className="auth-brand-mark" aria-label="NetSecure Analyzer">
            <span>N</span><span>S</span>
          </div>

          <div>
            <strong>NETSECURE ANALYZER</strong>
            <span>
              Network security compliance platform
            </span>
          </div>
        </div>

        <div className="auth-heading">
          <h1>Choose a new password</h1>
          <p>
            Create a new password for your NetSecure
            Analyzer account.
          </p>
        </div>

        {successMessage && (
          <div className="auth-success">
            {successMessage}
          </div>
        )}

        {formError && (
          <div className="auth-error">
            {formError}
          </div>
        )}

        {!successMessage && (
          <form
            onSubmit={handleResetPassword}
            className="auth-form"
          >
            <label className="auth-field">
              <span>New Password</span>

              <div className="auth-password-field">
                <input
                  type={
                    showNewPassword
                      ? "text"
                      : "password"
                  }
                  value={newPassword}
                  onChange={(event) =>
                    setNewPassword(event.target.value)
                  }
                  placeholder="Create a new password"
                  autoComplete="new-password"
                  disabled={loading}
                  minLength={8}
                  required
                />

                <button
                  type="button"
                  className="auth-password-toggle"
                  onClick={() =>
                    setShowNewPassword(
                      !showNewPassword
                    )
                  }
                  disabled={loading}
                >
                  {showNewPassword
                    ? "Hide"
                    : "Show"}
                </button>
              </div>

              <div className="password-strength">
                <div className="password-strength-bars">
                  {[1, 2, 3, 4].map((segment) => (
                    <span
                      key={segment}
                      className={
                        segment <=
                        passwordStrength.score
                          ? "filled"
                          : ""
                      }
                    />
                  ))}
                </div>

                <span>
                  {passwordStrength.label}
                </span>
              </div>
            </label>

            <label className="auth-field">
              <span>Confirm Password</span>

              <div className="auth-password-field">
                <input
                  type={
                    showConfirmPassword
                      ? "text"
                      : "password"
                  }
                  value={confirmPassword}
                  onChange={(event) =>
                    setConfirmPassword(
                      event.target.value
                    )
                  }
                  placeholder="Confirm your new password"
                  autoComplete="new-password"
                  disabled={loading}
                  minLength={8}
                  required
                />

                <button
                  type="button"
                  className="auth-password-toggle"
                  onClick={() =>
                    setShowConfirmPassword(
                      !showConfirmPassword
                    )
                  }
                  disabled={loading}
                >
                  {showConfirmPassword
                    ? "Hide"
                    : "Show"}
                </button>
              </div>
            </label>

            <button
              type="submit"
              className="primary-button auth-submit"
              disabled={loading}
            >
              {loading
                ? "Resetting..."
                : "Reset Password"}
            </button>
          </form>
        )}

        <div className="auth-switch">
          <span>
            {successMessage
              ? "Ready to sign in?"
              : "Remember your password?"}
          </span>

          <button
            type="button"
            className="secondary-button auth-switch-button"
            onClick={onBackToLogin}
            disabled={loading}
          >
            Back to Sign In
          </button>
        </div>
      </div>
    </div>
  );
}
function LoginScreen({
  onLogin,
  onRegister,
  onForgotPassword,
  onResetPassword,
  error,
}) {
  const [mode, setMode] = useState("login");

  const [forgotEmail, setForgotEmail] = useState("");

  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");

  const [registerUsername, setRegisterUsername] = useState("");
  const [registerEmail, setRegisterEmail] = useState("");
  const [registerPassword, setRegisterPassword] = useState("");
  const [registerConfirmPassword, setRegisterConfirmPassword] =
    useState("");

  const [showLoginPassword, setShowLoginPassword] =
    useState(false);
  const [showRegisterPassword, setShowRegisterPassword] =
    useState(false);
  const [showConfirmPassword, setShowConfirmPassword] =
    useState(false);

  const [loading, setLoading] = useState(false);
  const [formError, setFormError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  const passwordStrength = (() => {
    const value = registerPassword;

    if (!value) {
      return {
        score: 0,
        label: "Enter a password",
      };
    }

    let score = 0;

    if (value.length >= 8) score += 1;
    if (/[a-z]/.test(value)) score += 1;
    if (/[A-Z]/.test(value)) score += 1;
    if (/[0-9]|[^A-Za-z0-9]/.test(value)) score += 1;

    return {
      score,
      label:
        score === 1
          ? "Weak"
          : score === 2
            ? "Fair"
            : score === 3
              ? "Good"
              : "Strong",
    };
  })();

  async function handleLogin(event) {
    event.preventDefault();
    setFormError("");
    setSuccessMessage("");

    const username = loginUsername.trim();

    if (!username || !loginPassword) {
      setFormError("Enter your username and password.");
      return;
    }

    setLoading(true);

    try {
      await onLogin(username, loginPassword);
    } finally {
      setLoading(false);
    }
  }

  async function handleRegister(event) {
    event.preventDefault();
    setFormError("");
    setSuccessMessage("");

    const username = registerUsername.trim();
    const email = registerEmail.trim();

    if (username.length < 3) {
      setFormError(
        "Username must contain at least 3 characters."
      );
      return;
    }

    if (!email) {
      setFormError("Enter your email address.");
      return;
    }

    if (registerPassword.length < 8) {
      setFormError(
        "Password must contain at least 8 characters."
      );
      return;
    }

    if (registerPassword !== registerConfirmPassword) {
      setFormError("Passwords do not match.");
      return;
    }

    setLoading(true);

    try {
      const registered = await onRegister(
        username,
        email,
        registerPassword
      );

      if (registered) {
        setRegisterPassword("");
        setRegisterConfirmPassword("");
        setSuccessMessage(
          "Account created successfully. You can now sign in."
        );
        setMode("login");
        setLoginUsername(username);
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleForgotPassword(event) {
    event.preventDefault();
    setFormError("");
    setSuccessMessage("");

    const email = forgotEmail.trim();

    if (!email) {
      setFormError("Enter your email address.");
      return;
    }

    setLoading(true);

    try {
      const requested = await onForgotPassword(email);

      if (requested) {
        setSuccessMessage(
          "If an account exists for this email, a password reset link has been sent."
        );
        setForgotEmail("");
      }
    } finally {
      setLoading(false);
    }
  }

  function switchMode(nextMode) {
    setMode(nextMode);
    setFormError("");
    setSuccessMessage("");

    if (nextMode !== "forgot") {
      setForgotEmail("");
    }
  }

  return (
    <div className="login-page">
      <div className="login-card auth-card">
        <div className="auth-brand">
          <div className="auth-brand-mark" aria-label="NetSecure Analyzer">
            <span>N</span><span>S</span>
          </div>

          <div>
            <strong>NETSECURE ANALYZER</strong>
            <span>
              Network security compliance platform
            </span>
          </div>
        </div>

        {mode === "login" ? (
          <>
            <div className="auth-heading">
              <h1>Welcome back</h1>
              <p>
                Sign in to access your security operations
                workspace.
              </p>
            </div>

            {successMessage && (
              <div className="auth-success">
                {successMessage}
              </div>
            )}

            {(formError || error) && (
              <div className="auth-error">
                {formError || error}
              </div>
            )}

            <form
              onSubmit={handleLogin}
              className="auth-form"
            >
              <label className="auth-field">
                <span>Username</span>

                <input
                  type="text"
                  value={loginUsername}
                  onChange={(event) =>
                    setLoginUsername(event.target.value)
                  }
                  placeholder="Enter your username"
                  autoComplete="username"
                  disabled={loading}
                  required
                />
              </label>

              <label className="auth-field">
                <span>Password</span>

                <div className="auth-password-field">
                  <input
                    type={
                      showLoginPassword
                        ? "text"
                        : "password"
                    }
                    value={loginPassword}
                    onChange={(event) =>
                      setLoginPassword(event.target.value)
                    }
                    placeholder="Enter your password"
                    autoComplete="current-password"
                    disabled={loading}
                    required
                  />

                  <button
                    type="button"
                    className="auth-password-toggle"
                    onClick={() =>
                      setShowLoginPassword(
                        !showLoginPassword
                      )
                    }
                    disabled={loading}
                  >
                    {showLoginPassword
                      ? "Hide"
                      : "Show"}
                  </button>
                </div>
              </label>

              <div className="auth-forgot-row">
                <button
                  type="button"
                  className="auth-forgot-link"
                  onClick={() => switchMode("forgot")}
                  disabled={loading}
                >
                  Forgot password?
                </button>
              </div>

              <button
                type="submit"
                className="primary-button auth-submit"
                disabled={loading}
              >
                {loading
                  ? "Signing in..."
                  : "Sign In"}
              </button>
            </form>

            <div className="auth-switch">
              <span>
                Don't have an account?
              </span>

              <button
                type="button"
                className="secondary-button auth-switch-button"
                onClick={() =>
                  switchMode("register")
                }
                disabled={loading}
              >
                Create Account
              </button>
            </div>
          </>
        ) : mode === "forgot" ? (
          <>
            <div className="auth-heading">
              <h1>Reset your password</h1>
              <p>
                Enter your account email and we’ll send you a
                secure password reset link.
              </p>
            </div>

            {successMessage && (
              <div className="auth-success">
                {successMessage}
              </div>
            )}

            {(formError || error) && (
              <div className="auth-error">
                {formError || error}
              </div>
            )}

            <form
              onSubmit={handleForgotPassword}
              className="auth-form"
            >
              <label className="auth-field">
                <span>Email</span>

                <input
                  type="email"
                  value={forgotEmail}
                  onChange={(event) =>
                    setForgotEmail(event.target.value)
                  }
                  placeholder="you@example.com"
                  autoComplete="email"
                  disabled={loading}
                  required
                />
              </label>

              <button
                type="submit"
                className="primary-button auth-submit"
                disabled={loading}
              >
                {loading
                  ? "Sending..."
                  : "Send Reset Link"}
              </button>
            </form>

            <div className="auth-switch">
              <span>Remember your password?</span>

              <button
                type="button"
                className="secondary-button auth-switch-button"
                onClick={() => switchMode("login")}
                disabled={loading}
              >
                Back to Sign In
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="auth-heading">
              <h1>Create your account</h1>
              <p>
                Create an account to start managing your
                network security workspace.
              </p>
            </div>

            {(formError || error) && (
              <div className="auth-error">
                {formError || error}
              </div>
            )}

            <form
              onSubmit={handleRegister}
              className="auth-form"
            >
              <label className="auth-field">
                <span>Username</span>

                <input
                  type="text"
                  value={registerUsername}
                  onChange={(event) =>
                    setRegisterUsername(
                      event.target.value
                    )
                  }
                  placeholder="Choose a username"
                  autoComplete="username"
                  disabled={loading}
                  minLength={3}
                  required
                />
              </label>

              <label className="auth-field">
                <span>Email</span>

                <input
                  type="email"
                  value={registerEmail}
                  onChange={(event) =>
                    setRegisterEmail(
                      event.target.value
                    )
                  }
                  placeholder="you@example.com"
                  autoComplete="email"
                  disabled={loading}
                  required
                />
              </label>

              <label className="auth-field">
                <span>Password</span>

                <div className="auth-password-field">
                  <input
                    type={
                      showRegisterPassword
                        ? "text"
                        : "password"
                    }
                    value={registerPassword}
                    onChange={(event) =>
                      setRegisterPassword(
                        event.target.value
                      )
                    }
                    placeholder="Create a password"
                    autoComplete="new-password"
                    disabled={loading}
                    minLength={8}
                    required
                  />

                  <button
                    type="button"
                    className="auth-password-toggle"
                    onClick={() =>
                      setShowRegisterPassword(
                        !showRegisterPassword
                      )
                    }
                    disabled={loading}
                  >
                    {showRegisterPassword
                      ? "Hide"
                      : "Show"}
                  </button>
                </div>

                <div className="password-strength">
                  <div className="password-strength-bars">
                    {[1, 2, 3, 4].map((segment) => (
                      <span
                        key={segment}
                        className={
                          segment <=
                          passwordStrength.score
                            ? "filled"
                            : ""
                        }
                      />
                    ))}
                  </div>

                  <span>
                    {passwordStrength.label}
                  </span>
                </div>
              </label>

              <label className="auth-field">
                <span>Confirm Password</span>

                <div className="auth-password-field">
                  <input
                    type={
                      showConfirmPassword
                        ? "text"
                        : "password"
                    }
                    value={registerConfirmPassword}
                    onChange={(event) =>
                      setRegisterConfirmPassword(
                        event.target.value
                      )
                    }
                    placeholder="Confirm your password"
                    autoComplete="new-password"
                    disabled={loading}
                    required
                  />

                  <button
                    type="button"
                    className="auth-password-toggle"
                    onClick={() =>
                      setShowConfirmPassword(
                        !showConfirmPassword
                      )
                    }
                    disabled={loading}
                  >
                    {showConfirmPassword
                      ? "Hide"
                      : "Show"}
                  </button>
                </div>
              </label>


              <button
                type="submit"
                className="primary-button auth-submit"
                disabled={loading}
              >
                {loading
                  ? "Creating account..."
                  : "Create Account"}
              </button>
            </form>

            <div className="auth-switch">
              <span>
                Already have an account?
              </span>

              <button
                type="button"
                className="secondary-button auth-switch-button"
                onClick={() =>
                  switchMode("login")
                }
                disabled={loading}
              >
                Sign In
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
function Overview({ system, database, redis }) {
  return (
    <>
      <section className="status-grid">
        <StatusCard
          name="FastAPI"
          status={system?.status}
          detail={
            system
              ? `Version ${system.version}`
              : "Unavailable"
          }
        />

        <StatusCard
          name="PostgreSQL"
          status={database?.status}
          detail={
            database?.connection
              ? "Database connection verified"
              : "Connection unavailable"
          }
        />

        <StatusCard
          name="Redis"
          status={redis?.status}
          detail={
            redis?.connection
              ? "Redis connection verified"
              : "Connection unavailable"
          }
        />
      </section>

      <section className="foundation">
        <h2>Platform Modules</h2>

        <div className="module-grid">
          <ModuleCard
            title="Configuration Ingestion"
            description="Upload and analyze .cfg, .conf and .txt configurations."
            status="Ready"
          />

          <ModuleCard
            title="Device Intelligence"
            description="Identify vendor, platform, model, firmware and device type."
            status="Ready"
          />

          <ModuleCard
            title="Compliance Engine"
            description="Evaluate configurations against security frameworks."
            status="Ready"
          />

          <ModuleCard
            title="Human Training"
            description="Teach the analyzer unknown configuration semantics."
            status="Available"
          />
        </div>
      </section>
    </>
  );
}

function TrainingView({
  mappings,
  trainingCandidates,
  trainingStats,
  selectedTrainingCandidateIds,
  setSelectedTrainingCandidateIds,
  form,
  setForm,
  loading,
  error,
  onSubmit,
  onToggle,
  onRefresh,
  onTeach,
  onReject,
  onRejectSelected,
}) {
  const [mappingSearch, setMappingSearch] = useState("");
  const [mappingStatus, setMappingStatus] = useState("ALL");
  const [mappingCategory, setMappingCategory] = useState("ALL");
  const [selectedMapping, setSelectedMapping] = useState(null);
  const [showManualTrainingForm, setShowManualTrainingForm] =
    useState(false);

  const baselineParameters = {
    Authentication: [
      "authentication.aaa_new_model",
      "management.enable_secret",
    ],
    "Remote Access": [
      "remote_access.ssh_enabled",
      "remote_access.telnet_enabled",
    ],
    Logging: [
      "logging.local_buffered_logging",
      "logging.remote_syslog",
      "logging.timestamps",
    ],
    Cryptography: [
      "crypto.password_encryption",
    ],
    "Access Control": [
      "access_control.standard_acls",
    ],
  };

  const categories = [
    "Authentication",
    "Remote Access",
    "Logging",
    "Cryptography",
    "Access Control",
  ];

  const filteredMappings = mappings.filter((mapping) => {
    const search = mappingSearch.trim().toLowerCase();

    const matchesSearch =
      !search ||
      String(mapping.configuration_pattern || "")
        .toLowerCase()
        .includes(search) ||
      String(mapping.security_category || "")
        .toLowerCase()
        .includes(search) ||
      String(mapping.baseline_parameter || "")
        .toLowerCase()
        .includes(search);

    const matchesStatus =
      mappingStatus === "ALL" ||
      (mappingStatus === "ACTIVE" && mapping.is_active) ||
      (mappingStatus === "INACTIVE" && !mapping.is_active);

    const matchesCategory =
      mappingCategory === "ALL" ||
      mapping.security_category === mappingCategory;

    return matchesSearch && matchesStatus && matchesCategory;
  });

  const activeMappingCount = mappings.filter(
    (mapping) => mapping.is_active
  ).length;

  const toggleCandidate = (candidateId) => {
    setSelectedTrainingCandidateIds((current) =>
      current.includes(candidateId)
        ? current.filter((id) => id !== candidateId)
        : [...current, candidateId]
    );
  };

  const allCandidatesSelected =
    trainingCandidates.length > 0 &&
    trainingCandidates.every((candidate) =>
      selectedTrainingCandidateIds.includes(candidate.id)
    );

  const toggleSelectAll = () => {
    if (allCandidatesSelected) {
      setSelectedTrainingCandidateIds([]);
      return;
    }

    setSelectedTrainingCandidateIds(
      trainingCandidates.map((candidate) => candidate.id)
    );
  };

  return (
    <div className="training-page">
      <section className="training-knowledge-bar">
        <div className="training-knowledge-info">
          <span className="training-global-dot" />
          <div>
            <strong>GLOBAL KNOWLEDGE</strong>
            <span>
              {activeMappingCount} active mappings · Shared across all users
            </span>
          </div>
        </div>

        <button
          type="button"
          className="training-teach-button"
          onClick={() => setShowManualTrainingForm(true)}
        >
          <span>+</span>
          Teach Analyzer
        </button>
      </section>

      <section className="training-stat-grid">
        <div className="training-stat-card">
          <span className="training-stat-label">
            Pending Review
          </span>
          <strong className="training-stat-value">
            {trainingStats.pending}
          </strong>
          <span className="training-stat-description">
            Candidates awaiting human feedback
          </span>
        </div>

        <div className="training-stat-card">
          <span className="training-stat-label">
            Approved
          </span>
          <strong className="training-stat-value">
            {trainingStats.approved}
          </strong>
          <span className="training-stat-description">
            Human-approved training candidates
          </span>
        </div>

        <div className="training-stat-card">
          <span className="training-stat-label">
            Rejected
          </span>
          <strong className="training-stat-value">
            {trainingStats.rejected}
          </strong>
          <span className="training-stat-description">
            Candidates rejected during review
          </span>
        </div>

        <div className="training-stat-card training-stat-card-accent">
          <span className="training-stat-label">
            Active Knowledge
          </span>
          <strong className="training-stat-value">
            {activeMappingCount}
          </strong>
          <span className="training-stat-description">
            Global mappings currently used by the analyzer
          </span>
        </div>
      </section>

      {error && (
        <div className="training-error">
          {error}
        </div>
      )}

      <section className="training-panel">
        <div className="training-section-header">
          <div>
            <div className="training-section-kicker">
              HUMAN REVIEW
            </div>
            <h2>Training Queue</h2>
            <p>
              Review configuration syntax that the analyzer could
              not confidently classify.
            </p>
          </div>

          <button
            type="button"
            className="secondary-button"
            onClick={onRefresh}
            disabled={loading}
          >
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>

        {trainingCandidates.length > 0 && (
          <div className="training-bulk-toolbar">
            <label className="training-select-all">
              <input
                type="checkbox"
                checked={allCandidatesSelected}
                onChange={toggleSelectAll}
              />
              Select all
            </label>

            <div className="training-bulk-actions">
              <span className="training-selection-count">
                {selectedTrainingCandidateIds.length} selected
              </span>

              <button
                type="button"
                className="danger-button"
                disabled={
                  selectedTrainingCandidateIds.length === 0 ||
                  loading
                }
                onClick={onRejectSelected}
              >
                Reject Selected
              </button>
            </div>
          </div>
        )}

        {trainingCandidates.length === 0 ? (
          <div className="training-empty-state">
            <div className="training-empty-icon">✓</div>
            <strong>No pending AI training items</strong>
            <span>
              The analyzer currently has no uncertain configuration
              patterns waiting for review.
            </span>
          </div>
        ) : (
          <div className="training-candidate-list">
            {trainingCandidates.map((candidate, index) => {
              const confidence = Number(
                candidate.confidence || 0
              );

              return (
                <article
                  className="training-candidate-card"
                  key={candidate.id}
                >
                  <div className="training-candidate-top">
                    <label className="training-candidate-check">
                      <input
                        type="checkbox"
                        checked={selectedTrainingCandidateIds.includes(
                          candidate.id
                        )}
                        onChange={() =>
                          toggleCandidate(candidate.id)
                        }
                      />
                    </label>

                    <div className="training-candidate-title">
                      <span>
                        Candidate #{candidate.id}
                      </span>
                      <strong>
                        AI Candidate #{index + 1}
                      </strong>
                    </div>

                    <span
                      className={`training-confidence ${
                        confidence >= 0.8
                          ? "high"
                          : confidence >= 0.5
                            ? "medium"
                            : "low"
                      }`}
                    >
                      {Math.round(confidence * 100)}%
                    </span>
                  </div>

                  <div className="training-pattern">
                    {candidate.configuration_line}
                  </div>

                  <div className="training-candidate-grid">
                    <div>
                      <span>Suggested Category</span>
                      <strong>
                        {candidate.suggested_category || "—"}
                      </strong>
                    </div>

                    <div>
                      <span>Baseline Parameter</span>
                      <strong>
                        {candidate.suggested_baseline_parameter ||
                          "—"}
                      </strong>
                    </div>

                    <div>
                      <span>Expected Value</span>
                      <strong>
                        {String(
                          candidate.suggested_expected_value ?? "—"
                        )}
                      </strong>
                    </div>

                    <div>
                      <span>Source</span>
                      <strong>
                        {candidate.source || "AI Ingestion"}
                      </strong>
                    </div>
                  </div>

                  {candidate.evidence?.length > 0 && (
                    <div className="training-evidence">
                      <span>AI Evidence</span>
                      <ul>
                        {candidate.evidence.map(
                          (item, evidenceIndex) => (
                            <li key={evidenceIndex}>
                              {typeof item === "string"
                                ? item
                                : JSON.stringify(item)}
                            </li>
                          )
                        )}
                      </ul>
                    </div>
                  )}

                  <div className="training-candidate-actions">
                    <button
                      type="button"
                      className="primary-button"
                      onClick={() => onTeach(candidate)}
                      disabled={loading}
                    >
                      Teach This
                    </button>

                    <button
                      type="button"
                      className="danger-button"
                      onClick={() => onReject(candidate.id)}
                      disabled={loading}
                    >
                      Reject
                    </button>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>

      <section className="training-panel">
        <div className="training-section-header">
          <div>
            <div className="training-section-kicker">
              SHARED SEMANTIC KNOWLEDGE
            </div>
            <h2>Learned Mappings</h2>
            <p>
              Global mappings currently available to the analyzer.
              Click any mapping to inspect its meaning and impact.
            </p>
          </div>
        </div>

        <div className="training-mapping-toolbar">
          <div className="training-search">
            <span>⌕</span>
            <input
              type="search"
              value={mappingSearch}
              onChange={(event) =>
                setMappingSearch(event.target.value)
              }
              placeholder="Search configuration patterns or parameters..."
            />
          </div>

          <select
            value={mappingStatus}
            onChange={(event) =>
              setMappingStatus(event.target.value)
            }
          >
            <option value="ALL">All Status</option>
            <option value="ACTIVE">Active</option>
            <option value="INACTIVE">Inactive</option>
          </select>

          <select
            value={mappingCategory}
            onChange={(event) =>
              setMappingCategory(event.target.value)
            }
          >
            <option value="ALL">All Categories</option>
            {categories.map((category) => (
              <option value={category} key={category}>
                {category}
              </option>
            ))}
          </select>
        </div>

        {filteredMappings.length === 0 ? (
          <div className="training-empty-state compact">
            <strong>No mappings found</strong>
            <span>
              Try changing the search text or filters.
            </span>
          </div>
        ) : (
          <div className="training-mapping-list">
            {filteredMappings.map((mapping) => (
              <button
                type="button"
                className="training-mapping-row"
                key={mapping.id}
                onClick={() => setSelectedMapping(mapping)}
              >
                <div className="training-mapping-expand">
                  <span>›</span>
                </div>

                <div className="training-mapping-main">
                  <div className="training-mapping-heading">
                    <strong>
                      Mapping #{mapping.id}
                    </strong>

                    <span
                      className={
                        mapping.is_active
                          ? "mapping-status active"
                          : "mapping-status inactive"
                      }
                    >
                      {mapping.is_active
                        ? "ACTIVE"
                        : "INACTIVE"}
                    </span>
                  </div>

                  <div className="training-mapping-pattern">
                    {mapping.configuration_pattern}
                  </div>

                  <div className="training-mapping-meta">
                    <span>
                      {mapping.security_category}
                    </span>
                    <span>
                      {mapping.baseline_parameter}
                    </span>
                    <span>
                      Expected{" "}
                      {String(mapping.expected_value)}
                    </span>
                  </div>
                </div>

                <div className="training-mapping-confidence">
                  <span>Confidence</span>
                  <strong>
                    {Math.round(
                      Number(mapping.confidence || 0) * 100
                    )}
                    %
                  </strong>
                </div>

                <div
                  className="training-mapping-toggle"
                  onClick={(event) =>
                    event.stopPropagation()
                  }
                >
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() => onToggle(mapping)}
                  >
                    {mapping.is_active
                      ? "Deactivate"
                      : "Activate"}
                  </button>
                </div>
              </button>
            ))}
          </div>
        )}
      </section>

      {showManualTrainingForm && (
        <section className="training-panel training-teach-panel">
          <div className="training-section-header">
            <div>
              <div className="training-section-kicker">
                MANUAL KNOWLEDGE
              </div>
              <h2>Teach the Analyzer</h2>
              <p>
                Create a global semantic mapping when the analyzer
                needs explicit human guidance.
              </p>
            </div>

            <button
              type="button"
              className="secondary-button"
              onClick={() => setShowManualTrainingForm(false)}
            >
              Cancel
            </button>
          </div>

          <form
            onSubmit={onSubmit}
            className="training-form training-form-modern"
          >
            <label>
              Configuration Pattern

              <textarea
                value={form.configuration_pattern}
                onChange={(event) =>
                  setForm({
                    ...form,
                    configuration_pattern: event.target.value,
                  })
                }
                placeholder="Example: secure management access enabled"
                required
              />

              <small>
                Enter the configuration syntax or semantic pattern
                the analyzer should recognize.
              </small>
            </label>

            <label>
              Security Category

              <select
                value={form.security_category}
                onChange={(event) =>
                  setForm({
                    ...form,
                    security_category: event.target.value,
                    baseline_parameter: "",
                  })
                }
                required
              >
                <option value="">Select category</option>

                {categories.map((category) => (
                  <option value={category} key={category}>
                    {category}
                  </option>
                ))}
              </select>
            </label>

            <label>
              Baseline Parameter

              <select
                value={form.baseline_parameter}
                onChange={(event) =>
                  setForm({
                    ...form,
                    baseline_parameter: event.target.value,
                  })
                }
                required
              >
                <option value="">
                  Select baseline parameter
                </option>

                {(baselineParameters[form.security_category] || []).map(
                  (parameter) => (
                    <option value={parameter} key={parameter}>
                      {parameter}
                    </option>
                  )
                )}
              </select>
            </label>

            <label>
              Expected Value

              <select
                value={form.expected_value}
                onChange={(event) =>
                  setForm({
                    ...form,
                    expected_value: event.target.value,
                  })
                }
                required
              >
                <option value="" disabled>
                  Select expected value
                </option>

                <option value="True">True</option>
                <option value="False">False</option>
              </select>
            </label>

            <div className="training-form-footer">
              <span>
                New mappings become part of the shared AI knowledge
                base.
              </span>

              <button
                type="submit"
                className="primary-button"
                disabled={loading}
              >
                {loading
                  ? "Saving..."
                  : "Save Learned Mapping"}
              </button>
            </div>
          </form>
        </section>
      )}



      {selectedMapping && (
        <div
          className="training-modal-backdrop"
          onClick={() => setSelectedMapping(null)}
        >
          <div
            className="training-modal"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="training-modal-header">
              <div>
                <span className="training-section-kicker">
                  GLOBAL LEARNED MAPPING
                </span>
                <h2>
                  Mapping #{selectedMapping.id}
                </h2>
              </div>

              <button
                type="button"
                className="training-modal-close"
                onClick={() => setSelectedMapping(null)}
                aria-label="Close mapping details"
              >
                ×
              </button>
            </div>

            <div className="training-modal-status">
              <span
                className={
                  selectedMapping.is_active
                    ? "mapping-status active"
                    : "mapping-status inactive"
                }
              >
                {selectedMapping.is_active
                  ? "ACTIVE"
                  : "INACTIVE"}
              </span>

              <span className="training-modal-confidence">
                {Math.round(
                  Number(selectedMapping.confidence || 0) * 100
                )}
                % confidence
              </span>
            </div>

            <div className="training-detail-block">
              <span>Configuration Pattern</span>
              <strong>
                {selectedMapping.configuration_pattern}
              </strong>
            </div>

            <div className="training-detail-grid">
              <div className="training-detail-block">
                <span>Security Meaning</span>
                <strong>
                  {selectedMapping.security_category}
                </strong>
              </div>

              <div className="training-detail-block">
                <span>Baseline Parameter</span>
                <strong>
                  {selectedMapping.baseline_parameter}
                </strong>
              </div>

              <div className="training-detail-block">
                <span>Expected Value</span>
                <strong>
                  {String(selectedMapping.expected_value)}
                </strong>
              </div>

              <div className="training-detail-block">
                <span>Confidence</span>
                <strong>
                  {Math.round(
                    Number(selectedMapping.confidence || 0) * 100
                  )}
                  %
                </strong>
              </div>
            </div>

            <div className="training-detail-explanation">
              <strong>How the analyzer uses this</strong>
              <p>
                When configuration syntax matches this learned
                pattern, the analyzer can associate it with the
                selected vendor-neutral security baseline control.
              </p>
            </div>

            <div className="training-detail-warning">
              <strong>Global impact</strong>
              <p>
                This mapping is shared across the application.
                Activating, deactivating, or creating mappings can
                affect analysis performed for other users.
              </p>
            </div>

            <div className="training-modal-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() => setSelectedMapping(null)}
              >
                Close
              </button>

              <button
                type="button"
                className="primary-button"
                onClick={() => {
                  onToggle(selectedMapping);
                  setSelectedMapping(null);
                }}
              >
                {selectedMapping.is_active
                  ? "Deactivate Mapping"
                  : "Activate Mapping"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
function StatusCard({
  name,
  status,
  detail,
}) {
  const healthy = status === "healthy";

  return (
    <div className="status-card">
      <div className="status-header">
        <h2>{name}</h2>

        <span
          className={
            healthy
              ? "status healthy"
              : "status unhealthy"
          }
        >
          {healthy ? "ONLINE" : "OFFLINE"}
        </span>
      </div>

      <p>{detail}</p>
    </div>
  );
}

function ModuleCard({
  title,
  description,
  status,
}) {
  return (
    <div className="module-card">
      <div className="module-header">
        <h3>{title}</h3>

        <span className="module-status">
          {status}
        </span>
      </div>

      <p>{description}</p>
    </div>
  );
}

function ConfigurationAnalysisView({
  token,
  onLogout,
  onAnalysisComplete,
}) {
  const [configurations, setConfigurations] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [analysis, setAnalysis] = useState(null);
    const [remediationCreating, setRemediationCreating] =
    useState(null);

  const [remediationParameters, setRemediationParameters] =
    useState({});

  const [remediationError, setRemediationError] =
    useState(null);

  const [remediationMessage, setRemediationMessage] =
    useState(null);

  const [loading, setLoading] = useState(false);
  const [listLoading, setListLoading] = useState(true);
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(null);

  // Live scan state
  const [liveScanDeviceId, setLiveScanDeviceId] =
    useState("");

  const [liveScanDevices, setLiveScanDevices] =
    useState([]);

  const [liveScanUsername, setLiveScanUsername] =
    useState("");

  const [liveScanPassword, setLiveScanPassword] =
    useState("");

  const [showLiveScanPassword, setShowLiveScanPassword] =
  useState(false);

  const [liveScanPort, setLiveScanPort] =
    useState("22");

  const [liveScanFrameworks, setLiveScanFrameworks] =
    useState(FRAMEWORKS);

  const [liveScanLoading, setLiveScanLoading] =
    useState(false);

  const [liveScanResult, setLiveScanResult] =
    useState(null);

  useEffect(() => {
    loadConfigurations();
    loadLiveScanDevices();
  }, []);

  async function loadConfigurations() {
    if (!token) {
      return;
    }

    try {
      setListLoading(true);
      setError(null);

      const response = await axios.get(
        `${API_URL}/api/configurations`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      setConfigurations(
        response.data.configurations || []
      );
    } catch (err) {
      console.error(err);

      if (err.response?.status === 401) {
        onLogout();
        return;
      }

      setError(
        err.response?.data?.detail ||
          "Unable to load configurations."
      );
    } finally {
      setListLoading(false);
    }
  }

  async function loadLiveScanDevices() {
    if (!token) {
      return;
    }

    try {
      const response = await getDevices();

      const devices = normalizeArray(response, [
        "devices",
        "items",
      ]);

      setLiveScanDevices(devices);

      if (devices.length > 0) {
        setLiveScanDeviceId(String(devices[0].id));
      } else {
        setLiveScanDeviceId("");
      }
    } catch (err) {
      console.error(
        "Unable to load Live Scan devices:",
        err
      );

      if (err.response?.status === 401) {
        onLogout();
        return;
      }

      setLiveScanDevices([]);
      setLiveScanDeviceId("");
    }
  }

  async function uploadConfiguration(event) {
    event.preventDefault();

    if (!selectedFile) {
      setError("Please select a configuration file.");
      return;
    }

    try {
      setLoading(true);
      setError(null);
      setMessage(null);
      setAnalysis(null);

      const formData = new FormData();

      formData.append("file", selectedFile);

      await axios.post(
        `${API_URL}/api/configurations/upload`,
        formData,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      setMessage(
        "Configuration uploaded successfully."
      );

      setSelectedFile(null);

      event.target.reset();

      await loadConfigurations();
    } catch (err) {
      console.error(err);

      if (err.response?.status === 401) {
        onLogout();
        return;
      }

      setError(
        err.response?.data?.detail ||
          "Unable to upload configuration."
      );
    } finally {
      setLoading(false);
    }
  }

  async function analyzeConfiguration(
    configurationId
  ) {
    try {
      setLoading(true);
      setError(null);
      setMessage(null);
      setAnalysis(null);

      const response = await axios.post(
        `${API_URL}/api/configurations/${configurationId}/analyze`,
        null,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
          params: {
            frameworks: FRAMEWORKS,
          },
        }
      );

      setAnalysis(response.data);
      onAnalysisComplete(response.data);

      setMessage(
        "Configuration analysis completed."
      );

      await loadConfigurations();
    } catch (err) {
      console.error(err);

      if (err.response?.status === 401) {
        onLogout();
        return;
      }

      setError(
        err.response?.data?.detail ||
          "Unable to analyze configuration."
      );
    } finally {
      setLoading(false);
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

      const vendor =
        remediationObject?.vendor ||
        item?.vendor ||
        analysis?.device_intelligence?.vendor ||
        analysis?.vendor ||
        "Unknown";

      const commands =
        Array.isArray(
          remediationObject?.commands
        )
          ? remediationObject.commands
          : [];

      if (!ruleId) {
        throw new Error(
          "Remediation rule ID is missing."
        );
      }

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
          analysis?.configuration_id ?? null,

        device_id:
          analysis?.device_id ?? null,

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

      const response =
        await createRemediationRequest(
          payload
        );

      requestAnimationFrame(() => {
        document
          .getElementById("remediation-section")
          ?.scrollIntoView({
            behavior: "smooth",
            block: "start",
          });
      });

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

  async function runLiveScan(event) {
    event.preventDefault();

    if (!liveScanDeviceId) {
      setError("Please enter a device ID.");
      return;
    }

    if (
      !liveScanUsername ||
      !liveScanPassword
    ) {
      setError(
        "SSH username and password are required."
      );
      return;
    }

    if (liveScanFrameworks.length === 0) {
      setError(
        "Select at least one compliance framework."
      );
      return;
    }

    const port = Number(liveScanPort);

    if (
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65535
    ) {
      setError(
        "SSH port must be between 1 and 65535."
      );
      return;
    }

    try {
      setLiveScanLoading(true);
      setError(null);
      setMessage(null);
      setLiveScanResult(null);

      const response = await axios.post(
        `${API_URL}/api/devices/${liveScanDeviceId}/scan`,
        {
          username: liveScanUsername,
          password: liveScanPassword,
          port,
          frameworks: liveScanFrameworks,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      setLiveScanResult(response.data);

      if (response.data.status === "FAILED") {
        setError(
          response.data.error ||
            "Live device scan failed."
        );
      } else {
        setMessage(
          `Live scan completed successfully for ${
            response.data.hostname || "the device"
          }.`
        );
      }

      // Never keep the device password in frontend state
      setLiveScanPassword("");

      await loadConfigurations();
    } catch (err) {
      console.error(err);

      if (err.response?.status === 401) {
        onLogout();
        return;
      }

      setError(
        err.response?.data?.detail ||
          "Unable to complete the live device scan."
      );
    } finally {
      setLiveScanLoading(false);
    }
  }

  function toggleLiveFramework(framework) {
    setLiveScanFrameworks((current) =>
      current.includes(framework)
        ? current.filter(
            (item) => item !== framework
          )
        : [...current, framework]
    );
  }

  return (
    <section className="configuration-analysis">
      {error && (
        <div className="error">
          {error}
        </div>
      )}

      {message && (
        <div className="success-message">
          {message}
        </div>
      )}

      {remediationMessage && (
        <div className="success-message">
          {remediationMessage}
        </div>
      )}

      {remediationError && (
        <div className="error">
          {remediationError}
        </div>
      )}

      {/* =====================================================
          LIVE DEVICE SCAN
          ===================================================== */}

      <div className="analysis-upload-card">
        <div className="section-heading">
          <div>
            <h2>Live Device Scan</h2>

            <p>
              Connect directly to a network device over
              SSH, retrieve its running configuration and
              run the complete compliance analysis pipeline.
            </p>
          </div>
        </div>

        <form
          onSubmit={runLiveScan}
          className="training-form"
        >
          <div className="live-scan-grid">
            <label>
              Device

              <select
                value={liveScanDeviceId}
                onChange={(event) =>
                  setLiveScanDeviceId(event.target.value)
                }
                disabled={liveScanDevices.length === 0}
                required
              >
                <option value="">
                  {liveScanDevices.length === 0
                    ? "No devices registered"
                    : "Select a registered device"}
                </option>

                {liveScanDevices.map((device) => (
                  <option
                    key={device.id}
                    value={device.id}
                  >
                    {device.hostname ||
                      `Device #${device.id}`}
                    {" — "}
                    {device.vendor || "Unknown vendor"}
                    {" — "}
                    {device.management_ip}
                  </option>
                ))}
              </select>

              <small className="field-help">
                Select a device registered in your account.
              </small>
            </label>

            <label>
              SSH Port

              <input
                type="number"
                min="1"
                max="65535"
                value={liveScanPort}
                onChange={(event) =>
                  setLiveScanPort(
                    event.target.value
                  )
                }
                required
              />
            </label>

            <label>
              SSH Username

              <input
                type="text"
                value={liveScanUsername}
                onChange={(event) =>
                  setLiveScanUsername(
                    event.target.value
                  )
                }
                placeholder="SSH username"
                autoComplete="off"
                required
              />
            </label>

            <label>
              SSH Password

              <div className="password-input-wrapper">
                <input
                  type={showLiveScanPassword ? "text" : "password"}
                  value={liveScanPassword}
                  onChange={(event) =>
                    setLiveScanPassword(event.target.value)
                  }
                  autoComplete="off"
                  placeholder="Enter SSH password"
                  required
                />

                <button
                  type="button"
                  className="password-toggle-button"
                  onClick={() =>
                    setShowLiveScanPassword(
                      !showLiveScanPassword
                    )
                  }
                  aria-label={
                    showLiveScanPassword
                      ? "Hide SSH password"
                      : "Show SSH password"
                  }
                  title={
                    showLiveScanPassword
                      ? "Hide password"
                      : "Show password"
                  }
                >
                  {showLiveScanPassword ? "🙈" : "👁"}
                </button>
              </div>
            </label>
          </div>

          <div className="framework-selector">
            <div>
              <strong>
                Compliance Frameworks
              </strong>

              <p className="muted">
                Select the frameworks to evaluate during
                this live scan.
              </p>
            </div>

            <div className="framework-options">
              {FRAMEWORKS.map((framework) => (
                <label
                  className="framework-option"
                  key={framework}
                >
                  <input
                    type="checkbox"
                    checked={liveScanFrameworks.includes(
                      framework
                    )}
                    onChange={() =>
                      toggleLiveFramework(
                        framework
                      )
                    }
                  />

                  <span>
                    {formatFrameworkName(
                      framework
                    )}
                  </span>
                </label>
              ))}
            </div>
          </div>

          <div className="scan-actions">
            <button
              type="submit"
              className="primary-button"
              disabled={liveScanLoading}
            >
              {liveScanLoading
                ? "Scanning Device..."
                : "Start Live Scan"}
            </button>

            {liveScanLoading && (
              <span className="muted">
                Connecting â†’ Retrieving configuration â†’
                Analyzing â†’ Compliance â†’ Risk
              </span>
            )}
          </div>
        </form>
      </div>

      {liveScanResult && (
        <LiveScanResults
          result={liveScanResult}
        />
      )}

        {analysis && (
        <AnalysisResults
          analysis={analysis}
          remediationParameters={remediationParameters}
          setRemediationParameters={setRemediationParameters}
          remediationCreating={remediationCreating}
          createRemediation={createRemediation}
        />
      )}
    </section>
  );
}

function LiveScanResults({ result }) {
  const device =
    result.device_intelligence || {};

  const parser =
    result.parser || {};

  const baseline =
    result.security_baseline || {};

  const compliance =
    result.compliance || {};

  const risk =
    result.risk || {};

  const frameworkResults =
    result.framework_results || {};

  const remediation =
    result.remediation;

  const remediationItems = Array.isArray(
    remediation
  )
    ? remediation
    : remediation
      ? [remediation]
      : [];

  const compliancePercentage =
    Number(
      compliance.compliance_percentage || 0
    );

  const riskScore =
    Number(risk.risk_score || 0);

  return (
    <div className="analysis-results live-scan-results">
      <div className="section-heading">
        <div>
          <h2>Live Scan Results</h2>

          <p>
            Real-time analysis result for{" "}
            <strong>
              {result.hostname || device.hostname || "Device"}
            </strong>
          </p>
        </div>

        <span className="module-status">
          {result.status || "SUCCESS"}
        </span>
      </div>

      {/* Device Intelligence */}

      <div
        className="result-card-large"
        id="results-summary"
      >
        <h3>Device Intelligence</h3>

        <div className="result-grid">
          <ResultCard
            title="Hostname"
            value={
              result.hostname ||
              device.hostname ||
              "Unknown"
            }
          />

          <ResultCard
            title="Vendor"
            value={
              device.vendor || "Unknown"
            }
          />

          <ResultCard
            title="Product"
            value={
              device.product || "Unknown"
            }
          />

          <ResultCard
            title="Platform"
            value={
              device.platform || "Unknown"
            }
          />

          <ResultCard
            title="Model"
            value={
              device.model || "Unknown"
            }
          />

          <ResultCard
            title="Firmware"
            value={
              device.firmware || "Unknown"
            }
          />

          <ResultCard
            title="Device Type"
            value={
              device.device_type ||
              "Unknown"
            }
          />

          <ResultCard
            title="Serial Number"
            value={
              device.serial_number ||
              "Unknown"
            }
          />

          <ResultCard
            title="Confidence"
            value={`${(
              Number(device.confidence || 0) * 100
            ).toFixed(0)}%`}
          />
        </div>
      </div>

      {/* Parser */}

      <div className="result-card-large">
        <h3>Parser / AI Ingestion</h3>

        <div className="summary-grid">
          <div>
            <span>Parser</span>

            <strong>
              {parser.parser ||
                result.netmiko_device_type ||
                "Unknown"}
            </strong>
          </div>

          <div>
            <span>Status</span>

            <strong>
              {parser.status ||
                "PARSED"}
            </strong>
          </div>

          <div>
            <span>Vendor</span>

            <strong>
              {parser.vendor ||
                device.vendor ||
                "Unknown"}
            </strong>
          </div>

          <div>
            <span>Confidence</span>

            <strong>
              {(
                Number(
                  parser.confidence || 0
                ) * 100
              ).toFixed(0)}
              %
            </strong>
          </div>
        </div>
      </div>

      {/* Overall Compliance */}

      <div className="result-card-large">
        <h3>Overall Compliance</h3>

        <div className="result-grid">
          <ResultCard
            title="Compliance"
            value={`${compliancePercentage.toFixed(
              1
            )}%`}
          />

          <ResultCard
            title="Total Rules"
            value={
              compliance.total_rules || 0
            }
          />

          <ResultCard
            title="Passed"
            value={
              compliance.pass_count || 0
            }
          />

          <ResultCard
            title="Failed"
            value={
              compliance.fail_count || 0
            }
          />

          <ResultCard
            title="Not Applicable"
            value={
              compliance.na_count || 0
            }
          />
        </div>
      </div>

      {/* Framework Results */}

      <div className="result-card-large">
        <h3>Framework Compliance</h3>

        {Object.keys(frameworkResults).length ===
        0 ? (
          <p className="muted">
            No individual framework results returned.
          </p>
        ) : (
          <div className="framework-result-grid">
            {Object.entries(
              frameworkResults
            ).map(
              ([frameworkName, frameworkData]) => {
                const percentage = Number(
                  frameworkData?.compliance_percentage ||
                    0
                );

                return (
                  <div
                    className="framework-result-card"
                    key={frameworkName}
                  >
                    <div className="framework-result-header">
                      <h4>
                        {formatFrameworkName(
                          frameworkName
                        )}
                      </h4>

                      <strong>
                        {percentage.toFixed(1)}%
                      </strong>
                    </div>

                    <div className="summary-grid">
                      <div>
                        <span>Rules</span>

                        <strong>
                          {frameworkData?.total_rules ||
                            0}
                        </strong>
                      </div>

                      <div>
                        <span>Passed</span>

                        <strong>
                          {frameworkData?.pass_count ||
                            0}
                        </strong>
                      </div>

                      <div>
                        <span>Failed</span>

                        <strong>
                          {frameworkData?.fail_count ||
                            0}
                        </strong>
                      </div>

                      <div>
                        <span>N/A</span>

                        <strong>
                          {frameworkData?.na_count ||
                            0}
                        </strong>
                      </div>
                    </div>
                  </div>
                );
              }
            )}
          </div>
        )}
      </div>

      {/* Compliance Findings */}

      <div
        className="result-card-large"
        id="live-compliance-findings"
      >
        <h3>Compliance Findings</h3>

        {!Array.isArray(
          compliance.results
        ) ||
        compliance.results.length === 0 ? (
          <p className="muted">
            No compliance results returned.
          </p>
        ) : (
          <div className="finding-list">
            {compliance.results.map(
              (finding, index) => {
                const isFail =
                  finding.status === "FAIL";

                return (
                  <div
                    className={
                      isFail
                        ? "finding-item finding-fail"
                        : "finding-item"
                    }
                    key={
                      finding.rule_id ||
                      `live-finding-${index}`
                    }
                  >
                    <div>
                      <strong>
                        {finding.rule_id ||
                          "Control"}
                      </strong>

                      <p>
                        {finding.title ||
                          "Compliance control"}
                      </p>

                      {finding.evidence && (
                        <pre>
                          {String(
                            finding.evidence
                          )}
                        </pre>
                      )}
                    </div>

                    <div className="finding-meta">
                      <span>
                        {finding.severity ||
                          "UNKNOWN"}
                      </span>

                      <span>
                        {finding.status ||
                          "N/A"}
                      </span>

                      <span>
                        Confidence:{" "}
                        {Number(
                          finding.confidence ||
                            0
                        ).toFixed(2)}
                      </span>
                    </div>
                  </div>
                );
              }
            )}
          </div>
        )}
      </div>

      {/* Risk */}

      <div className="result-card-large">
        <h3>Risk Assessment</h3>

        <div className="result-grid">
          <ResultCard
            title="Risk Score"
            value={riskScore.toFixed(1)}
          />

          <ResultCard
            title="Risk Level"
            value={
              risk.risk_level ||
              "MINIMAL"
            }
          />

          <ResultCard
            title="Findings"
            value={
              risk.finding_count ||
              risk.findings?.length ||
              compliance.fail_count ||
              0
            }
          />

          <ResultCard
            title="Critical Findings"
            value={
              risk.critical_findings ||
              0
            }
          />
        </div>
      </div>

      {/* Baseline */}

      <div className="result-card-large">
        <h3>Security Baseline</h3>

        <div className="result-grid">
          <ResultCard
            title="Authentication"
            value={
              baseline.authentication
                ? "Analyzed"
                : "Available"
            }
          />

          <ResultCard
            title="Remote Access"
            value={
              baseline.remote_access
                ? "Analyzed"
                : "Available"
            }
          />

          <ResultCard
            title="Logging"
            value={
              baseline.logging
                ? "Analyzed"
                : "Available"
            }
          />

          <ResultCard
            title="Cryptography"
            value={
              baseline.crypto
                ? "Analyzed"
                : "Available"
            }
          />

          <ResultCard
            title="Access Control"
            value={
              baseline.access_control
                ? "Analyzed"
                : "Available"
            }
          />
        </div>
      </div>

      {/* Remediation */}

      <div
        className="result-card-large"
        id="live-remediation-section"
      >
        <h3>
          Remediation Recommendations
        </h3>

        {remediationItems.length === 0 ? (
          <p className="muted">
            No remediation recommendations.
          </p>
        ) : (
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

                return (
                  <div
                    className="finding-item"
                    key={
                      item?.rule_id ||
                      remediationObject?.rule_id ||
                      `live-remediation-${index}`
                    }
                  >
                    <div>
                      <strong>
                        {item?.rule_id ||
                          remediationObject?.rule_id ||
                          "Remediation"}
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

                          {(() => {
                            const ruleId =
                              item?.rule_id ||
                              remediationObject?.rule_id ||
                              "";

                            const placeholders = [
                              ...new Set(
                                commands.flatMap((command) =>
                                  (command.match(/<([^>]+)>/g) || [])
                                    .map((value) =>
                                      value.slice(1, -1)
                                    )
                                )
                              ),
                            ];

                            return (
                              <div className="remediation-create-panel">
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
                              </div>
                            );
                          })()}
                        </>
                      ) : (
                        <p className="muted">
                          Remediation details were
                          returned without CLI
                          commands.
                        </p>
                      )}

                      {remediationObject?.status && (
                        <div className="finding-meta">
                          <span>
                            Status:{" "}
                            {
                              remediationObject.status
                            }
                          </span>

                          {remediationObject.approval_required !==
                            undefined && (
                            <span>
                              Approval Required:{" "}
                              {remediationObject.approval_required
                                ? "YES"
                                : "NO"}
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              }
            )}
          </div>
        )}
      </div>

      {/* Scan Metadata */}

      <div
        className="result-card-large"
        id="scan-information"
      >
        <h3>Scan Information</h3>

        <div className="summary-grid">
          <div>
            <span>Device ID</span>

            <strong>
              {result.device_id || "Unknown"}
            </strong>
          </div>

          <div>
            <span>Configuration ID</span>

            <strong>
              {result.configuration_id ||
                "Unknown"}
            </strong>
          </div>

          <div>
            <span>Configuration Size</span>

            <strong>
              {result.configuration_size
                ? `${result.configuration_size} bytes`
                : "Unknown"}
            </strong>
          </div>

          <div>
            <span>Netmiko Driver</span>

            <strong>
              {result.netmiko_device_type ||
                "Unknown"}
            </strong>
          </div>

          <div>
            <span>Selected Frameworks</span>

            <strong>
              {Array.isArray(
                result.selected_frameworks
              )
                ? result.selected_frameworks
                    .map(
                      formatFrameworkName
                    )
                    .join(", ")
                : "Unknown"}
            </strong>
          </div>
        </div>
      </div>
    </div>
  );
}

function AnalysisResults({
  analysis,
  remediationParameters,
  setRemediationParameters,
  remediationCreating,
  createRemediation,
}) {
  const device =
    analysis.device_intelligence || {};

  const compliance =
    analysis.compliance || {};

  const risk =
    analysis.risk || {};

  const remediation =
    analysis.remediation;

  const remediationItems =
    Array.isArray(remediation)
      ? remediation
      : Array.isArray(remediation?.remediations)
        ? remediation.remediations
        : remediation
          ? [remediation]
          : [];

  return (
  <div className="analysis-results">
    <nav
      className="results-navigation"
      aria-label="Analysis sections"
    >
      <a href="#file-results-summary">Overview</a>
      <a href="#file-compliance-findings">Compliance</a>
      <a href="#file-remediation-section">Remediation</a>
    </nav>

    <div
      className="section-heading"
      id="file-results-summary"
    >
      <div>
        <h2>Analysis Results</h2>
        <p>{analysis.filename}</p>
      </div>
    </div>

    <div className="result-grid">
        <ResultCard
          title="Vendor"
          value={
            device.vendor || "Unknown"
          }
        />

        <ResultCard
          title="Platform"
          value={
            device.platform || "Unknown"
          }
        />

        <ResultCard
          title="Model"
          value={
            device.model || "Unknown"
          }
        />

        <ResultCard
          title="Device Type"
          value={
            device.device_type || "Unknown"
          }
        />

        <ResultCard
          title="Firmware"
          value={
            device.firmware || "Unknown"
          }
        />

        <ResultCard
          title="Compliance"
          value={`${Number(
            compliance.compliance_percentage || 0
          ).toFixed(1)}%`}
        />

        <ResultCard
          title="Risk Score"
          value={Number(
            risk.risk_score || 0
          ).toFixed(1)}
        />

        <ResultCard
          title="Risk Level"
          value={
            risk.risk_level || "MINIMAL"
          }
        />
      </div>

      <div
        className="result-card-large"
        id="file-compliance-findings"
      >
        <h3>Compliance Findings</h3>

        <div className="summary-grid">
          <div>
            <span>Total Rules</span>

            <strong>
              {compliance.total_rules || 0}
            </strong>
          </div>

          <div>
            <span>Passed</span>

            <strong>
              {compliance.pass_count || 0}
            </strong>
          </div>

          <div>
            <span>Failed</span>

            <strong>
              {compliance.fail_count || 0}
            </strong>
          </div>

          <div>
            <span>Not Applicable</span>

            <strong>
              {compliance.na_count || 0}
            </strong>
          </div>
        </div>
      </div>

      <div className="result-card-large">
        <h3>Compliance Findings</h3>

        {!Array.isArray(
          compliance.results
        ) ||
        compliance.results.length === 0 ? (
          <p className="muted">
            No compliance results returned.
          </p>
        ) : (
          <div className="finding-list">
            {compliance.results.map(
              (finding, index) => (
                <div
                  className="finding-item"
                  key={
                    finding.rule_id ||
                    `finding-${index}`
                  }
                >
                  <div>
                    <strong>
                      {finding.rule_id}
                    </strong>

                    <p>
                      {finding.title}
                    </p>

                    {finding.evidence && (
                      <pre>
                        {String(
                          finding.evidence
                        )}
                      </pre>
                    )}
                  </div>

                  <div className="finding-meta">
                    <span>
                      {finding.severity}
                    </span>

                    <span>
                      {finding.status}
                    </span>

                    <span>
                      Confidence:{" "}
                      {Number(
                        finding.confidence || 0
                      ).toFixed(2)}
                    </span>
                  </div>
                </div>
              )
            )}
          </div>
        )}
      </div>

      <div
        className="result-card-large"
        id="file-remediation-section"
      >
        <h3>Remediation Recommendations</h3>

        {remediationItems.length === 0 ? (
          <p className="muted">
            No remediation recommendations.
          </p>
        ) : (
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

                return (
                  <div
                    className="finding-item"
                    key={
                      item?.rule_id ||
                      remediationObject?.rule_id ||
                      `remediation-${index}`
                    }
                  >
                    <div>
                      <strong>
                        {item?.rule_id ||
                          remediationObject?.rule_id ||
                          "Remediation"}
                      </strong>

                      {remediationObject?.vendor && (
                        <p>
                          Vendor:{" "}
                          {
                            remediationObject.vendor
                          }
                        </p>
                      )}

                      {item?.description && (
                        <p>
                          {item.description}
                        </p>
                      )}

                      {item?.title && (
                        <p>
                          {item.title}
                        </p>
                      )}

                      {commands.length > 0 ? (
                        <>
                          <pre>
                            {commands.join("\n")}
                          </pre>

                          {(() => {
                            const ruleId =
                              item?.rule_id ||
                              remediationObject?.rule_id ||
                              "";

                            const placeholders = [
                              ...new Set(
                                commands.flatMap((command) =>
                                  (command.match(/<([^>]+)>/g) || [])
                                    .map((value) =>
                                      value.slice(1, -1)
                                    )
                                )
                              ),
                            ];

                            return (
                              <div className="remediation-create-panel">
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
                              </div>
                            );
                          })()}
                        </>
                      ) : (
                        <p className="muted">
                          Remediation details were
                          returned without CLI
                          commands.
                        </p>
                      )}
                    </div>
                  </div>
                );
              }
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ResultCard({
  title,
  value,
}) {
  return (
    <div className="result-card">
      <span>{title}</span>

      <strong>{value}</strong>
    </div>
  );
}


function ModulePlaceholder({ view }) {
  const modules = {
    devices: {
      title: "Devices",
      description:
        "Centralized inventory and security posture for monitored network devices.",
    },
    configurations: {
      title: "Configurations",
      description:
        "Browse configuration snapshots, analysis history and device configuration state.",
    },
    compliance: {
      title: "Compliance",
      description:
        "Review CIS, NIST, DISA STIG and ISO/IEC 27001 compliance results.",
    },
    "live-scan": {
      title: "Live Scan",
      description:
        "Run authenticated SSH scans against registered network devices.",
    },
    remediation: {
      title: "Remediation",
      description:
        "Review security findings, remediation commands, approvals and verification.",
    },
    audit: {
      title: "Audit Trail",
      description:
        "Review security operations and user activity recorded by NetSecure Analyzer.",
    },
    reports: {
      title: "Reports",
      description:
        "Generate and review security compliance reports.",
    },
  };

  const module = modules[view] || {
    title: "Module",
    description: "This module is being prepared.",
  };

  return (
    <section className="module-placeholder">
      <div className="placeholder-icon">â—ˆ</div>

      <span className="eyebrow">
        NETSECURE ANALYZER
      </span>

      <h2>{module.title}</h2>

      <p>{module.description}</p>

      <span className="placeholder-status">
        Module integration in progress
      </span>
    </section>
  );
}

export default App;
