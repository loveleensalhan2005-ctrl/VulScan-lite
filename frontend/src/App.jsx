import { useEffect, useState } from "react";
import "./App.css";

const API_URL = "https://vulscan-lite-a66m.onrender.com";

function App() {
  // =========================================================
  // LOGIN STATES
  // =========================================================

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loggedIn, setLoggedIn] = useState(false);
  const [loginError, setLoginError] = useState("");

  // =========================================================
  // SCANNER STATES
  // =========================================================

  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [taskId, setTaskId] = useState("");

  // =========================================================
  // HISTORY
  // =========================================================

  const [history, setHistory] = useState([]);
  const [showHistory, setShowHistory] = useState(false);

  // =========================================================
  // CHECK LOGIN
  // =========================================================

  useEffect(() => {
    checkLogin();
  }, []);

  async function checkLogin() {
    try {
      const response = await fetch(`${API_URL}/api/me`, {
        credentials: "include",
      });

      const data = await response.json();

      if (data.logged_in) {
        setLoggedIn(true);
        setUsername(data.username);
      } else {
        setLoggedIn(false);
      }
    } catch (err) {
      setLoggedIn(false);
    }
  }

  // =========================================================
  // LOGIN
  // =========================================================

  async function handleLogin(e) {
    e.preventDefault();

    setLoginError("");

    try {
      const response = await fetch(`${API_URL}/api/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({
          username,
          password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setLoginError(
          data.error || "Invalid username or password."
        );
        return;
      }

      setLoggedIn(true);
      setUsername(data.username || username);
      setPassword("");
    } catch (err) {
      setLoginError(
        "Unable to connect to the scanner server."
      );
    }
  }

  // =========================================================
  // LOGOUT
  // =========================================================

  async function handleLogout() {
    try {
      await fetch(`${API_URL}/api/logout`, {
        method: "POST",
        credentials: "include",
      });
    } catch (err) {
      // Ignore logout error
    }

    setLoggedIn(false);
    setResult(null);
    setUrl("");
    setHistory([]);
    setShowHistory(false);
  }

  // =========================================================
  // LOAD HISTORY
  // =========================================================

  async function loadHistory() {
    try {
      const response = await fetch(`${API_URL}/api/history`, {
        credentials: "include",
      });

      const data = await response.json();

      if (response.ok) {
        setHistory(data.history || []);
        setShowHistory(true);
      } else {
        setError(
          data.error || "Unable to load scan history."
        );
      }
    } catch (err) {
      setError("Unable to load scan history.");
    }
  }

  // =========================================================
  // START SCAN
  // =========================================================

  async function startScan(e) {
    e.preventDefault();

    setError("");
    setStatus("");
    setResult(null);
    setScanning(true);

    if (!url.trim()) {
      setError("Please enter a website URL.");
      setScanning(false);
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({
          url: url.trim(),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || "Unable to start scan.");
        setScanning(false);
        return;
      }

      const newTaskId = data.task_id;

      if (!newTaskId) {
        setError("Server did not return a scan task ID.");
        setScanning(false);
        return;
      }

      setTaskId(newTaskId);
      setStatus("Scan started. Analysing website...");

      pollScanStatus(newTaskId);
    } catch (err) {
      setError(
        "Unable to connect to the scanner server."
      );
      setScanning(false);
    }
  }

  // =========================================================
  // POLL SCAN STATUS
  // =========================================================

  async function pollScanStatus(id) {
    let attempts = 0;

    const maxAttempts = 120;

    const poll = async () => {
      attempts++;

      try {
        const response = await fetch(
          `${API_URL}/api/scan/${id}/status`,
          {
            credentials: "include",
          }
        );

        const data = await response.json();

        const currentStatus =
          String(data.status || "").toLowerCase();

        // -----------------------------------------------------
        // SUCCESS / COMPLETED
        // -----------------------------------------------------

        if (
          currentStatus === "success" ||
          currentStatus === "completed"
        ) {
          if (data.result) {
            setResult(data.result);
            setStatus("Scan completed successfully.");
            setScanning(false);

            loadHistory();

            return;
          }

          setError(
            "Scan completed, but no result was returned."
          );
          setStatus("");
          setScanning(false);
          return;
        }

        // -----------------------------------------------------
        // FAILURE
        // -----------------------------------------------------

        if (
          currentStatus === "failure" ||
          currentStatus === "failed"
        ) {
          setError(data.error || "Scan failed.");
          setStatus("");
          setScanning(false);
          return;
        }

        // -----------------------------------------------------
        // TIMEOUT
        // -----------------------------------------------------

        if (attempts >= maxAttempts) {
          setError(
            "Scan is taking too long. Please try again."
          );
          setStatus("");
          setScanning(false);
          return;
        }

        // -----------------------------------------------------
        // STILL RUNNING
        // -----------------------------------------------------

        setStatus(
          "Scan in progress... Please wait."
        );

        setTimeout(poll, 1000);
      } catch (err) {
        setError(
          "Unable to get scan status from server."
        );
        setScanning(false);
      }
    };

    poll();
  }

  // =========================================================
  // DOWNLOAD PDF
  // =========================================================

  async function downloadPDF(id = taskId) {
    if (!id) {
      setError("No scan report is available.");
      return;
    }

    try {
      const response = await fetch(
        `${API_URL}/api/scan/${id}/report`,
        {
          credentials: "include",
        }
      );

      if (!response.ok) {
        setError("Unable to generate PDF report.");
        return;
      }

      const blob = await response.blob();

      const downloadUrl =
        window.URL.createObjectURL(blob);

      const link = document.createElement("a");

      link.href = downloadUrl;
      link.download = "VulScan-Lite-Report.pdf";

      document.body.appendChild(link);
      link.click();
      link.remove();

      window.URL.revokeObjectURL(downloadUrl);
    } catch (err) {
      setError(
        "Unable to download PDF report."
      );
    }
  }

  // =========================================================
  // LOGIN PAGE
  // =========================================================

  if (!loggedIn) {
    return (
      <div className="login-page">

        <div className="login-card">

          <div className="login-logo">
            🛡️
          </div>

          <h1>
            VulScan-Lite
          </h1>

          <p className="login-subtitle">
            On-Demand Web Vulnerability Scanner
          </p>

          <form onSubmit={handleLogin}>

            <label>
              Username
            </label>

            <input
              type="text"
              value={username}
              onChange={(e) =>
                setUsername(e.target.value)
              }
              placeholder="Enter username"
              required
            />

            <label>
              Password
            </label>

            <input
              type="password"
              value={password}
              onChange={(e) =>
                setPassword(e.target.value)
              }
              placeholder="Enter password"
              required
            />

            {loginError && (
              <div className="error-box">
                {loginError}
              </div>
            )}

            <button
              type="submit"
              className="login-button"
            >
              Login
            </button>

          </form>

          <div className="demo-login">
            <strong>Demo Login</strong>
            <br />
            Username: student
            <br />
            Password: vulscan123
          </div>

          <p className="login-disclaimer">
            Only scan websites you own.
            This tool performs passive analysis only.
          </p>

        </div>

      </div>
    );
  }

  // =========================================================
  // MAIN DASHBOARD
  // =========================================================

  return (
    <div className="app">

      {/* HEADER */}

      <header className="header">

        <div className="brand">

          <div className="brand-icon">
            🛡️
          </div>

          <div>
            <h1>
              VulScan-Lite
            </h1>

            <p>
              Passive Web Vulnerability Scanner
            </p>
          </div>

        </div>

        <div className="user-section">

          <span>
            Welcome, <strong>{username}</strong>
          </span>

          <button
            className="logout-button"
            onClick={handleLogout}
          >
            Logout
          </button>

        </div>

      </header>

      {/* MAIN */}

      <main className="container">

        {/* HERO */}

        <section className="hero">

          <h2>
            Website Security Scanner
          </h2>

          <p>
            Perform a passive security assessment
            of an authorized website.
          </p>

        </section>

        {/* SCAN FORM */}

        <div className="scan-panel">

          <form
            className="scan-form"
            onSubmit={startScan}
          >

            <input
              type="text"
              value={url}
              onChange={(e) =>
                setUrl(e.target.value)
              }
              placeholder="Enter website URL e.g. https://example.com"
              disabled={scanning}
            />

            <button
              type="submit"
              disabled={scanning}
            >
              {scanning
                ? "Scanning..."
                : "Start Scan"}
            </button>

          </form>

          <div className="scan-note">
            Only scan websites you own or are
            authorized to test.
          </div>

        </div>

        {/* STATUS */}

        {status && (
          <div className="status-box">
            {status}
          </div>
        )}

        {/* ERROR */}

        {error && (
          <div className="error-box">
            {error}
          </div>
        )}

        {/* HISTORY CONTROLS */}

        <div className="history-controls">

          <button
            className="secondary-button"
            onClick={() =>
              showHistory
                ? setShowHistory(false)
                : loadHistory()
            }
          >
            {showHistory
              ? "Hide Scan History"
              : "View Scan History"}
          </button>

          {showHistory && (
            <button
              className="secondary-button"
              onClick={loadHistory}
            >
              Refresh History
            </button>
          )}

        </div>

        {/* HISTORY */}

        {showHistory && (
          <section className="panel history-panel">

            <h3>
              Scan History
            </h3>

            {history.length === 0 ? (
              <p className="empty">
                No scan history available.
              </p>
            ) : (
              <div className="table-wrapper">

                <table>

                  <thead>
                    <tr>
                      <th>Website</th>
                      <th>Score</th>
                      <th>Grade</th>
                      <th>HTTP</th>
                      <th>Date</th>
                      <th>Report</th>
                    </tr>
                  </thead>

                  <tbody>

                    {history.map((item, index) => (

                      <tr key={index}>

                        <td>
                          {item.url}
                        </td>

                        <td>
                          <strong>
                            {item.score}
                          </strong>
                        </td>

                        <td>
                          <span className="grade-badge">
                            {item.grade}
                          </span>
                        </td>

                        <td>
                          {item.status_code}
                        </td>

                        <td>
                          {item.created_at}
                        </td>

                        <td>

                          <button
                            className="small-button"
                            onClick={() =>
                              downloadPDF(
                                item.task_id
                              )
                            }
                          >
                            PDF
                          </button>

                        </td>

                      </tr>

                    ))}

                  </tbody>

                </table>

              </div>
            )}

          </section>
        )}

        {/* RESULTS */}

        {result && (

          <div className="results">

            {/* WEBSITE INFORMATION */}

            <section className="panel">

              <h3>
                Website Information
              </h3>

              <div className="info-grid">

                <div className="info-card">

                  <span className="label">
                    URL
                  </span>

                  <strong>
                    {result.url}
                  </strong>

                </div>

                <div className="info-card">

                  <span className="label">
                    HTTP Status
                  </span>

                  <strong>
                    {result.status_code}
                  </strong>

                </div>

                <div className="info-card">

                  <span className="label">
                    Response Time
                  </span>

                  <strong>
                    {result.response_time}s
                  </strong>

                </div>

                <div className="info-card">

                  <span className="label">
                    Server
                  </span>

                  <strong>
                    {result.server || "N/A"}
                  </strong>

                </div>

              </div>

            </section>

            {/* SECURITY SCORE */}

            <section className="panel">

              <h3>
                Security Score
              </h3>

              <div className="gauge-container">

                <div
                  className="gauge"
                  style={{
                    "--score":
                      `${
                        (Number(
                          result.security_score
                        ) || 0) * 1.8
                      }deg`,
                  }}
                >

                  <div className="gauge-inner">

                    <div className="gauge-number">
                      {result.security_score}
                    </div>

                    <div className="gauge-label">
                      / 100
                    </div>

                  </div>

                </div>

                <div className="gauge-grade">
                  Grade:{" "}
                  <strong>
                    {result.security_grade}
                  </strong>
                </div>

              </div>

              <div className="info-row">

                <span className="label">
                  SSL / TLS
                </span>

                <span
                  className={
                    result.summary?.ssl_tls ===
                    "PASS"
                      ? "pass"
                      : "fail"
                  }
                >
                  {result.summary?.ssl_tls ||
                    "N/A"}
                </span>

              </div>

              <div className="info-row">

                <span className="label">
                  DNS / IP
                </span>

                <span
                  className={
                    result.summary?.dns_ip ===
                    "PASS"
                      ? "pass"
                      : "fail"
                  }
                >
                  {result.summary?.dns_ip ||
                    "N/A"}
                </span>

              </div>

              <div className="info-row">

                <span className="label">
                  Scan Status
                </span>

                <span className="pass">
                  {result.summary?.scan_status ||
                    "Completed"}
                </span>

              </div>

            </section>

            {/* SECURITY HEADERS */}

            <section className="panel">

              <h3>
                Security Headers
              </h3>

              <div className="security-list">

                {[
                  [
                    "Content-Security-Policy",
                    result.security_headers?.[
                      "Content-Security-Policy"
                    ],
                  ],
                  [
                    "X-Frame-Options",
                    result.security_headers?.[
                      "X-Frame-Options"
                    ],
                  ],
                  [
                    "Strict-Transport-Security",
                    result.security_headers?.[
                      "Strict-Transport-Security"
                    ],
                  ],
                ].map(([name, header]) => {

                  const present =
                    typeof header === "object"
                      ? Boolean(header?.present)
                      : Boolean(header);

                  const value =
                    typeof header === "object"
                      ? header?.value
                      : header;

                  return (
                    <div
                      className="security-item"
                      key={name}
                    >

                      <div>

                        <strong>
                          {name}
                        </strong>

                        <p>
                          {value ||
                            "Header missing"}
                        </p>

                      </div>

                      <span
                        className={
                          present
                            ? "pass"
                            : "fail"
                        }
                      >
                        {present
                          ? "PASS"
                          : "FAIL"}
                      </span>

                    </div>
                  );

                })}

              </div>

            </section>

            {/* HOW TO FIX */}

            <section className="panel">

              <h3>
                How to Fix
              </h3>

              <div className="fix-list">

                {Array.isArray(
                  result.remediation
                ) &&
                result.remediation.length > 0 ? (

                  result.remediation.map(
                    (item, index) => (

                      <div
                        className="fix-item"
                        key={index}
                      >

                        <span className="fix-number">
                          {index + 1}
                        </span>

                        <p>
                          {typeof item === "object"
                            ? item?.value ||
                              item?.message ||
                              item?.fix ||
                              JSON.stringify(item)
                            : item}
                        </p>

                      </div>

                    )
                  )

                ) : (

                  <p>
                    No remediation guidance
                    available.
                  </p>

                )}

              </div>

            </section>

            {/* DNS / IP */}

            <section className="panel">

              <h3>
                DNS / IP Information
              </h3>

              <div className="info-grid">

                <div className="info-card">

                  <span className="label">
                    Hostname
                  </span>

                  <strong>
                    {result.hostname ||
                      "N/A"}
                  </strong>

                </div>

                <div className="info-card">

                  <span className="label">
                    IP Address
                  </span>

                  <strong>
                    {result.ip_address ||
                      "N/A"}
                  </strong>

                </div>

                <div className="info-card">

                  <span className="label">
                    DNS Status
                  </span>

                  <strong
                    className={
                      result.summary?.dns_ip ===
                      "PASS"
                        ? "pass"
                        : "fail"
                    }
                  >
                    {result.summary?.dns_ip ||
                      "N/A"}
                  </strong>

                </div>

              </div>

            </section>

            {/* SSL / TLS */}

            <section className="panel">

              <h3>
                SSL / TLS Information
              </h3>

              {result.ssl_tls ? (

                <div className="info-grid">

                  <div className="info-card">

                    <span className="label">
                      Issuer
                    </span>

                    <strong>
                      {typeof result.ssl_tls.issuer ===
                      "object"
                        ? JSON.stringify(
                            result.ssl_tls.issuer
                          )
                        : result.ssl_tls.issuer ||
                          "N/A"}
                    </strong>

                  </div>

                  <div className="info-card">

                    <span className="label">
                      Valid From
                    </span>

                    <strong>
                      {result.ssl_tls.valid_from ||
                        "N/A"}
                    </strong>

                  </div>

                  <div className="info-card">

                    <span className="label">
                      Valid Until
                    </span>

                    <strong>
                      {result.ssl_tls.valid_until ||
                        "N/A"}
                    </strong>

                  </div>

                  <div className="info-card">

                    <span className="label">
                      Cipher
                    </span>

                    <strong>
                      {typeof result.ssl_tls.cipher ===
                      "object"
                        ? JSON.stringify(
                            result.ssl_tls.cipher
                          )
                        : result.ssl_tls.cipher ||
                          "N/A"}
                    </strong>

                  </div>

                </div>

              ) : (

                <p>
                  SSL/TLS information unavailable.
                </p>

              )}

            </section>

            {/* REDIRECT ANALYSIS */}

            <section className="panel">

              <h3>
                Redirect Analysis
              </h3>

              <div className="info-grid">

                <div className="info-card">

                  <span className="label">
                    Redirect Count
                  </span>

                  <strong>
                    {result.redirect_count ??
                      "N/A"}
                  </strong>

                </div>

                <div className="info-card">

                  <span className="label">
                    Final URL
                  </span>

                  <strong>
                    {result.final_url ||
                      "N/A"}
                  </strong>

                </div>

              </div>

            </section>

            {/* COOKIE SECURITY */}

            <section className="panel">

              <h3>
                Cookie Security
              </h3>

              <div className="info-grid">

                <div className="info-card">

                  <span className="label">
                    Secure Cookie
                  </span>

                  <strong
                    className={
                      result.cookie_security?.secure
                        ? "pass"
                        : "fail"
                    }
                  >
                    {result.cookie_security?.secure
                      ? "PASS"
                      : "FAIL"}
                  </strong>

                </div>

                <div className="info-card">

                  <span className="label">
                    HttpOnly
                  </span>

                  <strong
                    className={
                      result.cookie_security?.httponly
                        ? "pass"
                        : "fail"
                    }
                  >
                    {result.cookie_security?.httponly
                      ? "PASS"
                      : "FAIL"}
                  </strong>

                </div>

              </div>

            </section>

            {/* PDF REPORT */}

            <section className="report-section">

              <button
                className="download-button"
                onClick={() =>
                  downloadPDF()
                }
              >
                Download PDF Report
              </button>

            </section>

          </div>

        )}

        {/* DISCLAIMER */}

        <footer className="footer">

          <strong>
            Security Disclaimer
          </strong>

          <p>
            Only scan websites you own or have
            explicit permission to test.
            VulScan-Lite performs passive
            security analysis only.
          </p>

        </footer>

      </main>

    </div>
  );
}

export default App;