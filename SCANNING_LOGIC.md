# VulScan-Lite – Scanning Logic Documentation

## 1. Overview

VulScan-Lite is a passive web vulnerability scanner designed for defensive security assessment and educational use.

The scanner analyzes publicly available HTTP/HTTPS response information without attempting to exploit vulnerabilities.

> **Disclaimer:** Only scan websites you own. This tool performs passive analysis only.

---

## 2. Security Header Analysis

VulScan-Lite checks important HTTP security headers to identify missing security protections.

### 2.1 Content-Security-Policy (CSP)

CSP helps control which resources a website is allowed to load.

- Present → PASS
- Missing → FAIL
- Missing CSP is reported as a security issue.
- The report provides remediation guidance.

### 2.2 X-Frame-Options

X-Frame-Options helps protect a website from clickjacking attacks.

- Present → PASS
- Missing → FAIL
- A remediation recommendation is displayed when missing.

### 2.3 Strict-Transport-Security (HSTS)

HSTS instructs browsers to use HTTPS for secure communication.

- Present → PASS
- Missing → FAIL
- Missing HSTS is reported with remediation guidance.

---

## 3. Security Score Calculation

The scanner starts with a base security score of 50.

For each checked security header:

- Header present → +10 points
- Header missing → -10 points

The final score is limited between 0 and 100.

### Grade Classification

| Score | Grade |
|------:|:-----:|
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 60–69 | D |
| Below 60 | F |

The score provides a simple overview of the website's security-header configuration.

---

## 4. SSL/TLS Analysis

For HTTPS websites, VulScan-Lite checks SSL/TLS connection information.

The scanner collects:

- Certificate issuer
- Certificate validity start date
- Certificate validity end date
- TLS cipher information

This information helps identify basic SSL/TLS configuration details.

---

## 5. CMS Detection

The scanner performs passive CMS detection.

It checks:

- HTML meta generator information
- Common CMS names in the response
- X-Powered-By response information

The scanner can identify technologies such as:

- WordPress
- Joomla
- Drupal

CMS detection is informational and does not attempt exploitation.

---

## 6. DNS and IP Detection

The scanner extracts the hostname from the supplied URL and performs DNS resolution.

It records:

- Hostname
- Resolved IP address
- DNS/IP status

This information helps identify the server associated with the scanned hostname.

---

## 7. HTTP Response Analysis

The scanner records basic HTTP information including:

- HTTP status code
- Response time
- Server information
- Final URL
- Redirect information
- Allowed HTTP methods

This provides additional information about the website's HTTP configuration.

---

## 8. Cookie Security Analysis

The scanner checks available cookie security attributes.

It can identify whether cookies use security-related properties such as:

- Secure
- HttpOnly

This provides a basic indication of cookie security configuration.

---

## 9. Remediation / How to Fix

When a security header is missing, VulScan-Lite generates remediation guidance.

The remediation section provides:

- Security issue
- Severity
- Explanation
- Recommended fix

This helps users understand how the identified configuration issue can be addressed.

---

## 10. Asynchronous Scanning

VulScan-Lite uses Celery with Redis-compatible message brokering for asynchronous scanning.

The workflow is:

1. User submits a URL.
2. Flask API validates the request.
3. A Celery task is created.
4. The worker performs the scan.
5. The frontend polls the scan status.
6. The completed result is displayed.
7. The result is stored in scan history.
8. A PDF security report can be generated.

---

## 11. Rate Limiting

VulScan-Lite includes a simple rate-limiting mechanism.

Each logged-in user can start a maximum of:

**5 scans within a rolling 60-second window.**

If the limit is exceeded, the API returns HTTP status:

**429 – Too Many Requests**

The user is asked to wait before starting another scan.

---

## 12. Scan History

Completed scans are stored in a local SQLite database.

The history records:

- Website URL
- Security score
- Security grade
- HTTP status code
- Scan date/time
- Task ID

Users can view previous scan results from the dashboard.

---

## 13. PDF Security Report

VulScan-Lite generates a downloadable PDF report containing:

- Scan information
- Security score and grade
- Security headers
- DNS/IP information
- Remediation guidance
- SSL/TLS information
- Redirect analysis
- Passive scanning disclaimer

---

## 14. Security and Ethical Scope

VulScan-Lite is designed for defensive and educational security assessment.

It does not perform:

- Exploitation
- Password attacks
- Brute-force attacks
- Destructive testing
- Intrusive vulnerability exploitation

The scanner is intended for authorized passive analysis only.