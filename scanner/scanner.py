import requests
import ssl
import socket
import json
from urllib.parse import urlparse
from bs4 import BeautifulSoup


def check_ssl(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if not hostname:
        return None

    context = ssl.create_default_context()

    with socket.create_connection((hostname, 443), timeout=10) as sock:
        with context.wrap_socket(
            sock,
            server_hostname=hostname
        ) as secure_sock:

            certificate = secure_sock.getpeercert()

            return {
                "issuer": str(certificate.get("issuer")),
                "valid_from": certificate.get("notBefore"),
                "valid_until": certificate.get("notAfter"),
                "cipher": str(secure_sock.cipher())
            }


def detect_cms(response):
    cms_detected = False
    cms_name = None

    soup = BeautifulSoup(
        response.text,
        "html.parser"
    )

    meta_generator = soup.find(
        "meta",
        attrs={"name": "generator"}
    )

    if meta_generator and meta_generator.get("content"):
        cms_name = meta_generator.get("content")
        cms_detected = True

    html_content = response.text.lower()

    if "wordpress" in html_content:
        cms_name = "WordPress"
        cms_detected = True

    elif "joomla" in html_content:
        cms_name = "Joomla"
        cms_detected = True

    elif "drupal" in html_content:
        cms_name = "Drupal"
        cms_detected = True

    powered_by = response.headers.get(
        "X-Powered-By"
    )

    return {
        "detected": cms_detected,
        "name": cms_name,
        "powered_by": powered_by
    }


def generate_remediation(header_results):
    remediation = []

    if not header_results[
        "Content-Security-Policy"
    ]["present"]:

        remediation.append({
            "title": "Content-Security-Policy (CSP)",
            "severity": "High",
            "message":
                "Add a Content-Security-Policy header "
                "to control which resources the browser "
                "is allowed to load and reduce XSS risks.",
            "fix":
                "Configure the web server or application "
                "to return a suitable Content-Security-Policy "
                "response header."
        })

    if not header_results[
        "X-Frame-Options"
    ]["present"]:

        remediation.append({
            "title": "X-Frame-Options",
            "severity": "Medium",
            "message":
                "Add X-Frame-Options to help prevent "
                "the website from being embedded in "
                "unauthorized frames.",
            "fix":
                "Add the X-Frame-Options response header, "
                "for example with the value SAMEORIGIN "
                "when appropriate."
        })

    if not header_results[
        "Strict-Transport-Security"
    ]["present"]:

        remediation.append({
            "title": "Strict-Transport-Security (HSTS)",
            "severity": "High",
            "message":
                "Add HSTS to instruct browsers to use "
                "HTTPS for future connections.",
            "fix":
                "Configure the Strict-Transport-Security "
                "response header after confirming that "
                "the website is fully available over HTTPS."
        })

    if not remediation:
        remediation.append({
            "title": "No critical header issues detected",
            "severity": "Pass",
            "message":
                "The checked security headers are present.",
            "fix":
                "Continue monitoring security configuration "
                "and keep headers properly configured."
        })

    return remediation


def run_scan(url):

    scan_result = {
        "url": url
    }

    response = requests.get(
        url,
        timeout=10
    )

    scan_result["status_code"] = response.status_code

    response_time = round(
        response.elapsed.total_seconds(),
        3
    )

    scan_result["response_time"] = response_time

    # CMS Detection
    scan_result["cms_detection"] = detect_cms(
        response
    )

    # DNS / IP
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    ip_address = None

    if hostname:

        try:
            ip_address = socket.gethostbyname(
                hostname
            )

        except socket.gaierror:
            ip_address = None

    scan_result["hostname"] = hostname
    scan_result["ip_address"] = ip_address

    # Redirect Analysis
    redirects = []

    for redirect in response.history:

        redirects.append({
            "status_code": redirect.status_code,
            "location":
                redirect.headers.get("Location")
        })

    scan_result["redirects"] = redirects
    scan_result["final_url"] = response.url

    # Security Headers
    headers_to_check = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security"
    ]

    header_results = {}
    score = 0

    for header in headers_to_check:

        if header in response.headers:

            header_results[header] = {
                "present": True,
                "value":
                    response.headers[header]
            }

            score += 10

        else:

            header_results[header] = {
                "present": False,
                "value": None
            }

            score -= 10

    final_score = max(
        0,
        min(
            100,
            50 + score
        )
    )

    scan_result["security_headers"] = (
        header_results
    )

    scan_result["security_score"] = (
        final_score
    )

    # Remediation Guidance
    scan_result["remediation"] = (
        generate_remediation(
            header_results
        )
    )

    # Grade
    if final_score >= 90:
        grade = "A"

    elif final_score >= 80:
        grade = "B"

    elif final_score >= 70:
        grade = "C"

    elif final_score >= 60:
        grade = "D"

    else:
        grade = "F"

    scan_result["security_grade"] = grade

    # Server Information
    scan_result["server"] = (
        response.headers.get("Server")
    )

    # HTTP Methods
    scan_result["allowed_methods"] = (
        response.headers.get("Allow")
    )

    # Cookie Security
    cookie_results = []

    for cookie in response.cookies:

        secure_flag = cookie.secure

        httponly_flag = (
            cookie.has_nonstandard_attr(
                "HttpOnly"
            )
        )

        samesite_flag = (
            cookie.has_nonstandard_attr(
                "SameSite"
            )
        )

        cookie_results.append({
            "name": cookie.name,
            "secure": secure_flag,
            "httponly": httponly_flag,
            "samesite": samesite_flag
        })

    scan_result["cookies"] = cookie_results

    # SSL/TLS
    ssl_info = None

    try:
        ssl_info = check_ssl(url)

    except Exception:
        ssl_info = None

    scan_result["ssl_tls"] = ssl_info

    # Summary
    scan_result["summary"] = {
        "ssl_tls":
            "PASS" if ssl_info else "FAIL",

        "dns_ip":
            "PASS"
            if hostname and ip_address
            else "FAIL",

        "scan_status":
            "Completed"
    }

    return scan_result


# Command-line mode
if __name__ == "__main__":

    url = input(
        "Enter website URL: "
    )

    try:

        result = run_scan(url)

        print(
            "\n--- Scan Result ---"
        )

        print(
            json.dumps(
                result,
                indent=4
            )
        )

        with open(
            "scan_results.json",
            "w"
        ) as file:

            json.dump(
                result,
                file,
                indent=4
            )

        print(
            "\nScan completed successfully."
        )

        print(
            "Results saved to scan_results.json"
        )

    except Exception as e:

        print(
            "\nError:",
            e
        )