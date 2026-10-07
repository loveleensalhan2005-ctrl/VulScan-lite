from flask import (
    Flask,
    request,
    jsonify,
    send_file,
    session
)

from flask_cors import CORS
from celery.result import AsyncResult
from celery_worker import celery_app

from io import BytesIO
import sqlite3
import os
import time

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)

app.secret_key = "vulscan-lite-project-secret-key"


# =========================================================
# CORS
# =========================================================

CORS(
    app,
    supports_credentials=True,
    origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174"
    ]
)


# =========================================================
# SESSION SETTINGS
# =========================================================

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False


# =========================================================
# DATABASE
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DB_PATH = os.path.join(
    BASE_DIR,
    "vulscan_history.db"
)


def get_db():

    connection = sqlite3.connect(
        DB_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_db():

    connection = get_db()

    cursor = connection.cursor()

    # Users table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """
    )

    # Scan history table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            task_id TEXT NOT NULL,
            url TEXT NOT NULL,
            score INTEGER,
            grade TEXT,
            status_code INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # Demo user
    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        ("student",)
    )

    user = cursor.fetchone()

    if not user:

        hashed_password = generate_password_hash(
            "vulscan123"
        )

        cursor.execute(
            """
            INSERT INTO users
            (username, password)
            VALUES (?, ?)
            """,
            (
                "student",
                hashed_password
            )
        )

    connection.commit()

    connection.close()


init_db()


# =========================================================
# RATE LIMITING
# =========================================================

# Simple in-memory rate limiter.
#
# Each logged-in user can start maximum
# 5 scans during a rolling 60-second window.

RATE_LIMIT = 5
RATE_WINDOW = 60

scan_requests = {}


def check_rate_limit(username):

    current_time = time.time()

    if username not in scan_requests:

        scan_requests[username] = []

    # Keep only requests inside the last 60 seconds
    scan_requests[username] = [
        timestamp
        for timestamp in scan_requests[username]
        if current_time - timestamp < RATE_WINDOW
    ]

    if len(scan_requests[username]) >= RATE_LIMIT:

        return False

    scan_requests[username].append(
        current_time
    )

    return True


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return jsonify({
        "message": "VulScan-Lite API is running",
        "status": "online"
    })


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/api/login",
    methods=["POST"]
)
def login():

    data = request.get_json(
        silent=True
    ) or {}

    username = data.get(
        "username",
        ""
    ).strip()

    password = data.get(
        "password",
        ""
    )

    if not username or not password:

        return jsonify({
            "success": False,
            "message":
                "Username and password are required."
        }), 400

    connection = get_db()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    user = cursor.fetchone()

    connection.close()

    if not user:

        return jsonify({
            "success": False,
            "message":
                "Invalid username or password."
        }), 401

    if not check_password_hash(
        user["password"],
        password
    ):

        return jsonify({
            "success": False,
            "message":
                "Invalid username or password."
        }), 401

    session.clear()

    session["username"] = username

    session.permanent = True

    return jsonify({
        "success": True,
        "username": username
    })


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/api/logout",
    methods=["POST"]
)
def logout():

    session.clear()

    return jsonify({
        "success": True,
        "message": "Logged out successfully."
    })


# =========================================================
# CHECK LOGIN
# =========================================================

@app.route(
    "/api/me",
    methods=["GET"]
)
def current_user():

    username = session.get(
        "username"
    )

    if username:

        return jsonify({
            "logged_in": True,
            "username": username
        })

    return jsonify({
        "logged_in": False
    })


# =========================================================
# START SCAN
# =========================================================

@app.route(
    "/api/scan",
    methods=["POST"]
)
def start_scan():

    username = session.get(
        "username"
    )

    if not username:

        return jsonify({
            "success": False,
            "message":
                "Please login before starting a scan."
        }), 401

    # Rate limit
    if not check_rate_limit(username):

        return jsonify({
            "success": False,
            "message":
                "Rate limit exceeded. "
                "Please wait before starting another scan."
        }), 429

    data = request.get_json(
        silent=True
    ) or {}

    url = data.get(
        "url",
        ""
    ).strip()

    if not url:

        return jsonify({
            "success": False,
            "message":
                "Please provide a website URL."
        }), 400

    # Basic URL validation
    if not (
        url.startswith("http://")
        or url.startswith("https://")
    ):

        return jsonify({
            "success": False,
            "message":
                "URL must start with http:// or https://"
        }), 400

    try:

        task = celery_app.send_task(
            "celery_worker.scan_website",
            args=[url]
        )

        return jsonify({
            "success": True,
            "task_id": task.id,
            "message":
                "Scan queued successfully."
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "message":
                "Unable to queue scan.",
            "error": str(e)
        }), 500


# =========================================================
# SCAN STATUS
# =========================================================

@app.route(
    "/api/scan/<task_id>/status",
    methods=["GET"]
)
def scan_status(task_id):

    username = session.get(
        "username"
    )

    if not username:

        return jsonify({
            "success": False,
            "message":
                "Please login."
        }), 401

    task = AsyncResult(
        task_id,
        app=celery_app
    )

    if task.state == "PENDING":

        return jsonify({
            "status": "pending"
        })

    if task.state == "STARTED":

        return jsonify({
            "status": "running"
        })

    if task.state == "FAILURE":

        return jsonify({
            "status": "failed",
            "error": str(task.info)
        })

    if task.state == "SUCCESS":

        result = task.result

        if not isinstance(
            result,
            dict
        ):

            return jsonify({
                "status": "failed",
                "error":
                    "Invalid scan result."
            }), 500

        # Save result into history
        connection = get_db()

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT id
            FROM scan_history
            WHERE task_id = ?
            """,
            (task_id,)
        )

        already_saved = cursor.fetchone()

        if not already_saved:

            cursor.execute(
                """
                INSERT INTO scan_history
                (
                    username,
                    task_id,
                    url,
                    score,
                    grade,
                    status_code
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    task_id,
                    result.get(
                        "url",
                        ""
                    ),
                    result.get(
                        "security_score"
                    ),
                    result.get(
                        "security_grade"
                    ),
                    result.get(
                        "status_code"
                    )
                )
            )

            connection.commit()

        connection.close()

        return jsonify({
            "status": "completed",
            "result": result
        })

    return jsonify({
        "status":
            task.state.lower()
    })


# =========================================================
# SCAN HISTORY
# =========================================================

@app.route(
    "/api/history",
    methods=["GET"]
)
def history():

    username = session.get(
        "username"
    )

    if not username:

        return jsonify({
            "success": False,
            "message":
                "Please login."
        }), 401

    connection = get_db()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            task_id,
            url,
            score,
            grade,
            status_code,
            created_at
        FROM scan_history
        WHERE username = ?
        ORDER BY created_at DESC
        """,
        (username,)
    )

    rows = cursor.fetchall()

    connection.close()

    history_data = []

    for row in rows:

        history_data.append({
            "id": row["id"],
            "task_id": row["task_id"],
            "url": row["url"],
            "score": row["score"],
            "grade": row["grade"],
            "status_code":
                row["status_code"],
            "created_at":
                row["created_at"]
        })

    return jsonify({
        "success": True,
        "history": history_data
    })


# =========================================================
# PDF REPORT
# =========================================================

@app.route(
    "/api/scan/<task_id>/report",
    methods=["GET"]
)
def generate_report(task_id):

    username = session.get(
        "username"
    )

    if not username:

        return jsonify({
            "success": False,
            "message":
                "Please login."
        }), 401

    # Make sure the scan belongs to logged-in user
    connection = get_db()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM scan_history
        WHERE task_id = ?
        AND username = ?
        """,
        (
            task_id,
            username
        )
    )

    history_row = cursor.fetchone()

    connection.close()

    if not history_row:

        return jsonify({
            "success": False,
            "message":
                "Scan report not found."
        }), 404

    task = AsyncResult(
        task_id,
        app=celery_app
    )

    if task.state != "SUCCESS":

        return jsonify({
            "success": False,
            "message":
                "Scan result is not available yet."
        }), 400

    result = task.result

    # -----------------------------------------------------
    # PDF setup
    # -----------------------------------------------------

    pdf_buffer = BytesIO()

    document = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]

    heading_style = styles["Heading2"]

    normal_style = styles["BodyText"]

    story = []

    # -----------------------------------------------------
    # Title
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "VulScan-Lite Security Report",
            title_style
        )
    )

    story.append(
        Spacer(1, 15)
    )

    story.append(
        Paragraph(
            "Passive Web Vulnerability Scanner",
            normal_style
        )
    )

    story.append(
        Spacer(1, 20)
    )

    # -----------------------------------------------------
    # 1. Scan Information
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "1. Scan Information",
            heading_style
        )
    )

    scan_info = [
        ["Property", "Value"],
        [
            "Website",
            str(
                result.get(
                    "url",
                    "N/A"
                )
            )
        ],
        [
            "HTTP Status",
            str(
                result.get(
                    "status_code",
                    "N/A"
                )
            )
        ],
        [
            "Response Time",
            str(
                result.get(
                    "response_time",
                    "N/A"
                )
            ) + " seconds"
        ],
        [
            "Server",
            str(
                result.get(
                    "server",
                    "N/A"
                )
            )
        ]
    ]

    scan_table = Table(
        scan_info,
        colWidths=[
            180,
            320
        ]
    )

    scan_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            )
        ])
    )

    story.append(scan_table)

    story.append(
        Spacer(1, 20)
    )

    # -----------------------------------------------------
    # 2. Security Assessment
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "2. Security Assessment",
            heading_style
        )
    )

    score = result.get(
        "security_score",
        0
    )

    grade = result.get(
        "security_grade",
        "N/A"
    )

    assessment_data = [
        ["Metric", "Result"],
        [
            "Security Score",
            f"{score} / 100"
        ],
        [
            "Security Grade",
            grade
        ]
    ]

    assessment_table = Table(
        assessment_data,
        colWidths=[
            180,
            320
        ]
    )

    assessment_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            )
        ])
    )

    story.append(
        assessment_table
    )

    story.append(
        Spacer(1, 20)
    )

    # -----------------------------------------------------
    # 3. Security Headers
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "3. Security Headers",
            heading_style
        )
    )

    header_results = result.get(
        "security_headers",
        {}
    )

    header_data = [
        [
            "Security Header",
            "Status",
            "Value"
        ]
    ]

    for header_name in [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security"
    ]:

        header = header_results.get(
            header_name,
            {}
        )

        if isinstance(
            header,
            dict
        ):

            present = header.get(
                "present",
                False
            )

            value = header.get(
                "value"
            )

        else:

            present = bool(header)
            value = str(header)

        header_data.append([
            header_name,
            "PASS"
            if present
            else "FAIL",
            str(value)
            if value
            else "Missing"
        ])

    header_table = Table(
        header_data,
        colWidths=[
            190,
            70,
            240
        ]
    )

    header_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            )
        ])
    )

    story.append(header_table)

    story.append(
        Spacer(1, 20)
    )

    # -----------------------------------------------------
    # 4. DNS / IP Information
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "4. DNS / IP Information",
            heading_style
        )
    )

    dns_data = [
        ["Property", "Value"],
        [
            "Hostname",
            str(
                result.get(
                    "hostname",
                    "N/A"
                )
            )
        ],
        [
            "IP Address",
            str(
                result.get(
                    "ip_address",
                    "N/A"
                )
            )
        ],
        [
            "DNS Status",
            str(
                result.get(
                    "summary",
                    {}
                ).get(
                    "dns_ip",
                    "N/A"
                )
            )
        ]
    ]

    dns_table = Table(
        dns_data,
        colWidths=[
            180,
            320
        ]
    )

    dns_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            )
        ])
    )

    story.append(dns_table)

    story.append(
        Spacer(1, 20)
    )

    # -----------------------------------------------------
    # 5. Remediation Guidance
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "5. Remediation Guidance",
            heading_style
        )
    )

    remediation = result.get(
        "remediation",
        []
    )

    if remediation:

        for item in remediation:

            if isinstance(
                item,
                dict
            ):

                title = item.get(
                    "title",
                    "Security Issue"
                )

                severity = item.get(
                    "severity",
                    "Information"
                )

                message = item.get(
                    "message",
                    ""
                )

                fix = item.get(
                    "fix",
                    ""
                )

                story.append(
                    Paragraph(
                        f"<b>{title}</b> "
                        f"({severity})",
                        normal_style
                    )
                )

                story.append(
                    Paragraph(
                        message,
                        normal_style
                    )
                )

                story.append(
                    Paragraph(
                        f"<b>How to Fix:</b> {fix}",
                        normal_style
                    )
                )

                story.append(
                    Spacer(1, 10)
                )

    else:

        story.append(
            Paragraph(
                "No remediation guidance available.",
                normal_style
            )
        )

    story.append(
        Spacer(1, 10)
    )

    # -----------------------------------------------------
    # 6. SSL / TLS
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "6. SSL / TLS Information",
            heading_style
        )
    )

    ssl_info = result.get(
        "ssl_tls"
    )

    if ssl_info:

        ssl_data = [
            ["Property", "Value"],
            [
                "Issuer",
                str(
                    ssl_info.get(
                        "issuer",
                        "N/A"
                    )
                )
            ],
            [
                "Valid From",
                str(
                    ssl_info.get(
                        "valid_from",
                        "N/A"
                    )
                )
            ],
            [
                "Valid Until",
                str(
                    ssl_info.get(
                        "valid_until",
                        "N/A"
                    )
                )
            ],
            [
                "Cipher",
                str(
                    ssl_info.get(
                        "cipher",
                        "N/A"
                    )
                )
            ]
        ]

        ssl_table = Table(
            ssl_data,
            colWidths=[
                180,
                320
            ]
        )

        ssl_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )
            ])
        )

        story.append(
            ssl_table
        )

    else:

        story.append(
            Paragraph(
                "SSL/TLS information unavailable.",
                normal_style
            )
        )

    story.append(
        Spacer(1, 20)
    )

    # -----------------------------------------------------
    # 7. Redirect Analysis
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "7. Redirect Analysis",
            heading_style
        )
    )

    redirects = result.get(
        "redirects",
        []
    )

    if redirects:

        redirect_data = [
            [
                "Status Code",
                "Location"
            ]
        ]

        for redirect in redirects:

            redirect_data.append([
                str(
                    redirect.get(
                        "status_code",
                        "N/A"
                    )
                ),
                str(
                    redirect.get(
                        "location",
                        "N/A"
                    )
                )
            ])

        redirect_table = Table(
            redirect_data,
            colWidths=[
                120,
                380
            ]
        )

        redirect_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                )
            ])
        )

        story.append(
            redirect_table
        )

    else:

        story.append(
            Paragraph(
                "No redirects detected.",
                normal_style
            )
        )

    story.append(
        Spacer(1, 20)
    )

    # -----------------------------------------------------
    # 8. Disclaimer
    # -----------------------------------------------------

    story.append(
        Paragraph(
            "8. Disclaimer",
            heading_style
        )
    )

    story.append(
        Paragraph(
            "<b>Only scan websites you own. "
            "This tool performs passive analysis only.</b>",
            normal_style
        )
    )

    story.append(
        Spacer(1, 15)
    )

    story.append(
        Paragraph(
            "VulScan-Lite is designed for defensive "
            "security assessment and educational use.",
            normal_style
        )
    )

    # -----------------------------------------------------
    # BUILD PDF
    # -----------------------------------------------------

    document.build(story)

    pdf_buffer.seek(0)

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="vulscan-lite-report.pdf"
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )