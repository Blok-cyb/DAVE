
from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename
import sqlite3
import os

from feature_extraction import extract_features


scan = Blueprint("scan", __name__)

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

UPLOAD_FOLDER = os.path.join("/tmp", "uploads")
DATABASE = os.path.join(BASE_DIR, "database.db")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ==========================================
# DATABASE CONNECTION
# ==========================================

def db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ==========================================
# GET USER ID FROM REQUEST
# ==========================================

def get_user_id():

    # First try JSON/form/query sources
    user_id = request.form.get("user_id")

    if not user_id:
        user_id = request.args.get("user_id")

    if not user_id:
        data = request.get_json(silent=True) or {}
        user_id = data.get("user_id")

    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return None

    if user_id <= 0:
        return None

    return user_id


# ==========================================
# CHECK THAT USER EXISTS
# ==========================================

def user_exists(user_id):

    conn = db()

    row = conn.execute(
        "SELECT id FROM users WHERE id=?",
        (user_id,)
    ).fetchone()

    conn.close()

    return row is not None


# ==========================================
# SCAN FILE
# ==========================================

@scan.route("/scan", methods=["POST"])
def scan_file():

    # ======================================
    # GET LOGGED-IN USER
    # ======================================

    user_id = get_user_id()

    if not user_id:

        return jsonify(
            success=False,
            message="User account could not be identified. Please log in again."
        ), 401


    # ======================================
    # VERIFY USER
    # ======================================

    if not user_exists(user_id):

        return jsonify(
            success=False,
            message="Invalid user account."
        ), 401


    # ======================================
    # CHECK FILE
    # ======================================

    if "file" not in request.files:

        return jsonify(
            success=False,
            message="No file selected."
        ), 400


    file = request.files["file"]


    if not file.filename:

        return jsonify(
            success=False,
            message="Please choose a file."
        ), 400


    # ======================================
    # SECURE FILE NAME
    # ======================================

    filename = secure_filename(file.filename)


    if not filename:

        return jsonify(
            success=False,
            message="Invalid filename."
        ), 400


    # ======================================
    # PREVENT SAME-NAME CONFLICTS
    # ======================================

    # Store each uploaded file with the user ID
    # so different accounts do not overwrite
    # each other's files.

    base_name, extension = os.path.splitext(filename)

    filepath = os.path.join(
        UPLOAD_FOLDER,
        f"user_{user_id}_{base_name}{extension}"
    )


    # ======================================
    # SAVE FILE
    # ======================================

    try:

        file.save(filepath)

    except OSError as error:

        return jsonify(
            success=False,
            message=f"Unable to save file: {error}"
        ), 500


    # ======================================
    # EXTRACT FEATURES
    # ======================================

    try:

        result = extract_features(filepath)

    except Exception as error:

        # Remove failed upload
        try:
            if os.path.isfile(filepath):
                os.remove(filepath)
        except OSError:
            pass

        return jsonify(
            success=False,
            message=f"File analysis failed: {error}"
        ), 500


    # ======================================
    # SAVE SCAN FOR THIS USER ONLY
    # ======================================

    conn = db()

    try:

        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO scan_history
            (
                user_id,
                file_name,
                file_path,
                file_size,
                prediction,
                confidence,
                threat_level,

                write_count,
                delete_count,
                create_count,
                rename_count,

                write_entropy,
                ext_diversity,
                sensitive_path_access,
                read_write_ratio,

                hidden_file_activity,
                execution_attempts,

                detection_score,
                detection_reasons
            )

            VALUES
            (
                ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?,
                ?, ?
            )
            """,

            (
                user_id,

                filename,
                filepath,

                result.get("file_size", 0),

                result.get("prediction", "Pending"),

                result.get("confidence", 0),

                result.get("risk", "Unknown"),

                result.get("write_count", 0),

                result.get("delete_count", 0),

                result.get("create_count", 0),

                result.get("rename_count", 0),

                result.get("write_entropy", 0),

                result.get("ext_diversity", 0),

                result.get("sensitive_path_access", 0),

                result.get("read_write_ratio", 0),

                result.get("hidden_file_activity", 0),

                result.get("execution_attempts", 0),

                result.get("score", 0),

                "; ".join(result.get("reasons", []))
            )
        )


        scan_id = cur.lastrowid

        conn.commit()


    except sqlite3.Error as error:

        conn.rollback()

        conn.close()

        return jsonify(
            success=False,
            message=f"Unable to save scan result: {error}"
        ), 500


    conn.close()


    # ======================================
    # RETURN RESULT
    # ======================================

    return jsonify(

        success=True,

        scan_id=scan_id,

        user_id=user_id,

        **result

    )


# ==========================================
# PDF REPORT
# ==========================================

@scan.route("/report/<int:scan_id>/pdf", methods=["GET"])
def report_pdf(scan_id):

    # ======================================
    # GET USER ID
    # ======================================

    user_id = request.args.get("user_id")

    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        user_id = None


    if not user_id:

        return jsonify(
            success=False,
            message="User account is required."
        ), 401


    # ======================================
    # REPORTLAB
    # ======================================

    try:

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

    except ImportError:

        return jsonify(
            success=False,
            message="reportlab is not installed. Run: python -m pip install reportlab"
        ), 500


    # ======================================
    # GET REPORT BELONGING TO USER
    # ======================================

    conn = db()

    row = conn.execute(
        """
        SELECT
            id,
            file_name,
            file_size,
            prediction,
            confidence,
            threat_level,
            scan_time,

            write_count,
            delete_count,
            create_count,
            rename_count,

            write_entropy,
            ext_diversity,
            sensitive_path_access,
            read_write_ratio,

            hidden_file_activity,
            execution_attempts,

            detection_score,
            detection_reasons

        FROM scan_history

        WHERE id=?
        AND user_id=?

        """,

        (
            scan_id,
            user_id
        )
    ).fetchone()

    conn.close()


    if not row:

        return jsonify(
            success=False,
            message="Scan not found for this user."
        ), 404


    # ======================================
    # CREATE PDF
    # ======================================

    out = os.path.join(
        UPLOAD_FOLDER,
        f"malware_scan_report_{scan_id}.pdf"
    )


    doc = SimpleDocTemplate(
        out,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )


    styles = getSampleStyleSheet()


    story = [

        Paragraph(
            "Malware Detection Scan Report",
            styles["Title"]
        ),

        Spacer(1, 12),

        Paragraph(
            "Malware Detection Using File Activity",
            styles["Heading2"]
        ),

        Spacer(1, 8)

    ]


    labels = [

        "Scan ID",
        "File Name",
        "File Size (bytes)",
        "Prediction",
        "Confidence",
        "Risk",
        "Scan Time",

        "Write Count",
        "Delete Count",
        "Create Count",
        "Rename Count",

        "Write Entropy",
        "Extension Diversity",
        "Sensitive Path Access",
        "Read/Write Ratio",

        "Hidden File Activity",
        "Execution Attempts",

        "Detection Score"

    ]


    vals = list(row[:18])


    data = [
        ["Metric", "Result"]
    ] + [
        [str(a), str(b)]
        for a, b in zip(labels, vals)
    ]


    table = Table(
        data,
        colWidths=[210, 270]
    )


    table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#163b6d")
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
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
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                6
            )

        ])
    )


    story.append(table)

    story.append(Spacer(1, 14))


    story.append(
        Paragraph(
            "<b>Detection explanation:</b> "
            + str(row[18]),
            styles["BodyText"]
        )
    )


    story.append(Spacer(1, 10))


    story.append(
        Paragraph(
            "Note: This upload scan uses static file analysis. "
            "Activity counters represent the controlled scan/upload "
            "transaction; they are not a substitute for "
            "process-attributed live monitoring.",
            styles["BodyText"]
        )
    )


    doc.build(story)


    return send_file(
        out,
        as_attachment=True,
        download_name=os.path.basename(out),
        mimetype="application/pdf"
    )

