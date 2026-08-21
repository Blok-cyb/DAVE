from flask import Blueprint, request, jsonify
import sqlite3

from utils.security import (
    is_valid_email,
    is_strong_password,
    hash_password,
    verify_password
)

auth = Blueprint("auth", __name__)


# ==========================
# LOGIN HISTORY LOGGER
# ==========================

def save_login_log(cursor, user_id, email, status, ip_address):

    cursor.execute("""

        INSERT INTO login_logs(
            user_id,
            email,
            ip_address,
            status
        )

        VALUES(?,?,?,?)

    """, (

        user_id,
        email,
        ip_address,
        status

    ))


# ==========================
# SIGNUP
# ==========================

@auth.route("/signup", methods=["POST"])
def signup():

    data = request.get_json()

    fullname = data.get("fullname", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not fullname or not email or not password:

        return jsonify({

            "success": False,
            "message": "All fields are required."

        }), 400

    if not is_valid_email(email):

        return jsonify({

            "success": False,
            "message": "Invalid email format."

        }), 400

    if not is_strong_password(password):

        return jsonify({

            "success": False,
            "message": "Password must contain at least 8 characters, uppercase, lowercase, number and special character."

        }), 400

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(

        "SELECT * FROM users WHERE email=?",

        (email,)

    )

    user = cursor.fetchone()

    if user:

        conn.close()

        return jsonify({

            "success": False,
            "message": "Email already exists."

        }), 409

    hashed_password = hash_password(password)

    cursor.execute("""

        INSERT INTO users(
            fullname,
            email,
            password
        )

        VALUES(?,?,?)

    """, (

        fullname,
        email,
        hashed_password

    ))

    conn.commit()
    conn.close()

    return jsonify({

        "success": True,
        "message": "Account created successfully."

    }), 201
# ==========================
# LOGIN
# ==========================

@auth.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""

        SELECT
            id,
            fullname,
            email,
            password,
            failed_attempts,
            locked

        FROM users

        WHERE email=?

    """, (email,))

    user = cursor.fetchone()

    ip_address = request.remote_addr

    # ==========================
    # EMAIL NOT FOUND
    # ==========================

    if not user:

        save_login_log(
            cursor,
            None,
            email,
            "Unknown Email",
            ip_address
        )

        conn.commit()
        conn.close()

        return jsonify({

            "success": False,
            "message": "Invalid email or password."

        }), 401

    user_id = user[0]
    fullname = user[1]
    hashed_password = user[3]
    failed_attempts = user[4]
    locked = user[5]

    # ==========================
    # ACCOUNT LOCKED
    # ==========================

    if locked == 1:

        save_login_log(
            cursor,
            user_id,
            email,
            "Locked Account",
            ip_address
        )

        conn.commit()
        conn.close()

        return jsonify({

            "success": False,
            "message": "Account locked. Please reset your password."

        }), 403

    # ==========================
    # WRONG PASSWORD
    # ==========================

    if not verify_password(password, hashed_password):

        failed_attempts += 1

        save_login_log(
            cursor,
            user_id,
            email,
            "Failed",
            ip_address
        )

        if failed_attempts >= 5:

            cursor.execute("""

                UPDATE users

                SET
                    failed_attempts=?,
                    locked=1

                WHERE id=?

            """, (

                failed_attempts,
                user_id

            ))

            conn.commit()
            conn.close()

            return jsonify({

                "success": False,
                "message": "Account locked after 5 failed login attempts."

            }), 403

        cursor.execute("""

            UPDATE users

            SET failed_attempts=?

            WHERE id=?

        """, (

            failed_attempts,
            user_id

        ))

        conn.commit()
        conn.close()

        return jsonify({

            "success": False,
            "message": f"Invalid password. Attempt {failed_attempts} of 5."

        }), 401

    # ==========================
    # SUCCESSFUL LOGIN
    # ==========================

    cursor.execute("""

        UPDATE users

        SET
            failed_attempts=0,
            locked=0

        WHERE id=?

    """, (

        user_id,

    ))

    save_login_log(
        cursor,
        user_id,
        email,
        "Success",
        ip_address
    )

    conn.commit()
    conn.close()

    return jsonify({

        "success": True,
        "message": "Login successful.",

        "user": {

            "id": user_id,
            "fullname": fullname,
            "email": email

        }

    })
# ==========================
# FORGOT PASSWORD
# ==========================

@auth.route("/forgot-password", methods=["POST"])
def forgot_password():

    data = request.get_json()

    email = data.get("email", "").strip().lower()
    new_password = data.get("password", "")

    # ==========================
    # VALIDATE EMAIL
    # ==========================

    if not is_valid_email(email):

        return jsonify({

            "success": False,
            "message": "Invalid email."

        }), 400

    # ==========================
    # VALIDATE PASSWORD
    # ==========================

    if not is_strong_password(new_password):

        return jsonify({

            "success": False,
            "message": "Password must contain at least 8 characters, uppercase, lowercase, number and special character."

        }), 400

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""

        SELECT id

        FROM users

        WHERE email=?

    """, (email,))

    user = cursor.fetchone()

    if not user:

        conn.close()

        return jsonify({

            "success": False,
            "message": "Email not found."

        }), 404

    hashed_password = hash_password(new_password)

    cursor.execute("""

        UPDATE users

        SET

            password=?,
            failed_attempts=0,
            locked=0

        WHERE email=?

    """, (

        hashed_password,
        email

    ))

    conn.commit()
    conn.close()

    return jsonify({

        "success": True,
        "message": "Password reset successful."

    }), 200
    # ==========================
# LOGIN HISTORY
# ==========================

@auth.route("/login-history", methods=["GET"])
def login_history():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""

        SELECT
            email,
            status,
            ip_address,
            login_time

        FROM login_logs

        ORDER BY login_time DESC

    """)

    rows = cursor.fetchall()

    conn.close()

    history = []

    for row in rows:

        history.append({

            "email": row[0],
            "status": row[1],
            "ip_address": row[2],
            "login_time": row[3]

        })

    return jsonify({

        "success": True,
        "logs": history

    })