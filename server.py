import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, make_response, request, send_from_directory


ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DATABASE_PATH", ROOT / "luxe_strand.db"))
SESSION_COOKIE = "luxe_session"
SESSION_DURATION = 8 * 60 * 60
PASSWORD_ITERATIONS = 260_000


@contextmanager
def get_db_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    else:
        conn.commit()
    finally:
        conn.close()


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def get_session_cookie(token, max_age):
    cookie = (
        f"{SESSION_COOKIE}={token}; Max-Age={max_age}; "
        "Path=/; HttpOnly; SameSite=Lax"
    )
    if os.environ.get("COOKIE_SECURE", "").lower() in {"1", "true", "yes"}:
        cookie += "; Secure"
    return cookie


def verify_password(password, stored_password):
    if not stored_password.startswith("pbkdf2_sha256$"):
        return hmac.compare_digest(password, stored_password), True

    try:
        _, iterations, salt_hex, digest_hex = stored_password.split("$")
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
    except (ValueError, TypeError):
        return False, False

    return hmac.compare_digest(digest.hex(), digest_hex), False


def init_db():
    app_environment = os.environ.get("APP_ENV", "development").lower()
    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if app_environment == "production" and (not admin_username or not admin_password):
        raise RuntimeError(
            "Set ADMIN_USERNAME and ADMIN_PASSWORD before starting in production."
        )
    using_demo_credentials = not admin_username and not admin_password
    if using_demo_credentials:
        admin_username = "admin"
        admin_password = "admin123"
    elif not admin_username or not admin_password:
        raise RuntimeError("Set both ADMIN_USERNAME and ADMIN_PASSWORD.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", admin_username):
        raise RuntimeError("ADMIN_USERNAME must be 3-32 letters, numbers, dots, underscores, or hyphens.")
    if (not using_demo_credentials and len(admin_password) < 12) or len(admin_password) > 128:
        raise RuntimeError("ADMIN_PASSWORD must be between 12 and 128 characters.")

    with get_db_connection() as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

        if "accounts" in tables and "users" not in tables:
            conn.execute("ALTER TABLE accounts RENAME TO users")
        if "sessions" in tables and "admin_sessions" not in tables:
            conn.execute("ALTER TABLE sessions RENAME TO admin_sessions")
        if "accounts" in tables and "users" in tables:
            conn.execute(
                "INSERT OR IGNORE INTO users (username, password, email, role) "
                "SELECT username, password, email, role FROM accounts"
            )
            conn.execute("DROP TABLE accounts")
        if "sessions" in tables and "admin_sessions" in tables:
            conn.execute(
                "INSERT OR IGNORE INTO admin_sessions (token_hash, user_id, expires_at) "
                "SELECT token_hash, user_id, expires_at FROM sessions"
            )
            conn.execute("DROP TABLE sessions")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE,
                role TEXT NOT NULL DEFAULT 'admin'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                service TEXT NOT NULL,
                date TEXT NOT NULL,
                time TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending'
            )
            """
        )
        user_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
        if "email" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
        if "role" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")
        appointment_columns = {row["name"] for row in conn.execute("PRAGMA table_info(appointments)")}
        if "email" in appointment_columns:
            conn.execute("ALTER TABLE appointments DROP COLUMN email")
            appointment_columns.remove("email")
        if "user_id" not in appointment_columns:
            conn.execute("ALTER TABLE appointments ADD COLUMN user_id INTEGER REFERENCES users(id)")

        duplicate_user_ids = conn.execute(
            """
            SELECT id
            FROM users
            WHERE role = 'customer'
              AND LOWER(username) IN (
                  SELECT LOWER(username)
                  FROM users
                  WHERE role = 'customer'
                  GROUP BY LOWER(username)
                  HAVING COUNT(*) > 1
              )
            ORDER BY LOWER(username), id
            """
        ).fetchall()
        if duplicate_user_ids:
            duplicate_user_map = {}
            for row in duplicate_user_ids:
                user_id = row["id"]
                username_key = conn.execute(
                    "SELECT LOWER(username) FROM users WHERE id = ?",
                    (user_id,),
                ).fetchone()[0]
                duplicate_user_map.setdefault(username_key, []).append(user_id)
            for username_key, user_ids in duplicate_user_map.items():
                keep_id = min(user_ids)
                for duplicate_id in user_ids:
                    if duplicate_id == keep_id:
                        continue
                    conn.execute(
                        "UPDATE admin_sessions SET user_id = ? WHERE user_id = ?",
                        (keep_id, duplicate_id),
                    )
                    conn.execute(
                        "UPDATE appointments SET user_id = ? WHERE user_id = ?",
                        (keep_id, duplicate_id),
                    )
                    conn.execute("DELETE FROM users WHERE id = ?", (duplicate_id,))

        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users(email)")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS users_customer_username_ci_unique ON users(LOWER(username)) WHERE role = 'customer'"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            )
            """
        )

        admin = conn.execute(
            "SELECT id, role FROM users WHERE LOWER(username) = ? LIMIT 1",
            (admin_username.casefold(),),
        ).fetchone()
        if admin is not None and admin["role"] != "admin":
            raise RuntimeError("ADMIN_USERNAME is already assigned to a customer account.")
        if admin is None:
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')",
                (admin_username, hash_password(admin_password)),
            )
        else:
            conn.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (hash_password(admin_password), admin["id"]),
            )
        conn.execute("DELETE FROM admin_sessions WHERE expires_at <= ?", (int(time.time()),))
        conn.commit()


class APIController:
    def __init__(self):
        self.response = None

    def read_json(self):
        try:
            if request.content_length is None or request.content_length <= 0 or request.content_length > 16_384:
                raise ValueError("Invalid request size.")
            data = request.get_json(silent=True)
        except (ValueError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def get_session_user(self):
        token = request.cookies.get(SESSION_COOKIE)
        if token is None:
            return None

        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with get_db_connection() as conn:
            return conn.execute(
                """
                SELECT users.id, users.username, users.email, users.role
                FROM admin_sessions
                JOIN users ON users.id = admin_sessions.user_id
                WHERE admin_sessions.token_hash = ? AND admin_sessions.expires_at > ?
                """,
                (token_hash, int(time.time())),
            ).fetchone()

    def handle_get_session(self):
        user = self.get_session_user()
        if user is None:
            self.send_json({"authenticated": False}, 401)
            return
        self.send_json(
            {
                "authenticated": True,
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
            }
        )

    def handle_login(self):
        data = self.read_json()
        if data is None:
            self.send_json({"success": False, "message": "Invalid login data."}, 400)
            return

        username = str(data.get("username") or "").strip()
        password = str(data.get("password") or "")
        lookup_username = username.casefold()
        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT id, username, password, role FROM users WHERE LOWER(username) = ?",
                (lookup_username,),
            ).fetchone()
            if user is None:
                self.send_json({"success": False, "message": "Invalid username or password."}, 401)
                return

            valid, needs_rehash = verify_password(password, user["password"])
            if not valid:
                self.send_json({"success": False, "message": "Invalid username or password."}, 401)
                return
            if needs_rehash:
                conn.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    (hash_password(password), user["id"]),
                )

            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            conn.execute(
                "INSERT INTO admin_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_hash, user["id"], int(time.time()) + SESSION_DURATION),
            )
            conn.commit()

        self.send_json(
            {"success": True, "message": "Login successful.", "role": user["role"]},
            headers={
                "Set-Cookie": get_session_cookie(token, SESSION_DURATION)
            },
        )

    def handle_register(self):
        data = self.read_json()
        if data is None:
            self.send_json({"success": False, "message": "Invalid account details."}, 400)
            return

        username = str(data.get("username") or "").strip()
        password = str(data.get("password") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            self.send_json(
                {"success": False, "message": "Use 3–32 letters, numbers, dots, underscores, or hyphens for the username."},
                400,
            )
            return
        if len(password) < 12 or len(password) > 128:
            self.send_json(
                {"success": False, "message": "The password must be between 12 and 128 characters."},
                400,
            )
            return

        lookup_username = username.casefold()
        try:
            with get_db_connection() as conn:
                existing_user = conn.execute(
                    "SELECT id FROM users WHERE role = 'customer' AND LOWER(username) = ? LIMIT 1",
                    (lookup_username,),
                ).fetchone()
                if existing_user is not None:
                    self.send_json(
                        {"success": False, "message": "That username is already registered."}, 409
                    )
                    return

                cursor = conn.execute(
                    "INSERT INTO users (username, password, role) VALUES (?, ?, 'customer')",
                    (username, hash_password(password)),
                )
                user_id = cursor.lastrowid
                token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
                conn.execute(
                    "INSERT INTO admin_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                    (token_hash, user_id, int(time.time()) + SESSION_DURATION),
                )
                conn.commit()
        except sqlite3.IntegrityError:
            self.send_json(
                {"success": False, "message": "That username is already registered."}, 409
            )
            return

        self.send_json(
            {"success": True, "message": "Account created.", "role": "customer"},
            201,
            headers={"Set-Cookie": get_session_cookie(token, SESSION_DURATION)},
        )

    def handle_logout(self):
        user = self.get_session_user()
        if user is not None:
            token = request.cookies[SESSION_COOKIE]
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            with get_db_connection() as conn:
                conn.execute("DELETE FROM admin_sessions WHERE token_hash = ?", (token_hash,))
                conn.commit()

        self.send_json(
            {"success": True},
            headers={"Set-Cookie": get_session_cookie("", 0)},
        )

    def handle_get_appointments(self):
        user = self.get_session_user()
        if user is None:
            self.send_json({"error": "Sign in to view appointments."}, 401)
            return

        with get_db_connection() as conn:
            if user["role"] == "admin":
                rows = conn.execute(
                    "SELECT id, customer, phone, service, date, time, status "
                    "FROM appointments ORDER BY id DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT id, customer, phone, service, date, time, status
                    FROM appointments WHERE user_id = ? ORDER BY id DESC
                    """,
                    (user["id"],),
                ).fetchall()
        self.send_json({"appointments": [dict(row) for row in rows]})

    def handle_update_appointment_status(self):
        user = self.get_session_user()
        if user is None:
            self.send_json({"success": False, "message": "Sign in as an admin to update appointments."}, 401)
            return
        if user["role"] != "admin":
            self.send_json({"success": False, "message": "Only admins can update appointment status."}, 403)
            return

        data = self.read_json()
        if data is None or not isinstance(data.get("id"), int) or isinstance(data.get("id"), bool):
            self.send_json({"success": False, "message": "Invalid appointment update."}, 400)
            return
        appointment_id = data["id"]

        status = data.get("status")
        if not isinstance(status, str) or status not in {"Pending", "Completed"}:
            self.send_json({"success": False, "message": "Choose Pending or Completed."}, 400)
            return

        with get_db_connection() as conn:
            cursor = conn.execute(
                "UPDATE appointments SET status = ? WHERE id = ?",
                (status, appointment_id),
            )
            conn.commit()
        if cursor.rowcount == 0:
            self.send_json({"success": False, "message": "Appointment not found."}, 404)
            return

        self.send_json({"success": True, "status": status})

    def handle_delete_appointment(self):
        user = self.get_session_user()
        if user is None:
            self.send_json({"success": False, "message": "Sign in as an admin to remove appointments."}, 401)
            return
        if user["role"] != "admin":
            self.send_json({"success": False, "message": "Only admins can remove appointments."}, 403)
            return

        data = self.read_json()
        if data is None or not isinstance(data.get("id"), int) or isinstance(data.get("id"), bool):
            self.send_json({"success": False, "message": "Invalid appointment ID."}, 400)
            return

        with get_db_connection() as conn:
            cursor = conn.execute("DELETE FROM appointments WHERE id = ?", (data["id"],))
            conn.commit()
        if cursor.rowcount == 0:
            self.send_json({"success": False, "message": "Appointment not found."}, 404)
            return

        self.send_json({"success": True, "message": "Appointment removed."})

    def handle_create_appointment(self):
        data = self.read_json()
        if data is None:
            self.send_json({"success": False, "message": "Invalid appointment data."}, 400)
            return

        required = ["customer", "service", "date", "time"]
        if any(not str(data.get(key, "")).strip() for key in required):
            self.send_json(
                {"success": False, "message": "Missing required appointment information."}, 400
            )
            return

        customer = str(data["customer"]).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", customer):
            self.send_json(
                {"success": False, "message": "Use a username-style name without spaces or last names."},
                400,
            )
            return
        phone = str(data.get("phone") or "").strip()
        service = str(data["service"]).strip()
        appointment_date = str(data["date"]).strip()
        appointment_time = str(data["time"]).strip()
        try:
            parsed_date = datetime.strptime(appointment_date, "%Y-%m-%d").date()
        except ValueError:
            self.send_json({"success": False, "message": "Enter a valid appointment date."}, 400)
            return
        if parsed_date.year != datetime.now().year:
            self.send_json(
                {"success": False, "message": f"Appointments must be scheduled within {datetime.now().year}."},
                400,
            )
            return
        normalized_phone = None
        if phone:
            phone_digits = re.sub(r"\D", "", phone)
            if phone_digits.startswith("63"):
                phone_digits = phone_digits[2:]
            elif phone_digits.startswith("0"):
                phone_digits = phone_digits[1:]
            if not re.fullmatch(r"9\d{9}", phone_digits):
                self.send_json(
                    {"success": False, "message": "Enter a valid Philippine mobile number."}, 400
                )
                return
            normalized_phone = f"+63 {phone_digits[:3]} {phone_digits[3:6]} {phone_digits[6:]}"
        user = self.get_session_user()

        with get_db_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO appointments (customer, phone, service, date, time, status, user_id)
                VALUES (?, ?, ?, ?, ?, 'Pending', ?)
                """,
                (
                    customer,
                    normalized_phone or None,
                    service,
                    appointment_date,
                    appointment_time,
                    user["id"] if user is not None and user["role"] == "customer" else None,
                ),
            )
            conn.commit()
            appointment_id = cursor.lastrowid

        self.send_json(
            {
                "success": True,
                "message": "Your appointment request is saved and is pending salon confirmation.",
                "id": appointment_id,
            },
            201,
        )

    def send_json(self, payload, status=200, headers=None):
        response = make_response(jsonify(payload), status)
        for name, value in (headers or {}).items():
            response.headers[name] = value
        self.response = response
        return response


app = Flask(__name__, static_folder=None)


@app.get("/health")
def health():
    return {"status": "ok"}


def dispatch_handler(handler_name):
    controller = APIController()
    getattr(controller, handler_name)()
    if controller.response is None:
        raise RuntimeError(f"{handler_name} did not create an HTTP response.")
    return controller.response


@app.get("/")
def home():
    return send_from_directory(ROOT, "index.html")


@app.get("/api/session")
def get_session():
    return dispatch_handler("handle_get_session")


@app.get("/api/appointments")
def get_appointments():
    return dispatch_handler("handle_get_appointments")


@app.post("/api/login")
def login():
    return dispatch_handler("handle_login")


@app.post("/api/register")
def register():
    return dispatch_handler("handle_register")


@app.post("/api/logout")
def logout():
    return dispatch_handler("handle_logout")


@app.post("/api/appointments")
def create_appointment():
    return dispatch_handler("handle_create_appointment")


@app.post("/api/appointments/status")
def update_appointment_status():
    return dispatch_handler("handle_update_appointment_status")


@app.delete("/api/appointments")
def delete_appointment():
    return dispatch_handler("handle_delete_appointment")


@app.get("/favicon.ico")
def favicon():
    return send_from_directory(ROOT / "images", "favicon.jpg")


@app.get("/<path:filename>")
def static_file(filename):
    if Path(filename).suffix.lower() not in {".html", ".css", ".js", ".jpg"}:
        return "Not found", 404
    return send_from_directory(ROOT, filename)


init_db()


def main():
    host = "127.0.0.1"
    port = int(os.environ.get("PORT", "8000"))
    print(f"Serving Luxe Strand at http://{host}:{port}")
    try:
        app.run(host=host, port=port, threaded=True)
    except KeyboardInterrupt:
        print("\nStopping server...")


if __name__ == "__main__":
    main()
