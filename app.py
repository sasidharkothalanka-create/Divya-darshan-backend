import os
import re
import secrets
from datetime import date, datetime, timedelta, timezone
from functools import wraps

import jwt
import pymysql
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")

# ---------------------------------------------------------------- config
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "temple_booking"),
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit": False,
}

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    print("WARNING: SECRET_KEY not set in .env - using a random one "
          "(everyone will be logged out whenever the server restarts).")

TOKEN_HOURS = 12
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin12345")

# Prices are decided HERE, never trusted from the browser.
PRICE_MEN = 300
PRICE_WOMEN = 250
PRICE_HANDICAPPED = 150

SLOTS = {
    "Morning (06:00 AM - 09:00 AM)",
    "Midday (10:00 AM - 01:00 PM)",
    "Evening (04:00 PM - 07:00 PM)",
    "Night (07:30 PM - 09:30 PM)",
}
PAYMENT_METHODS = {"UPI QR", "Card", "NetBanking"}
MAX_PEOPLE_PER_BOOKING = 20
MAX_DAYS_AHEAD = 180

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
PHONE_RE = re.compile(r"^\d{10}$")

app = Flask(__name__, static_folder=None)

origins = [o.strip() for o in os.getenv(
    "CORS_ORIGINS", "http://localhost:5500,http://127.0.0.1:5500"
).split(",") if o.strip()]
# Only needed if you open the frontend from another port (e.g. VS Code Live Server).
CORS(app, resources={r"/api/*": {"origins": origins}})


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = pymysql.connect(**DB_CONFIG)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query_all(sql, params=()):
    with get_db().cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def query_one(sql, params=()):
    with get_db().cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def ensure_admin():
    """Create the admin account on first start (password stored hashed)."""
    conn = pymysql.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username = %s", (ADMIN_USERNAME,))
            if cur.fetchone() is None:
                cur.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'admin')",
                    (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD)),
                )
                conn.commit()
                print(f"Admin user '{ADMIN_USERNAME}' created.")
    finally:
        conn.close()


# ---------------------------------------------------------------- helpers
def error(message, status=400, code=None):
    body = {"error": message}
    if code:
        body["code"] = code
    return jsonify(body), status


def make_token(user):
    payload = {
        "sub": str(user["id"]),
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def public_user(user):
    return {"username": user["username"], "role": user["role"]}


def login_required(admin_only=False):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return error("Please sign in first.", 401, "NO_TOKEN")
            try:
                data = jwt.decode(header[7:], SECRET_KEY, algorithms=["HS256"])
                user_id = int(data["sub"])
            except jwt.ExpiredSignatureError:
                return error("Session expired. Please sign in again.", 401, "TOKEN_EXPIRED")
            except (jwt.InvalidTokenError, ValueError, KeyError):
                return error("Invalid session. Please sign in again.", 401, "BAD_TOKEN")

            user = query_one("SELECT id, username, role FROM users WHERE id = %s", (user_id,))
            if user is None:
                return error("Account no longer exists.", 401, "NO_USER")
            if admin_only and user["role"] != "admin":
                return error("Admin access required.", 403, "FORBIDDEN")
            g.user = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def to_int(value, field, low=0, high=MAX_PEOPLE_PER_BOOKING):
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a number.")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be a number.")
    if number < low or number > high:
        raise ValueError(f"{field} must be between {low} and {high}.")
    return number


BOOKING_SELECT = """
    SELECT b.ticket_id, b.devotee_name, b.phone, b.temple_id, b.darshan_date, b.slot,
           b.men_qty, b.women_qty, b.handicapped_qty, b.wheelchair, b.payment_method,
           b.total_amount, b.status, b.created_at,
           u.username, t.name AS temple_name, t.deity
    FROM bookings b
    JOIN users   u ON u.id = b.user_id
    JOIN temples t ON t.id = b.temple_id
"""


def booking_json(r):
    """Shape matches what the frontend (script.js) already expects."""
    return {
        "id": r["ticket_id"],
        "username": r["username"],
        "devoteeName": r["devotee_name"],
        "phone": r["phone"],
        "templeId": r["temple_id"],
        "templeName": r["temple_name"],
        "deity": r["deity"],
        "date": r["darshan_date"].isoformat(),
        "slot": r["slot"],
        "menQty": r["men_qty"],
        "womenQty": r["women_qty"],
        "handicappedQty": r["handicapped_qty"],
        "wheelchair": bool(r["wheelchair"]),
        "paymentMethod": r["payment_method"],
        "totalAmount": r["total_amount"],
        "status": r["status"],
        "bookingTime": r["created_at"].isoformat(),
    }


# ---------------------------------------------------------------- auth routes
@app.post("/api/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not USERNAME_RE.match(username):
        return error("Username must be 3-30 characters: letters, numbers or underscore.")
    if len(password) < 6:
        return error("Password must be at least 6 characters.")

    if query_one("SELECT id FROM users WHERE username = %s", (username,)):
        return error("That username is already taken.", 409, "USERNAME_TAKEN")

    db = get_db()
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, 'devotee')",
            (username, generate_password_hash(password)),
        )
        user_id = cur.lastrowid
    db.commit()

    user = {"id": user_id, "username": username, "role": "devotee"}
    return jsonify({"token": make_token(user), "user": public_user(user), "created": True}), 201


@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    user = query_one(
        "SELECT id, username, password_hash, role FROM users WHERE username = %s", (username,)
    )
    if user is None:
        return error("No account with that username.", 404, "USER_NOT_FOUND")
    if not check_password_hash(user["password_hash"], password):
        return error("Incorrect password.", 401, "INVALID_PASSWORD")

    return jsonify({"token": make_token(user), "user": public_user(user), "created": False})


# ---------------------------------------------------------------- temples
@app.get("/api/temples")
def list_temples():
    rows = query_all(
        "SELECT id, name, deity, location, description, map_url AS mapUrl FROM temples ORDER BY name"
    )
    return jsonify({"temples": rows})


# ---------------------------------------------------------------- bookings
@app.post("/api/bookings")
@login_required()
def create_booking():
    data = request.get_json(silent=True) or {}

    temple = query_one("SELECT id FROM temples WHERE id = %s", (str(data.get("templeId", "")),))
    if temple is None:
        return error("Unknown temple.")

    devotee_name = str(data.get("devoteeName", "")).strip()
    if not 2 <= len(devotee_name) <= 100:
        return error("Devotee name must be 2-100 characters.")

    phone = str(data.get("phone", "")).strip()
    if not PHONE_RE.match(phone):
        return error("Phone number must be exactly 10 digits.")

    try:
        darshan_date = date.fromisoformat(str(data.get("date", "")))
    except ValueError:
        return error("Invalid darshan date.")
    today = date.today()
    if darshan_date < today:
        return error("Darshan date cannot be in the past.")
    if darshan_date > today + timedelta(days=MAX_DAYS_AHEAD):
        return error(f"Bookings open only {MAX_DAYS_AHEAD} days in advance.")

    slot = str(data.get("slot", ""))
    if slot not in SLOTS:
        return error("Invalid time slot.")

    payment = str(data.get("paymentMethod", "UPI QR"))
    if payment not in PAYMENT_METHODS:
        return error("Invalid payment method.")

    try:
        men = to_int(data.get("menQty", 0), "Men count")
        women = to_int(data.get("womenQty", 0), "Women count")
        handicapped = to_int(data.get("handicappedQty", 0), "Divyangjan count")
    except ValueError as exc:
        return error(str(exc))

    people = men + women + handicapped
    if people == 0:
        return error("Select at least 1 devotee.")
    if people > MAX_PEOPLE_PER_BOOKING:
        return error(f"Maximum {MAX_PEOPLE_PER_BOOKING} devotees per booking.")

    wheelchair = 1 if data.get("wheelchair") is True else 0
    total = men * PRICE_MEN + women * PRICE_WOMEN + handicapped * PRICE_HANDICAPPED

    db = get_db()
    ticket_id = None
    for _ in range(10):  # retry in the (very unlikely) case of an ID clash
        candidate = f"APTS-{secrets.randbelow(900000) + 100000}"
        try:
            with db.cursor() as cur:
                cur.execute(
                    """INSERT INTO bookings
                       (ticket_id, user_id, temple_id, devotee_name, phone, darshan_date, slot,
                        men_qty, women_qty, handicapped_qty, wheelchair, payment_method, total_amount)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (candidate, g.user["id"], temple["id"], devotee_name, phone, darshan_date,
                     slot, men, women, handicapped, wheelchair, payment, total),
                )
            db.commit()
            ticket_id = candidate
            break
        except pymysql.err.IntegrityError as exc:
            db.rollback()
            if exc.args and exc.args[0] == 1062:  # duplicate ticket_id -> try another
                continue
            raise
    if ticket_id is None:
        return error("Could not generate a ticket. Please try again.", 500)

    row = query_one(BOOKING_SELECT + " WHERE b.ticket_id = %s", (ticket_id,))
    return jsonify({"booking": booking_json(row)}), 201


@app.get("/api/bookings/my")
@login_required()
def my_bookings():
    rows = query_all(
        BOOKING_SELECT + " WHERE b.user_id = %s ORDER BY b.created_at DESC, b.id DESC",
        (g.user["id"],),
    )
    return jsonify({"bookings": [booking_json(r) for r in rows]})


@app.get("/api/admin/bookings")
@login_required(admin_only=True)
def admin_bookings():
    rows = query_all(BOOKING_SELECT + " ORDER BY b.created_at DESC, b.id DESC")
    return jsonify({"bookings": [booking_json(r) for r in rows]})


@app.get("/api/health")
def health():
    query_one("SELECT 1 AS ok")
    return jsonify({"status": "ok", "database": "connected"})


# ---------------------------------------------------------------- errors
@app.errorhandler(404)
def not_found(_e):
    if request.path.startswith("/api/"):
        return error("Not found.", 404)
    return "Not found", 404


@app.errorhandler(500)
def server_error(_e):
    return error("Server error. Check the Flask console for details.", 500)


@app.errorhandler(pymysql.err.OperationalError)
def db_down(_e):
    return error("Cannot connect to the MySQL database. Check backend/.env and that MySQL is running.", 503)


# ---------------------------------------------------------------- serve frontend
@app.get("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/<path:filename>")
def frontend_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


if __name__ == "__main__":
    try:
        ensure_admin()
    except pymysql.err.MySQLError as exc:
        raise SystemExit(
            f"\nCould not connect to MySQL: {exc}\n"
            "1) Make sure MySQL is running\n"
            "2) Check DB_USER / DB_PASSWORD in backend/.env\n"
            "3) Create the tables:  python init_db.py\n"
        )
    app.run(host="127.0.0.1", port=5000, debug=os.getenv("FLASK_DEBUG") == "1")
