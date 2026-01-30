from flask import *
from urllib.parse import quote, urlparse, parse_qs
import re
import os
import json
from datetime import timedelta, datetime
from functools import wraps
import secrets
from authlib.integrations.flask_client import OAuth
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from dotenv import load_dotenv

load_dotenv()
import mailer


app = Flask(__name__)


app.secret_key = os.getenv("FLASK_SECRET_KEY", "AW_r%@jN*HU4AW_r%@jN*HU4AW_r%@jN*HU4")
WHATSAPP_NUMBER = os.getenv("WHATSAPP_NUMBER", "+254752370545")
ADMIN_USERS = {
    name.strip()
    for name in os.getenv("ADMIN_USERS", "myvpn").split(",")
    if name.strip()
}


UPLOAD_FOLDER = os.path.join("static", "images")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_SESSION_SECURE", "0") == "1"
remember_days_env = os.getenv("REMEMBER_ME_DAYS", "30")
try:
    remember_days = int(remember_days_env)
except ValueError:
    remember_days = 30
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=remember_days)

oauth = OAuth(app)
oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def image_url(path):
    if not path:
        return url_for("static", filename="images/logo.jpeg")
    try:
        path = path.decode("utf-8")
    except AttributeError:
        path = str(path)

    if path.startswith("http://") or path.startswith("https://"):
        return path

    path = path.lstrip("/")
    if path.startswith("static/"):
        path = path[len("static/") :]

    if not path.startswith("images/"):
        path = f"images/{path}"

    return url_for("static", filename=path)

def _row_at(row, idx, default=None):
    if row is None:
        return default
    if isinstance(row, dict):
        try:
            return list(row.values())[idx]
        except Exception:
            return default
    try:
        return row[idx]
    except Exception:
        return default


def _is_safe_url(target):
    if not target:
        return False
    try:
        ref = urlparse(request.host_url)
        test = urlparse(target)
        return (
            test.scheme in ("http", "https", "")
            and ref.netloc == test.netloc
        )
    except Exception:
        return False


def _remember_next_url():
    next_param = request.args.get("next", "")
    candidate = next_param or (request.referrer or "")
    if not _is_safe_url(candidate): 
        return 
    path = urlparse(candidate).path or ""
    if path in ("/signin", "/signup"):
        return
    session["next_url"] = candidate


def _pop_next_url():
    next_url = session.pop("next_url", None)
    if not _is_safe_url(next_url):
        return None
    path = urlparse(next_url).path or ""
    if path in ("/signin", "/signup"):
        return None
    return next_url


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        app.static_folder,
        "favicon.ico",
        mimetype="image/x-icon",
    )

def _parse_db_url(db_url: str) -> dict:
    parsed = urlparse(db_url)
    if parsed.scheme not in {"mysql", "mariadb"}:
        raise ValueError("Unsupported database URL scheme")
    database = parsed.path.lstrip("/")
    query = parse_qs(parsed.query)
    return {
        "host": parsed.hostname,
        "user": parsed.username,
        "password": parsed.password,
        "database": database,
        "port": parsed.port or 3306,
        "query": query,
    }


def get_db_connection():
    db_url = os.getenv("DATABASE_URL") or os.getenv("MYSQL_URL") or os.getenv("DB_URL")
    if db_url:
        try:
            cfg = _parse_db_url(db_url)
        except Exception as exc:
            raise RuntimeError(f"Invalid DATABASE_URL/MYSQL_URL: {exc}") from exc
        host = cfg["host"]
        user = cfg["user"]
        password = cfg["password"]
        database = cfg["database"]
        port = int(cfg["port"])
        query = cfg["query"]
    else:
        host = os.getenv("DB_HOST")
        user = os.getenv("DB_USER")
        password = os.getenv("DB_PASSWORD")
        database = os.getenv("DB_NAME")
        port = int(os.getenv("DB_PORT", "3306"))
        query = {}

    if not host:
        raise RuntimeError("Database host is not set (DB_HOST or DATABASE_URL).")

    ssl_disabled = os.getenv("DB_SSL_DISABLED", "0") == "1"
    sslmode = (query.get("sslmode") or [""])[0].lower()
    ssl_query = (query.get("ssl") or [""])[0].lower()
    if sslmode == "disable" or ssl_query in {"0", "false", "no"}:
        ssl_disabled = True

    connect_kwargs = dict(
        host=host,
        user=user,
        password=password,
        database=database,
        port=port,
        connect_timeout=10,
        read_timeout=10,
        write_timeout=10,
    )
    if not ssl_disabled:
        connect_kwargs["ssl"] = {"ssl": {}}

    try:
        return pymysql.connect(**connect_kwargs)
    except pymysql.err.OperationalError as exc:
        hint = ""
        if host.endswith(".railway.internal"):
            hint = (
                " The host looks like a Railway internal address. "
                "Use the public MySQL host/port (or DATABASE_URL) when deploying outside Railway."
            )
        raise pymysql.err.OperationalError(
            exc.args[0], f"{exc.args[1]}{hint}"
        ) from exc


def _scalar(cur, query, params=None, default=0):
    try:
        cur.execute(query, params or ())
        row = cur.fetchone()
        if not row:
            return default
        value = _row_at(row, 0, default)
        return default if value is None else value
    except Exception:
        return default

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            session["next_url"] = url_for("upload")
            return redirect(url_for("signin"))
        return view(*args, **kwargs)
    return wrapped



def verify_password(stored_password, provided_password):
    if stored_password is None or provided_password is None:
        return False, False

    # Hashed password path
    try:
        if check_password_hash(stored_password, provided_password):
            return True, False
    except (ValueError, TypeError):
        pass

    # Legacy plaintext fallback
    if stored_password == provided_password:
        return True, True

    return False, False


def send_login_notifications(user_name, user_email, user_phone):
    if user_phone and validate_phone_number(user_phone):
        try:
            import sms
            sms.send_sms(user_phone, f"Hi {user_name}, you have successfully signed in to Bigoh.")
        except Exception:
            pass

    if user_email and validate_email_format(user_email):
        try:
            forwarded = request.headers.get("X-Forwarded-For", "")
            ip_addr = forwarded.split(",")[0].strip() if forwarded else request.remote_addr
            subject, text_body, html_body = mailer.build_signin_email(
                user_name, ip=ip_addr
            )
            mailer.send_email(user_email, subject, text_body, html_body)
        except Exception:
            pass


def validate_password_strength(password):
    if password is None:
        return "Password is required."
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if re.search(r"(.)\1\1", password):
        return "Password cannot contain more than 2 identical characters in a row."

    category_count = 0
    if re.search(r"[a-z]", password):
        category_count += 1
    if re.search(r"[A-Z]", password):
        category_count += 1
    if re.search(r"[0-9]", password):
        category_count += 1
    if re.search(r"[^A-Za-z0-9]", password):
        category_count += 1
    if category_count < 3:
        return "Password must include at least 3 of: lowercase, uppercase, numbers, special characters."
    return None


EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def validate_email_format(email: str) -> bool:
    if not email:
        return False
    if len(email) > 254:
        return False
    if " " in email:
        return False
    if email.count("@") != 1:
        return False
    local_part, domain = email.split("@", 1)
    if not local_part or not domain:
        return False
    if ".." in local_part or ".." in domain:
        return False
    return bool(EMAIL_REGEX.match(email))


def normalize_phone_number(phone: str) -> str:
    if not phone:
        return ""
    cleaned = re.sub(r"[\s\-().]", "", phone)
    if cleaned.startswith("+"):
        digits = cleaned[1:]
        prefix = "+"
    else:
        digits = cleaned
        prefix = ""
    if not digits.isdigit():
        return ""
    if len(digits) < 10 or len(digits) > 15:
        return ""
    return f"{prefix}{digits}"


def validate_phone_number(phone: str) -> bool:
    return bool(normalize_phone_number(phone))


EMAIL_TOKEN_TTL = timedelta(hours=24)
PHONE_OTP_TTL = timedelta(minutes=10)
OTP_MAX_ATTEMPTS = 5
RESET_OTP_TTL = timedelta(minutes=1)
RESET_OTP_MAX_ATTEMPTS = 5


def _now_utc():
    return datetime.utcnow()


def _schema_cache_key(table: str, column: str) -> str:
    return f"SCHEMA_HAS_{table.upper()}_{column.upper()}"


def table_has_column(conn, table: str, column: str) -> bool:
    cache_key = _schema_cache_key(table, column)
    cached = app.config.get(cache_key)
    if cached is not None:
        return cached
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = %s
                  AND COLUMN_NAME = %s
                """,
                (table, column),
            )
            row = cur.fetchone()
            has_col = bool(row and _row_at(row, 0, 0) > 0)
            app.config[cache_key] = has_col
            return has_col
    except Exception:
        app.config[cache_key] = False
        return False


def ensure_user_verification_schema(conn) -> bool:
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS user_verifications (
                    user_id INT PRIMARY KEY,
                    email_token VARCHAR(120) NULL,
                    email_token_expires DATETIME NULL,
                    email_sent_at DATETIME NULL,
                    phone_otp VARCHAR(10) NULL,
                    phone_otp_expires DATETIME NULL,
                    phone_sent_at DATETIME NULL,
                    phone_otp_attempts INT NOT NULL DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX (email_token),
                    INDEX (phone_otp)
                )
                """
            )

            if not table_has_column(conn, "users", "email_verified"):
                cur.execute(
                    "ALTER TABLE users ADD COLUMN email_verified TINYINT(1) NOT NULL DEFAULT 0"
                )
                app.config[_schema_cache_key("users", "email_verified")] = True
            if not table_has_column(conn, "users", "phone_verified"):
                cur.execute(
                    "ALTER TABLE users ADD COLUMN phone_verified TINYINT(1) NOT NULL DEFAULT 0"
                )
                app.config[_schema_cache_key("users", "phone_verified")] = True
            if not table_has_column(conn, "users", "email_verified_at"):
                cur.execute(
                    "ALTER TABLE users ADD COLUMN email_verified_at DATETIME NULL"
                )
                app.config[_schema_cache_key("users", "email_verified_at")] = True
            if not table_has_column(conn, "users", "phone_verified_at"):
                cur.execute(
                    "ALTER TABLE users ADD COLUMN phone_verified_at DATETIME NULL"
                )
                app.config[_schema_cache_key("users", "phone_verified_at")] = True
            if not table_has_column(conn, "user_verifications", "password_reset_otp"):
                cur.execute(
                    "ALTER TABLE user_verifications ADD COLUMN password_reset_otp VARCHAR(10) NULL"
                )
                app.config[_schema_cache_key("user_verifications", "password_reset_otp")] = True
            if not table_has_column(conn, "user_verifications", "password_reset_expires"):
                cur.execute(
                    "ALTER TABLE user_verifications ADD COLUMN password_reset_expires DATETIME NULL"
                )
                app.config[_schema_cache_key("user_verifications", "password_reset_expires")] = True
            if not table_has_column(conn, "user_verifications", "password_reset_attempts"):
                cur.execute(
                    "ALTER TABLE user_verifications ADD COLUMN password_reset_attempts INT NOT NULL DEFAULT 0"
                )
                app.config[_schema_cache_key("user_verifications", "password_reset_attempts")] = True

        conn.commit()
        return True
    except Exception:
        return False


def generate_email_token() -> str:
    return secrets.token_urlsafe(32)


def generate_phone_otp() -> str:
    return f"{secrets.randbelow(1000000):06d}"


def ensure_user_verification_row(cur, user_id: int):
    cur.execute("INSERT IGNORE INTO user_verifications (user_id) VALUES (%s)", (user_id,))


def update_user_verification(cur, user_id: int, fields: dict):
    if not fields:
        return
    columns = ", ".join([f"{key}=%s" for key in fields.keys()])
    params = list(fields.values()) + [user_id]
    cur.execute(
        f"UPDATE user_verifications SET {columns} WHERE user_id=%s",
        params,
    )


def get_verification_state(conn, user_id: int) -> dict:
    state = {"email_verified": True, "phone_verified": True}
    if not table_has_column(conn, "users", "email_verified") or not table_has_column(
        conn, "users", "phone_verified"
    ):
        return state
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT email_verified, phone_verified FROM users WHERE id=%s",
                (user_id,),
            )
            row = cur.fetchone()
            if not row:
                return state
            state["email_verified"] = bool(_row_at(row, 0, 1))
            state["phone_verified"] = bool(_row_at(row, 1, 1))
            return state
    except Exception:
        return state


def build_verify_url(token: str) -> str:
    base = os.getenv("APP_BASE_URL", "").rstrip("/")
    if not base:
        base = request.host_url.rstrip("/")
    return f"{base}{url_for('verify_email')}?token={quote(token)}"


def send_email_verification(user_name: str, user_email: str, token: str):
    verify_url = build_verify_url(token)
    subject, text_body, html_body = mailer.build_email_verification(
        user_name, verify_url
    )
    mailer.send_email(user_email, subject, text_body, html_body)


def send_phone_otp_sms(phone: str, otp: str):
    import sms
    sms.send_sms(phone, f"Your Bigoh verification code is {otp}. It expires in 10 minutes.")


def send_password_reset_sms(phone: str, otp: str):
    import sms
    sms.send_sms(phone, f"Your Bigoh password reset code is {otp}. It expires in 1 minute.")


def send_password_reset_email(user_name: str, user_email: str, otp: str):
    subject, text_body, html_body = mailer.build_password_reset_email(
        user_name, otp
    )
    mailer.send_email(user_email, subject, text_body, html_body)


def _random_password() -> str:
    return secrets.token_urlsafe(32)


def _unique_username_from_email(conn, email: str) -> str:
    base = (email.split("@", 1)[0] or "user").strip().lower()
    base = re.sub(r"[^a-z0-9_.-]", "", base) or "user"
    candidate = base
    with conn.cursor() as cur:
        suffix = 0
        while True:
            cur.execute("SELECT 1 FROM users WHERE username=%s LIMIT 1", (candidate,))
            if not cur.fetchone():
                return candidate
            suffix += 1
            candidate = f"{base}{suffix}"



def set_site_message(message, level="warning"):
    session["site_message"] = message
    session["site_message_level"] = level


def users_has_is_admin():
    cached = app.config.get("USERS_HAS_IS_ADMIN")
    if cached is not None:
        return cached

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = 'users'
                  AND COLUMN_NAME = 'is_admin'
                """
            )
            row = cur.fetchone()
            has_col = bool(row and _row_at(row, 0, 0) > 0)
            app.config["USERS_HAS_IS_ADMIN"] = has_col
            return has_col
    except Exception:
        app.config["USERS_HAS_IS_ADMIN"] = False
        return False
    finally:
        conn.close()


def orders_has_reference():
    cached = app.config.get("ORDERS_HAS_REFERENCE")
    if cached is not None:
        return cached

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = 'orders'
                  AND COLUMN_NAME = 'order_reference'
                """
            )
            row = cur.fetchone()
            has_col = bool(row and _row_at(row, 0, 0) > 0)
            app.config["ORDERS_HAS_REFERENCE"] = has_col
            return has_col
    except Exception:
        app.config["ORDERS_HAS_REFERENCE"] = False
        return False
    finally:
        conn.close()


def ensure_reviews_table(cur):
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS product_reviews (
                id INT AUTO_INCREMENT PRIMARY KEY,
                product_id INT NOT NULL,
                user_name VARCHAR(80) NOT NULL,
                rating INT NOT NULL,
                comment TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_seed TINYINT(1) NOT NULL DEFAULT 0,
                INDEX (product_id)
            )
            """
        )
        return True
    except Exception:
        return False


def seed_sample_reviews(cur):
    # Samples disabled: do not auto-insert seed reviews.
    return False
    try:
        cur.execute("SELECT COUNT(*) FROM product_reviews")
        row = cur.fetchone()
        if row and _row_at(row, 0, 0) > 0:
            return False

        cur.execute("SELECT product_id FROM products ORDER BY product_id DESC LIMIT 4")
        product_rows = cur.fetchall() or []
        product_ids = [_row_at(r, 0) for r in product_rows]
        if not product_ids:
            return False

        samples = [
            ("Sample review: Delivery was quick and the quality is impressive.", 5),
            ("Sample review: Looks great in person, feels premium for the price.", 4),
            ("Sample review: Packaging was neat and the item matched the photos.", 5),
            ("Sample review: Good value and comfortable to use daily.", 4),
            ("Sample review: Nice finish and solid build, will order again.", 5),
            ("Sample review: Clean design, would recommend to friends.", 4),
        ]
        data = []
        for idx, pid in enumerate(product_ids):
            base = idx * 2
            for offset in range(2):
                text, rating = samples[(base + offset) % len(samples)]
                data.append((pid, f"Sample Buyer {idx + offset + 1}", rating, text, 1))

        if data:
            cur.executemany(
                """
                INSERT INTO product_reviews
                (product_id, user_name, rating, comment, is_seed)
                VALUES (%s, %s, %s, %s, %s)
                """,
                data,
            )
        return True
    except Exception:
        return False


def get_product_reviews(conn, product_id):
    reviews = []
    avg_rating = 0.0
    review_count = 0
    has_seed = False
    try:
        with conn.cursor() as cur:
            if not ensure_reviews_table(cur):
                return reviews, avg_rating, review_count, has_seed
            conn.commit()

            cur.execute(
                """
                SELECT user_name, rating, comment, created_at, is_seed
                FROM product_reviews
                WHERE product_id = %s AND is_seed = 0
                ORDER BY created_at DESC, id DESC
                """,
                (product_id,),
            )
            reviews = cur.fetchall() or []
            cur.execute(
                """
                SELECT
                    AVG(rating),
                    COUNT(*)
                FROM product_reviews
                WHERE product_id = %s AND is_seed = 0
                """,
                (product_id,),
            )
            row = cur.fetchone()
            avg_rating = float(_row_at(row, 0, 0) or 0)
            review_count = int(_row_at(row, 1, 0) or 0)
    except Exception:
        return reviews, avg_rating, review_count, has_seed

    return reviews, avg_rating, review_count, has_seed


def get_ratings_for_products(conn, product_ids):
    if not product_ids:
        return {}
    try:
        with conn.cursor() as cur:
            if not ensure_reviews_table(cur):
                return {}
            conn.commit()

            ids = sorted({int(pid) for pid in product_ids if pid is not None})
            if not ids:
                return {}

            placeholders = ", ".join(["%s"] * len(ids))
            cur.execute(
                f"""
                SELECT
                    product_id,
                    AVG(rating),
                    COUNT(*)
                FROM product_reviews
                WHERE is_seed = 0 AND product_id IN ({placeholders})
                GROUP BY product_id
                """,
                tuple(ids),
            )
            rows = cur.fetchall() or []
            rating_map = {}
            for row in rows:
                pid = int(_row_at(row, 0, 0))
                avg_rating = float(_row_at(row, 1, 0) or 0)
                count_rating = int(_row_at(row, 2, 0) or 0)
                rating_map[pid] = {
                    "avg": round(avg_rating, 1),
                    "count": count_rating,
                }
            return rating_map
    except Exception:
        return {}


def ensure_flash_sale_tables(cur):
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS flash_sale_settings (
                id INT PRIMARY KEY,
                is_active TINYINT(1) NOT NULL DEFAULT 0,
                duration_seconds INT NOT NULL DEFAULT 0,
                ends_at DATETIME NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS flash_sale_items (
                product_id INT PRIMARY KEY,
                is_active TINYINT(1) NOT NULL DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute("SELECT COUNT(*) FROM flash_sale_settings WHERE id = 1")
        row = cur.fetchone()
        if not row or _row_at(row, 0, 0) == 0:
            cur.execute(
                """
                INSERT INTO flash_sale_settings (id, is_active, duration_seconds, ends_at)
                VALUES (1, 0, 0, NULL)
                """
            )
        return True
    except Exception:
        return False


def format_duration(seconds):
    try:
        seconds = int(seconds or 0)
    except (TypeError, ValueError):
        seconds = 0
    if seconds < 0:
        seconds = 0
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours:02d}h : {minutes:02d}m : {secs:02d}s"


def get_flash_sale_state(conn):
    state = {
        "active": False,
        "duration_seconds": 0,
        "seconds_left": 0,
        "items": [],
    }
    try:
        with conn.cursor() as cur:
            if not ensure_flash_sale_tables(cur):
                return state
            conn.commit()

            cur.execute(
                "SELECT is_active, duration_seconds, ends_at FROM flash_sale_settings WHERE id = 1"
            )
            row = cur.fetchone()
            is_active = bool(_row_at(row, 0, 0)) if row else False
            duration_seconds = int(_row_at(row, 1, 0) or 0) if row else 0
            ends_at = _row_at(row, 2, None) if row else None

            now = datetime.now()
            if is_active and duration_seconds <= 0:
                is_active = False
            if is_active and duration_seconds > 0 and ends_at is None:
                ends_at = now + timedelta(seconds=duration_seconds)
                cur.execute(
                    "UPDATE flash_sale_settings SET ends_at=%s WHERE id=1",
                    (ends_at,),
                )
                conn.commit()

            seconds_left = 0
            if is_active and ends_at:
                seconds_left = int((ends_at - now).total_seconds())
                if seconds_left <= 0:
                    is_active = False
                    seconds_left = 0
                    cur.execute(
                        "UPDATE flash_sale_settings SET is_active=0, ends_at=NULL WHERE id=1"
                    )
                    conn.commit()

            items = []
            if is_active:
                cur.execute(
                    """
                    SELECT p.*
                    FROM flash_sale_items f
                    JOIN products p ON f.product_id = p.product_id
                    WHERE f.is_active = 1
                    ORDER BY p.product_id DESC
                    """
                )
                items = cur.fetchall() or []

            state = {
                "active": is_active,
                "duration_seconds": duration_seconds,
                "seconds_left": seconds_left,
                "items": items,
            }
    except Exception:
        return state

    return state

@app.context_processor
def cart_count():
    cart = session.get("cart", {})
    total_items = sum(cart.values())
    msg = session.pop("site_message", None)
    msg_level = session.pop("site_message_level", "warning")
    return dict(
        cart_count=total_items,
        site_message=msg,
        site_message_level=msg_level,
        image_url=image_url,
    )



def get_product(product_id):
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    connection.close()
    return product



# Default Home route
@app.route("/")
def home():
    connection = get_db_connection()

    sql1 = "SELECT * FROM products WHERE category = 'Men Watch'"
    cursor = connection.cursor()
    cursor.execute(sql1)
    watches = cursor.fetchall()

    sql2 = "SELECT * FROM products WHERE category = 'Ladies Watch'"
    cursor = connection.cursor()
    cursor.execute(sql2)
    ladies = cursor.fetchall()

    sql3 = "SELECT * FROM products WHERE category = 'Jersey'"
    cursor = connection.cursor()
    cursor.execute(sql3)
    jersey = cursor.fetchall()

    sql4 = "SELECT * FROM products WHERE category = 'Cleaning'"
    cursor = connection.cursor()
    cursor.execute(sql4)
    foam = cursor.fetchall()

    sql5 = "SELECT * FROM products ORDER BY RAND() LIMIT 10"
    cursor = connection.cursor()
    cursor.execute(sql5)
    new_products = cursor.fetchall()

    flash_state = get_flash_sale_state(connection)
    flash_sales = flash_state["items"]
    flash_sale_active = flash_state["active"]
    flash_sale_seconds = flash_state["seconds_left"]
    flash_sale_time_label = format_duration(flash_sale_seconds if flash_sale_active else 0)
    flash_sale_duration_seconds = flash_state["duration_seconds"]

    rating_ids = []
    for group in (watches, ladies, jersey, foam, new_products, flash_sales):
        rating_ids.extend([_row_at(row, 0) for row in group] if group else [])
    ratings = get_ratings_for_products(connection, rating_ids)

    connection.close()

    return render_template(
        "home.html",
        watches=watches,
        ladies=ladies,
        jersey=jersey,
        foam=foam,
        new_products=new_products,
        flash_sales=flash_sales,
        flash_sale_active=flash_sale_active,
        flash_sale_seconds=flash_sale_seconds,
        flash_sale_time_label=flash_sale_time_label,
        flash_sale_duration_seconds=flash_sale_duration_seconds,
        ratings=ratings,
    )


#Single_item route
@app.route("/single_item/<product_id>")
def single(product_id):
    connection = get_db_connection()
    try:
        sql = "SELECT * FROM products WHERE product_id = %s"
        cursor1 = connection.cursor()
        cursor1.execute(sql, (product_id,))
        product = cursor1.fetchone()
        if not product:
            return redirect(url_for("home"))

        reviews, avg_rating, review_count, has_seed = get_product_reviews(
            connection, product_id
        )
    finally:
        connection.close()

    avg_rating = round(avg_rating, 1)
    avg_rating_int = int(round(avg_rating))

    return render_template(
        "single.html",
        product=product,
        reviews=reviews,
        avg_rating=avg_rating,
        avg_rating_int=avg_rating_int,
        review_count=review_count,
        has_seed=has_seed,
    )


@app.route("/product/<int:product_id>/review", methods=["POST"])
def add_product_review(product_id):
    if not session.get("key"):
        session["next_url"] = url_for("single", product_id=product_id)
        return redirect(url_for("signin"))

    name = session.get("key", "").strip()
    comment = request.form.get("comment", "").strip()
    try:
        rating = int(request.form.get("rating", "0"))
    except ValueError:
        rating = 0

    if not name or not comment or rating not in {1, 2, 3, 4, 5}:
        return redirect(url_for("single", product_id=product_id, review="error"))

    if len(comment) > 500:
        comment = comment[:500]

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            if not ensure_reviews_table(cur):
                return redirect(url_for("single", product_id=product_id, review="error"))

            cur.execute("SELECT product_id FROM products WHERE product_id = %s", (product_id,))
            if not cur.fetchone():
                return redirect(url_for("home"))

            cur.execute(
                """
                INSERT INTO product_reviews (product_id, user_name, rating, comment, is_seed)
                VALUES (%s, %s, %s, %s, 0)
                """,
                (product_id, name, rating, comment),
            )
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("single", product_id=product_id, review="ok"))


# Signup route
@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        next_from_form = request.form.get("next", "")
        if _is_safe_url(next_from_form):
            session["next_url"] = next_from_form
        try:
            username = request.form['username']
            email = request.form.get('email', '').strip().lower()
            phone_raw = request.form.get('phone', '').strip()
            phone = normalize_phone_number(phone_raw)
            password1 = request.form['password1']
            password2 = request.form['password2']
            strength_error = validate_password_strength(password1)
            if strength_error:
                return render_template('signup.html', error=strength_error)

            if password1 != password2:
                return render_template('signup.html', error='Password Do Not Match')

            if not email or not validate_email_format(email):
                return render_template('signup.html', error='Please enter a valid email address.', error_field="email")

            if not phone:
                return render_template('signup.html', error='Please enter a valid phone number.', error_field="phone")

            connection = get_db_connection()
            cursor = connection.cursor()
            try:
                ensure_user_verification_schema(connection)
                cursor.execute("SELECT 1 FROM users WHERE email = %s LIMIT 1", (email,))
                if cursor.fetchone():
                    connection.close()
                    return render_template('signup.html', error='Email already registered. Please sign in.', error_field="email")
                cursor.execute("SELECT 1 FROM users WHERE username = %s LIMIT 1", (username,))
                if cursor.fetchone():
                    connection.close()
                    return render_template('signup.html', error='Username already taken. Please choose another.', error_field="username")
            except Exception:
                connection.close()
                return render_template('signup.html', error='Unable to validate account details. Please try again.')

            hashed_password = generate_password_hash(password1)

            if users_has_is_admin():
                sql = ''' 
                     insert into users(username, password, email, phone, is_admin) 
                     values(%s, %s, %s, %s, %s)
                 '''
                cursor.execute(sql, (username, hashed_password, email, phone, 0))
            else:
                sql = ''' 
                     insert into users(username, password, email, phone) 
                     values(%s, %s, %s, %s)
                 '''
                cursor.execute(sql, (username, hashed_password, email, phone))

            try:
                connection.commit()
            except pymysql.err.IntegrityError:
                connection.close()
                return render_template('signup.html', error='Email or username already registered.', error_field="both")

            try:
                user_id = cursor.lastrowid
                now = _now_utc()
                email_token = generate_email_token()
                phone_otp = generate_phone_otp()
                with connection.cursor() as ver_cur:
                    ensure_user_verification_row(ver_cur, user_id)
                    update_user_verification(
                        ver_cur,
                        user_id,
                        {
                            "email_token": email_token,
                            "email_token_expires": now + EMAIL_TOKEN_TTL,
                            "email_sent_at": now,
                            "phone_otp": phone_otp,
                            "phone_otp_expires": now + PHONE_OTP_TTL,
                            "phone_sent_at": now,
                            "phone_otp_attempts": 0,
                        },
                    )
                connection.commit()
            except Exception:
                connection.close()
                return render_template('signup.html', error='Signup failed. Please try again.')

            try:
                if validate_phone_number(phone):
                    send_phone_otp_sms(phone, phone_otp)
            except Exception:
                pass
            try:
                if validate_email_format(email):
                    send_email_verification(username, email, email_token)
            except Exception:
                pass

            session["verify_user_id"] = user_id
            session["verify_email"] = email
            session["verify_phone"] = phone
            set_site_message(
                "We sent a verification link to your email and a code to your phone.",
                "info",
            )
            return redirect(url_for("verify_phone"))
        except Exception:
            app.logger.exception("Signup error")
            return render_template('signup.html', error='Signup failed. Please try again.')
        
    else:
        _remember_next_url()
        return render_template('signup.html', next_url=session.get("next_url", ""))
    

@app.route('/verify-email', methods=['GET'])
def verify_email():
    token = request.args.get("token", "").strip()
    if not token:
        set_site_message("Invalid verification link.", "danger")
        return redirect(url_for("signin"))

    connection = get_db_connection()
    try:
        ensure_user_verification_schema(connection)
        with connection.cursor() as cur:
            cur.execute(
                """
                SELECT v.user_id, v.email_token_expires, u.email, u.phone
                FROM user_verifications v
                JOIN users u ON u.id = v.user_id
                WHERE v.email_token = %s
                """,
                (token,),
            )
            row = cur.fetchone()
            if not row:
                set_site_message("Verification link is invalid or already used.", "danger")
                return redirect(url_for("signin"))
            user_id = _row_at(row, 0)
            expires_at = _row_at(row, 1)
            user_email = _row_at(row, 2, "")
            user_phone = _row_at(row, 3, "")
            if expires_at and expires_at < _now_utc():
                session["verify_user_id"] = user_id
                session["verify_email"] = user_email
                session["verify_phone"] = user_phone
                set_site_message("Verification link has expired. Please request a new one.", "warning")
                return redirect(url_for("verify_phone"))

            cur.execute(
                """
                UPDATE users
                SET email_verified = 1, email_verified_at = %s
                WHERE id = %s
                """,
                (_now_utc(), user_id),
            )
            cur.execute(
                """
                UPDATE user_verifications
                SET email_token = NULL, email_token_expires = NULL
                WHERE user_id = %s
                """,
                (user_id,),
            )
        connection.commit()
    except Exception:
        set_site_message("Unable to verify email. Please try again.", "danger")
        return redirect(url_for("signin"))
    finally:
        connection.close()

    session["verify_user_id"] = user_id
    session["verify_email"] = user_email
    session["verify_phone"] = user_phone

    connection = get_db_connection()
    try:
        verification = get_verification_state(connection, user_id)
    finally:
        connection.close()

    if verification.get("phone_verified"):
        set_site_message("Email verified. You can now sign in.", "success")
        session.pop("verify_user_id", None)
        session.pop("verify_email", None)
        session.pop("verify_phone", None)
        return redirect(url_for("signin"))

    set_site_message("Email verified. Please verify your phone.", "info")
    return redirect(url_for("verify_phone"))


@app.route('/verify-phone', methods=['GET', 'POST'])
def verify_phone():
    user_id = session.get("verify_user_id") or session.get("username")
    if not user_id:
        set_site_message("Please sign in to verify your account.", "warning")
        return redirect(url_for("signin"))

    if request.method == 'GET':
        connection = get_db_connection()
        try:
            ensure_user_verification_schema(connection)
            verification = get_verification_state(connection, user_id)
            if verification.get("email_verified") and verification.get("phone_verified"):
                set_site_message("Your account is already verified.", "info")
                return redirect(url_for("signin"))
        finally:
            connection.close()

    if request.method == 'POST':
        otp = (request.form.get("otp") or "").strip()
        if not otp:
            return render_template('verify_phone.html', error="Please enter the verification code.")

        connection = get_db_connection()
        try:
            ensure_user_verification_schema(connection)
            with connection.cursor() as cur:
                cur.execute(
                    """
                    SELECT phone_otp, phone_otp_expires, phone_otp_attempts
                    FROM user_verifications
                    WHERE user_id = %s
                    """,
                    (user_id,),
                )
                row = cur.fetchone()
                if not row:
                    return render_template('verify_phone.html', error="Verification code not found. Please resend.")
                code = _row_at(row, 0, "")
                expires_at = _row_at(row, 1)
                attempts = int(_row_at(row, 2, 0) or 0)
                if attempts >= OTP_MAX_ATTEMPTS:
                    return render_template('verify_phone.html', error="Too many attempts. Please resend a new code.")
                if expires_at and expires_at < _now_utc():
                    return render_template('verify_phone.html', error="Verification code has expired. Please resend.")
                if otp != code:
                    attempts += 1
                    update_user_verification(
                        cur,
                        user_id,
                        {"phone_otp_attempts": attempts},
                    )
                    connection.commit()
                    return render_template('verify_phone.html', error="Incorrect code. Please try again.")

                cur.execute(
                    """
                    UPDATE users
                    SET phone_verified = 1, phone_verified_at = %s
                    WHERE id = %s
                    """,
                    (_now_utc(), user_id),
                )
                update_user_verification(
                    cur,
                    user_id,
                    {
                        "phone_otp": None,
                        "phone_otp_expires": None,
                        "phone_otp_attempts": 0,
                    },
                )
            connection.commit()
        except Exception:
            return render_template('verify_phone.html', error="Unable to verify phone. Please try again.")
        finally:
            connection.close()

        set_site_message("Phone verified. You can now sign in.", "success")
        session.pop("verify_user_id", None)
        session.pop("verify_email", None)
        session.pop("verify_phone", None)
        return redirect(url_for("signin"))

    return render_template('verify_phone.html')


@app.route('/verify/resend', methods=['POST'])
def resend_verification():
    user_id = session.get("verify_user_id") or session.get("username")
    if not user_id:
        set_site_message("Please sign in to resend verification.", "warning")
        return redirect(url_for("signin"))

    connection = get_db_connection()
    try:
        ensure_user_verification_schema(connection)
        verification = get_verification_state(connection, user_id)
        with connection.cursor() as cur:
            cur.execute(
                "SELECT username, email, phone FROM users WHERE id=%s",
                (user_id,),
            )
            user_row = cur.fetchone() or ()
            user_name = _row_at(user_row, 0, "Customer")
            user_email = _row_at(user_row, 1, "")
            user_phone = _row_at(user_row, 2, "")
            session["verify_email"] = user_email
            session["verify_phone"] = user_phone

            ensure_user_verification_row(cur, user_id)
            now = _now_utc()
            email_token = None
            phone_otp = None
            if not verification.get("email_verified"):
                email_token = generate_email_token()
                update_user_verification(
                    cur,
                    user_id,
                    {
                        "email_token": email_token,
                        "email_token_expires": now + EMAIL_TOKEN_TTL,
                        "email_sent_at": now,
                    },
                )
            if not verification.get("phone_verified"):
                phone_otp = generate_phone_otp()
                update_user_verification(
                    cur,
                    user_id,
                    {
                        "phone_otp": phone_otp,
                        "phone_otp_expires": now + PHONE_OTP_TTL,
                        "phone_sent_at": now,
                        "phone_otp_attempts": 0,
                    },
                )
        connection.commit()
    except Exception:
        set_site_message("Unable to resend verification right now.", "danger")
        return redirect(url_for("verify_phone"))
    finally:
        connection.close()

    try:
        if email_token and validate_email_format(user_email or ""):
            send_email_verification(user_name, user_email, email_token)
    except Exception:
        pass
    try:
        if phone_otp and validate_phone_number(user_phone or ""):
            send_phone_otp_sms(user_phone, phone_otp)
    except Exception:
        pass

    set_site_message("Verification messages sent.", "info")
    return redirect(url_for("verify_phone"))


@app.route('/add-phone', methods=['GET', 'POST'])
def add_phone():
    user_id = session.get("pending_user_id")
    if not user_id:
        set_site_message("Please sign in to continue.", "warning")
        return redirect(url_for("signin"))

    if request.method == 'POST':
        phone_raw = (request.form.get("phone") or "").strip()
        phone = normalize_phone_number(phone_raw)
        if not phone:
            return render_template('add_phone.html', error="Please enter a valid phone number.")

        connection = get_db_connection()
        try:
            ensure_user_verification_schema(connection)
            with connection.cursor() as cur:
                cur.execute("UPDATE users SET phone=%s WHERE id=%s", (phone, user_id))
                now = _now_utc()
                phone_otp = generate_phone_otp()
                ensure_user_verification_row(cur, user_id)
                update_user_verification(
                    cur,
                    user_id,
                    {
                        "phone_otp": phone_otp,
                        "phone_otp_expires": now + PHONE_OTP_TTL,
                        "phone_sent_at": now,
                        "phone_otp_attempts": 0,
                    },
                )
            connection.commit()
        except Exception:
            return render_template('add_phone.html', error="Unable to save phone number. Please try again.")
        finally:
            connection.close()

        try:
            send_phone_otp_sms(phone, phone_otp)
        except Exception:
            pass

        session["verify_user_id"] = user_id
        session["verify_phone"] = phone
        session.pop("pending_user_id", None)
        set_site_message("We sent a verification code to your phone.", "info")
        return redirect(url_for("verify_phone"))

    return render_template('add_phone.html')


@app.route('/login/google')
def login_google():
    if not os.getenv("GOOGLE_CLIENT_ID") or not os.getenv("GOOGLE_CLIENT_SECRET"):
        set_site_message("Google sign-in is not configured yet.", "warning")
        return redirect(url_for("signin"))

    remember_me = request.args.get("remember") == "1"
    session["google_remember_me"] = remember_me
    _remember_next_url()
    redirect_uri = url_for("auth_google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/auth/google/callback')
def auth_google_callback():
    try:
        token = oauth.google.authorize_access_token()
    except Exception:
        set_site_message("Google sign-in failed. Please try again.", "danger")
        return redirect(url_for("signin"))

    userinfo = token.get("userinfo")
    if not userinfo:
        try:
            userinfo = oauth.google.userinfo()
        except Exception:
            userinfo = None

    if not userinfo:
        set_site_message("Unable to read Google profile.", "danger")
        return redirect(url_for("signin"))

    email = (userinfo.get("email") or "").strip().lower()
    email_verified = bool(userinfo.get("email_verified"))
    display_name = (userinfo.get("name") or "").strip() or email.split("@", 1)[0]

    if not email or not validate_email_format(email):
        set_site_message("Google account email is invalid.", "danger")
        return redirect(url_for("signin"))

    connection = get_db_connection()
    try:
        ensure_user_verification_schema(connection)
        with connection.cursor() as cur:
            cur.execute(
                "SELECT id, username, email, phone FROM users WHERE email=%s LIMIT 1",
                (email,),
            )
            row = cur.fetchone()
            if row:
                user_id = _row_at(row, 0)
                username = _row_at(row, 1, display_name)
                phone = _row_at(row, 3, "") or ""
            else:
                username = _unique_username_from_email(connection, email)
                password_hash = generate_password_hash(_random_password())
                if users_has_is_admin():
                    cur.execute(
                        """
                        INSERT INTO users (username, password, email, phone, is_admin, email_verified, email_verified_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            username,
                            password_hash,
                            email,
                            "",
                            0,
                            1 if email_verified else 0,
                            _now_utc() if email_verified else None,
                        ),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO users (username, password, email, phone, email_verified, email_verified_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (
                            username,
                            password_hash,
                            email,
                            "",
                            1 if email_verified else 0,
                            _now_utc() if email_verified else None,
                        ),
                    )
                user_id = cur.lastrowid
                phone = ""
            connection.commit()
    except Exception:
        set_site_message("Unable to complete Google sign-in.", "danger")
        return redirect(url_for("signin"))
    finally:
        connection.close()

    # Always skip phone verification for Google accounts.
    try:
        connection = get_db_connection()
        ensure_user_verification_schema(connection)
        with connection.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET phone_verified = 1,
                    phone_verified_at = COALESCE(phone_verified_at, %s)
                WHERE id = %s
                """,
                (_now_utc(), user_id),
            )
        connection.commit()
    except Exception:
        pass
    finally:
        try:
            connection.close()
        except Exception:
            pass

    if not email_verified:
        token = None
        try:
            connection = get_db_connection()
            ensure_user_verification_schema(connection)
            with connection.cursor() as cur:
                now = _now_utc()
                token = generate_email_token()
                ensure_user_verification_row(cur, user_id)
                update_user_verification(
                    cur,
                    user_id,
                    {
                        "email_token": token,
                        "email_token_expires": now + EMAIL_TOKEN_TTL,
                        "email_sent_at": now,
                    },
                )
            connection.commit()
        except Exception:
            pass
        finally:
            if connection:
                connection.close()
        try:
            send_email_verification(username, email, token)
        except Exception:
            pass
        session["verify_user_id"] = user_id
        session["verify_email"] = email
        set_site_message("Please verify your email to continue.", "warning")
        return redirect(url_for("verify_phone"))

    session.clear()
    remember_me = session.pop("google_remember_me", False)
    session.permanent = remember_me
    session["key"] = username
    session["username"] = user_id
    session["remember_me"] = remember_me
    session["is_admin"] = username in ADMIN_USERS
    session.pop("pending_user_id", None)

    next_url = _pop_next_url()
    return redirect(next_url or url_for("home"))

#Signin route
@app.route('/signin', methods=['POST', 'GET'])
def signin():
    if request.method == 'POST':
        next_from_form = request.form.get("next", "")
        if _is_safe_url(next_from_form):
            session["next_url"] = next_from_form
        username = request.form['username']
        password = request.form['password']
        remember_me = request.form.get("remember_me") == "1"

        connection = get_db_connection()

        has_admin_col = users_has_is_admin()
        if has_admin_col:
            sql = '''
               select id, username, password, email, phone, is_admin from users where username = %s
            '''
        else:
            sql = '''
               select * from users where username = %s
            '''
        cursor = connection.cursor()
        identifier = (username or "").strip()
        email_identifier = identifier.lower()
        phone_identifier = normalize_phone_number(identifier)
        if has_admin_col:
            sql = '''
               select id, username, password, email, phone, is_admin
               from users
               where username = %s or email = %s or phone = %s
               limit 1
            '''
            cursor.execute(sql, (identifier, email_identifier, phone_identifier))
        else:
            sql = '''
               select * from users
               where username = %s or email = %s or phone = %s
               limit 1
            '''
            cursor.execute(sql, (identifier, email_identifier, phone_identifier))
        user = cursor.fetchone()

        if not user:
            connection.close()
            return render_template('signin.html', error='Invalid Credentials')
        else:
            stored_password = user[2] if len(user) > 2 else None
            valid, needs_update = verify_password(stored_password, password)
            if not valid:
                connection.close()
                return render_template('signin.html', error='Invalid Credentials')

            if needs_update:
                new_hash = generate_password_hash(password)
                cursor.execute("UPDATE users SET password=%s WHERE id=%s", (new_hash, user[0]))
                connection.commit()

            # assume users table columns are (id, username, password, email, phone)
            user_id = user[0]
            user_name = user[1]
            user_email = user[3] if len(user) > 3 else None
            user_phone = user[4] if len(user) > 4 else None

            connection.close()
            session.clear()
            session.permanent = remember_me
            session['key'] = user_name
            # `pay_on_delivery` expects `session['username']` to contain user id
            session['username'] = user_id
            session['remember_me'] = remember_me

            if has_admin_col:
                session["is_admin"] = bool(user[5]) or (user[1] in ADMIN_USERS)
            else:
                session["is_admin"] = (user[1] in ADMIN_USERS)

            send_login_notifications(user_name, user_email, user_phone)

            next_url = _pop_next_url()
            return redirect(next_url or url_for("home"))

    else:
        _remember_next_url()
        success = "Registered Successfully, You can Signin Now" if request.args.get("signup") == "success" else ""
        return render_template('signin.html', success=success, next_url=session.get("next_url", ""))    


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        phone_raw = (request.form.get("phone") or "").strip()
        email_raw = (request.form.get("email") or "").strip().lower()
        phone = normalize_phone_number(phone_raw)
        email = email_raw if validate_email_format(email_raw) else ""
        if not phone and not email:
            return render_template('forgot_password.html', error="Please enter a valid phone number or email.")

        connection = get_db_connection()
        user_id = None
        user_name = "Customer"
        try:
            ensure_user_verification_schema(connection)
            with connection.cursor() as cur:
                if phone:
                    cur.execute("SELECT id, username FROM users WHERE phone=%s LIMIT 1", (phone,))
                else:
                    cur.execute("SELECT id, username FROM users WHERE email=%s LIMIT 1", (email,))
                row = cur.fetchone()
                if row:
                    user_id = _row_at(row, 0)
                    user_name = _row_at(row, 1, "Customer")
                    otp = generate_phone_otp()
                    ensure_user_verification_row(cur, user_id)
                    update_user_verification(
                        cur,
                        user_id,
                        {
                            "password_reset_otp": otp,
                            "password_reset_expires": _now_utc() + RESET_OTP_TTL,
                            "password_reset_attempts": 0,
                        },
                    )
            connection.commit()
        except Exception:
            return render_template('forgot_password.html', error="Unable to start password reset. Please try again.")
        finally:
            connection.close()

        if user_id:
            try:
                if phone:
                    send_password_reset_sms(phone, otp)
                else:
                    send_password_reset_email(user_name, email, otp)
            except Exception:
                pass
            session["reset_user_id"] = user_id
            session["reset_phone"] = phone
            session["reset_email"] = email
            session["reset_channel"] = "email" if email else "phone"
        set_site_message("If that account is registered, we sent a reset code.", "info")
        return redirect(url_for("reset_password"))

    return render_template('forgot_password.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    user_id = session.get("reset_user_id")
    phone = session.get("reset_phone")
    email = session.get("reset_email")
    channel = session.get("reset_channel")
    if request.method == 'POST':
        otp = (request.form.get("otp") or "").strip()
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        if not user_id:
            return render_template('reset_password.html', error="Please request a reset code first.")

        if not otp:
            return render_template('reset_password.html', error="Please enter the reset code.")

        if password1 != password2:
            return render_template('reset_password.html', error="Passwords do not match.")

        strength_error = validate_password_strength(password1)
        if strength_error:
            return render_template('reset_password.html', error=strength_error)

        connection = get_db_connection()
        try:
            ensure_user_verification_schema(connection)
            with connection.cursor() as cur:
                cur.execute(
                    """
                    SELECT password_reset_otp, password_reset_expires, password_reset_attempts
                    FROM user_verifications
                    WHERE user_id=%s
                    """,
                    (user_id,),
                )
                row = cur.fetchone()
                if not row:
                    return render_template('reset_password.html', error="Reset code not found. Please request a new one.")
                stored_otp = _row_at(row, 0, "")
                expires_at = _row_at(row, 1)
                attempts = int(_row_at(row, 2, 0) or 0)
                if attempts >= RESET_OTP_MAX_ATTEMPTS:
                    return render_template('reset_password.html', error="Too many attempts. Please request a new code.")
                if expires_at and expires_at < _now_utc():
                    return render_template('reset_password.html', error="Reset code has expired. Please request a new one.")
                if otp != stored_otp:
                    update_user_verification(
                        cur,
                        user_id,
                        {"password_reset_attempts": attempts + 1},
                    )
                    connection.commit()
                    return render_template('reset_password.html', error="Incorrect code. Please try again.")

                new_hash = generate_password_hash(password1)
                cur.execute("UPDATE users SET password=%s WHERE id=%s", (new_hash, user_id))
                update_user_verification(
                    cur,
                    user_id,
                    {
                        "password_reset_otp": None,
                        "password_reset_expires": None,
                        "password_reset_attempts": 0,
                    },
                )
            connection.commit()
        except Exception:
            return render_template('reset_password.html', error="Unable to reset password. Please try again.")
        finally:
            connection.close()

        session.pop("reset_user_id", None)
        session.pop("reset_phone", None)
        session.pop("reset_email", None)
        session.pop("reset_channel", None)
        set_site_message("Password updated. You can now sign in.", "success")
        return redirect(url_for("signin"))

    return render_template('reset_password.html', phone=phone or "", email=email or "", channel=channel or "")


#logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/signin')



#Search route
@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    if not q:
        return render_template("search_results.html", results=[], q="")

    category_filter = request.args.get("category", "").strip()
    brand_filter = request.args.get("brand", "").strip()
    sort = request.args.get("sort", "popularity").strip()
    min_price_raw = request.args.get("min_price", "").strip()
    max_price_raw = request.args.get("max_price", "").strip()

    results = advanced_product_search(q)

    category_counts = {}
    brand_counts = {}
    for row in results:
        category = str(_row_at(row, 2, "") or "").strip()
        brand = str(_row_at(row, 3, "") or "").strip()
        if category:
            category_counts[category] = category_counts.get(category, 0) + 1
        if brand:
            brand_counts[brand] = brand_counts.get(brand, 0) + 1

    if not category_filter and not brand_filter:
        lowered = q.lower()
        brand_match = next((b for b in brand_counts.keys() if b.lower() == lowered), None)
        category_match = next((c for c in category_counts.keys() if c.lower() == lowered), None)
        if brand_match:
            brand_filter = brand_match
        elif category_match:
            category_filter = category_match
        else:
            partial_brands = [b for b in brand_counts.keys() if lowered in b.lower()]
            if len(partial_brands) == 1:
                brand_filter = partial_brands[0]
            elif partial_brands:
                # pick the brand with the most hits if multiple partial matches
                brand_filter = max(partial_brands, key=lambda b: brand_counts.get(b, 0))

    try:
        min_price = float(min_price_raw) if min_price_raw else None
    except ValueError:
        min_price = None
    try:
        max_price = float(max_price_raw) if max_price_raw else None
    except ValueError:
        max_price = None

    conn = get_db_connection()
    try:
        ratings = get_ratings_for_products(conn, [_row_at(row, 0) for row in results])
    finally:
        conn.close()

    filtered = []
    for row in results:
        if category_filter:
            category = str(_row_at(row, 2, "") or "").strip()
            if category != category_filter:
                continue
        if brand_filter:
            brand = str(_row_at(row, 3, "") or "").strip()
            if brand != brand_filter:
                continue
        price_val = _row_at(row, 4, None)
        try:
            price_val = float(price_val)
        except (TypeError, ValueError):
            price_val = None
        if min_price is not None and price_val is not None and price_val < min_price:
            continue
        if max_price is not None and price_val is not None and price_val > max_price:
            continue
        filtered.append(row)

    category_counts = {}
    brand_counts = {}
    for row in filtered:
        category = str(_row_at(row, 2, "") or "").strip()
        brand = str(_row_at(row, 3, "") or "").strip()
        if category:
            category_counts[category] = category_counts.get(category, 0) + 1
        if brand:
            brand_counts[brand] = brand_counts.get(brand, 0) + 1

    prices = []
    for row in filtered:
        price_val = _row_at(row, 4, None)
        if price_val is not None:
            try:
                prices.append(float(price_val))
            except (TypeError, ValueError):
                pass

    base_min = int(min(prices)) if prices else 0
    base_max = int(max(prices)) if prices else 0

    if min_price is None:
        min_price = base_min
    if max_price is None:
        max_price = base_max

    def _price_value(row):
        try:
            return float(_row_at(row, 4, 0) or 0)
        except (TypeError, ValueError):
            return 0

    if sort == "newest":
        filtered.sort(key=lambda r: _row_at(r, 0, 0), reverse=True)
    elif sort == "price_asc":
        filtered.sort(key=_price_value)
    elif sort == "price_desc":
        filtered.sort(key=_price_value, reverse=True)
    elif sort == "rating":
        filtered.sort(
            key=lambda r: ratings.get(_row_at(r, 0), {}).get("avg", 0),
            reverse=True,
        )

    categories = sorted(
        [{"name": k, "count": v} for k, v in category_counts.items()],
        key=lambda item: item["name"].lower(),
    )
    brands = sorted(
        [{"name": k, "count": v} for k, v in brand_counts.items()],
        key=lambda item: item["name"].lower(),
    )

    return render_template(
        "search_results.html",
        results=filtered,
        q=q,
        ratings=ratings,
        category_filter=category_filter,
        brand_filter=brand_filter,
        sort=sort,
        min_price=min_price,
        max_price=max_price,
        base_min=base_min,
        base_max=base_max,
        categories=categories,
        brands=brands,
        total_results=len(filtered),
    )


@app.route("/search_suggestions")
def search_suggestions():
    q = request.args.get("q", "").strip()
    if len(q) < 2:
        return jsonify([])

    q_lower = q.lower()
    like = f"%{q_lower}%"
    prefix = f"{q_lower}%"
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT product_id, product_name, category, brand, price, stock, description, image_url
                FROM products
                WHERE LOWER(product_name) LIKE %s
                   OR LOWER(category) LIKE %s
                   OR LOWER(brand) LIKE %s
                   OR LOWER(description) LIKE %s
                   OR SOUNDEX(product_name) = SOUNDEX(%s)
                   OR SOUNDEX(brand) = SOUNDEX(%s)
                ORDER BY
                  CASE
                    WHEN LOWER(product_name) = %s THEN 6
                    WHEN LOWER(product_name) LIKE %s THEN 5
                    WHEN LOWER(brand) = %s THEN 4
                    WHEN LOWER(brand) LIKE %s THEN 3
                    WHEN LOWER(category) LIKE %s THEN 2
                    WHEN LOWER(description) LIKE %s THEN 1
                    ELSE 0
                  END DESC,
                  product_id DESC
                LIMIT 8
                """,
                (
                    like,
                    like,
                    like,
                    like,
                    q_lower,
                    q_lower,
                    q_lower,
                    prefix,
                    q_lower,
                    prefix,
                    like,
                    like,
                ),
            )
            rows = cur.fetchall() or []
    finally:
        conn.close()

    suggestions = []
    for row in rows:
        suggestions.append(
            {
                "id": _row_at(row, 0),
                "name": _row_at(row, 1),
                "category": _row_at(row, 2),
                "brand": _row_at(row, 3),
                "price": _row_at(row, 4),
                "stock": _row_at(row, 5),
                "description": _row_at(row, 6),
                "image_url": image_url(_row_at(row, 7)),
            }
        )
    return jsonify(suggestions)


def _tokenize_search(raw_query):
    tokens = re.findall(r'"[^"]+"|\\S+', raw_query)
    cleaned = []
    for tok in tokens:
        tok = tok.strip()
        if tok.startswith('"') and tok.endswith('"'):
            tok = tok[1:-1]
        tok = tok.strip()
        if tok:
            cleaned.append(tok)
    return cleaned


def _expand_synonyms(term: str) -> list:
    synonyms = {
        "jersey": ["kit", "football shirt", "soccer jersey"],
        "kit": ["jersey", "football shirt", "soccer jersey"],
        "watch": ["wristwatch", "timepiece"],
        "watches": ["watch", "wristwatch", "timepiece"],
        "ladies": ["women", "female"],
        "men": ["male", "gents"],
        "cleaning": ["cleaner", "cleaners", "detergent"],
        "sneakers": ["shoes", "trainers"],
        "shoes": ["sneakers", "trainers"],
    }
    key = term.lower()
    return synonyms.get(key, [])


def advanced_product_search(raw_query):
    tokens = _tokenize_search(raw_query)
    raw_lower = raw_query.strip().lower()

    general_terms = []
    name_terms = []
    brand_terms = []
    category_terms = []
    desc_terms = []
    min_price = None
    max_price = None

    for tok in tokens:
        if ":" in tok:
            key, value = tok.split(":", 1)
            key = key.lower().strip()
            value = value.strip()
            if key in {"category", "cat"}:
                category_terms.append(value)
                continue
            if key in {"brand"}:
                brand_terms.append(value)
                continue
            if key in {"name", "title"}:
                name_terms.append(value)
                continue
            if key in {"desc", "description"}:
                desc_terms.append(value)
                continue
            if key in {"price"}:
                if "-" in value:
                    low, high = value.split("-", 1)
                    try:
                        min_price = float(low)
                        max_price = float(high)
                    except ValueError:
                        pass
                else:
                    try:
                        min_price = float(value)
                    except ValueError:
                        pass
                continue
            if key in {"min"}:
                try:
                    min_price = float(value)
                except ValueError:
                    pass
                continue
            if key in {"max"}:
                try:
                    max_price = float(value)
                except ValueError:
                    pass
                continue

        general_terms.append(tok)

    where_parts = []
    where_params = []
    score_parts = []
    score_params = []

    def add_score(expr, term, weight, like=False):
        if like:
            score_parts.append(f"CASE WHEN {expr} LIKE %s THEN {weight} ELSE 0 END")
            score_params.append(term)
        else:
            score_parts.append(f"CASE WHEN {expr} = %s THEN {weight} ELSE 0 END")
            score_params.append(term)

    def add_soundex_score(field, term, weight):
        score_parts.append(f"CASE WHEN SOUNDEX({field}) = SOUNDEX(%s) THEN {weight} ELSE 0 END")
        score_params.append(term)

    def add_term_group(term, weight_scale=1.0):
        variants = [term] + _expand_synonyms(term)
        term_clauses = []
        for v in variants:
            v = v.strip().lower()
            if not v:
                continue
            like = f"%{v}%"
            term_clauses.append(
                "(LOWER(p.product_name) LIKE %s OR LOWER(p.category) LIKE %s OR LOWER(p.brand) LIKE %s OR LOWER(p.description) LIKE %s "
                "OR SOUNDEX(p.product_name)=SOUNDEX(%s) OR SOUNDEX(p.brand)=SOUNDEX(%s) OR SOUNDEX(p.category)=SOUNDEX(%s))"
            )
            where_params.extend([like, like, like, like, v, v, v])

            w = weight_scale
            add_score("LOWER(p.product_name)", v, int(28 * w))
            add_score("LOWER(p.brand)", v, int(18 * w))
            add_score("LOWER(p.category)", v, int(14 * w))
            add_score("LOWER(p.product_name)", f"{v}%", int(20 * w), like=True)
            add_score("LOWER(p.brand)", f"{v}%", int(12 * w), like=True)
            add_score("LOWER(p.category)", f"{v}%", int(9 * w), like=True)
            add_score("LOWER(p.product_name)", f"%{v}%", int(9 * w), like=True)
            add_score("LOWER(p.brand)", f"%{v}%", int(6 * w), like=True)
            add_score("LOWER(p.category)", f"%{v}%", int(4 * w), like=True)
            add_score("LOWER(p.description)", f"%{v}%", int(2 * w), like=True)
            add_soundex_score("p.product_name", v, int(4 * w))
            add_soundex_score("p.brand", v, int(3 * w))
            add_soundex_score("p.category", v, int(2 * w))
        if term_clauses:
            where_parts.append("(" + " OR ".join(term_clauses) + ")")

    for term in general_terms:
        add_term_group(term, 1.0)

    for term in name_terms:
        add_term_group(term, 1.2)

    for term in brand_terms:
        add_term_group(term, 1.1)

    for term in category_terms:
        add_term_group(term, 1.05)

    for term in desc_terms:
        add_term_group(term, 0.9)

    if raw_lower:
        add_score("LOWER(p.product_name)", raw_lower, 40)
        add_score("LOWER(p.brand)", raw_lower, 24)
        add_score("LOWER(p.category)", raw_lower, 18)
        add_score("LOWER(p.product_name)", f"{raw_lower}%", 26, like=True)
        add_score("LOWER(p.brand)", f"{raw_lower}%", 14, like=True)
        add_score("LOWER(p.category)", f"{raw_lower}%", 10, like=True)
        add_score("LOWER(p.product_name)", f"%{raw_lower}%", 12, like=True)
        add_score("LOWER(p.brand)", f"%{raw_lower}%", 7, like=True)
        add_score("LOWER(p.category)", f"%{raw_lower}%", 5, like=True)
        add_score("LOWER(p.description)", f"%{raw_lower}%", 3, like=True)
        add_soundex_score("p.product_name", raw_lower, 5)
        add_soundex_score("p.brand", raw_lower, 3)
        add_soundex_score("p.category", raw_lower, 2)

    if min_price is not None and max_price is not None:
        where_parts.append("p.price BETWEEN %s AND %s")
        where_params.extend([min_price, max_price])
    elif min_price is not None:
        where_parts.append("p.price >= %s")
        where_params.append(min_price)
    elif max_price is not None:
        where_parts.append("p.price <= %s")
        where_params.append(max_price)

    where_clause = ""
    if where_parts:
        where_clause = "WHERE " + " AND ".join(where_parts)

    score_expr = "0"
    if score_parts:
        score_expr = " + ".join(score_parts)

    sql = f"""
        SELECT
            p.*,
            COALESCE(r.avg_rating, 0) AS avg_rating,
            COALESCE(r.rating_count, 0) AS rating_count,
            ({score_expr})
              + (COALESCE(r.avg_rating, 0) * 2)
              + (LEAST(COALESCE(r.rating_count, 0), 50) * 0.2) AS score
        FROM products p
        LEFT JOIN (
            SELECT product_id, AVG(rating) AS avg_rating, COUNT(*) AS rating_count
            FROM product_reviews
            WHERE is_seed = 0
            GROUP BY product_id
        ) r ON r.product_id = p.product_id
        {where_clause}
        ORDER BY score DESC, rating_count DESC, avg_rating DESC, p.product_name
        LIMIT 60
    """

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(sql, score_params + where_params)
            return cursor.fetchall()
    finally:
        connection.close()



def get_products_by_category(category_name):
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM products WHERE category = %s", (category_name,))
            return cursor.fetchall()
    finally:
        connection.close()


@app.route("/categories")
def categories():
    categories_list = [
        {"name": "Men Watch", "slug": "men-watch", "image": "rolex1.jpg"},
        {"name": "Ladies Watch", "slug": "ladies-watch", "image": "3ladies1.jpg"},
        {"name": "Jersey", "slug": "jersey", "image": "jersey1.jpg"},
        {"name": "Cleaning", "slug": "cleaning", "image": "foam1.jpeg"},
    ]
    return render_template("categories.html", categories=categories_list)


@app.route("/category/men-watch")
def category_men_watch():
    products = get_products_by_category("Men Watch")
    conn = get_db_connection()
    try:
        ratings = get_ratings_for_products(conn, [_row_at(row, 0) for row in products])
    finally:
        conn.close()
    return render_template("category_men_watch.html", products=products, ratings=ratings)


@app.route("/category/ladies-watch")
def category_ladies_watch():
    products = get_products_by_category("Ladies Watch")
    conn = get_db_connection()
    try:
        ratings = get_ratings_for_products(conn, [_row_at(row, 0) for row in products])
    finally:
        conn.close()
    return render_template("category_ladies_watch.html", products=products, ratings=ratings)


@app.route("/category/jersey")
def category_jersey():
    products = get_products_by_category("Jersey")
    conn = get_db_connection()
    try:
        ratings = get_ratings_for_products(conn, [_row_at(row, 0) for row in products])
    finally:
        conn.close()
    return render_template("category_jersey.html", products=products, ratings=ratings)


@app.route("/category/cleaning")
def category_cleaning():
    products = get_products_by_category("Cleaning")
    conn = get_db_connection()
    try:
        ratings = get_ratings_for_products(conn, [_row_at(row, 0) for row in products])
    finally:
        conn.close()
    return render_template("category_cleaning.html", products=products, ratings=ratings)


@app.route("/flash-sales")
def flash_sales_page():
    conn = get_db_connection()
    try:
        flash_state = get_flash_sale_state(conn)
        ratings = get_ratings_for_products(
            conn, [_row_at(row, 0) for row in flash_state["items"]]
        )
    finally:
        conn.close()

    flash_sales = flash_state["items"] if flash_state["active"] else []
    flash_sale_active = flash_state["active"]
    flash_sale_seconds = flash_state["seconds_left"]
    flash_sale_time_label = format_duration(
        flash_sale_seconds if flash_sale_active else 0
    )

    return render_template(
        "flash_sales.html",
        flash_sales=flash_sales,
        flash_sale_active=flash_sale_active,
        flash_sale_seconds=flash_sale_seconds,
        flash_sale_time_label=flash_sale_time_label,
        ratings=ratings,
    )


@app.route("/about")
def about():
    return render_template("about.html")


#Add to cart route
def get_product(product_id):
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    connection.close()
    return product

@app.route("/add_to_cart/<int:product_id>", methods=["POST"])
def add_to_cart(product_id):
    wants_json = (
        request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "application/json" in request.headers.get("Accept", "")
    )
    try:
        qty = int(request.form.get("qty", 1))
    except ValueError:
        qty = 1
    if qty <= 0:
        qty = 1

    product = get_product(product_id)
    if not product:
        message = "Product not found."
        if wants_json:
            return jsonify({"ok": False, "message": message, "level": "danger"}), 404
        set_site_message(message, "danger")
        return redirect(request.referrer or url_for("home"))

    try:
        stock = int(product[5]) if product[5] is not None else 0
    except (ValueError, TypeError):
        stock = 0

    if stock <= 0:
        message = "This item is currently out of stock."
        if wants_json:
            return jsonify({"ok": False, "message": message, "level": "danger"}), 409
        set_site_message(message, "danger")
        return redirect(request.referrer or url_for("home"))

    cart = session.get("cart", {})  # {"12": 2, "15": 1}
    pid = str(product_id)
    current = int(cart.get(pid, 0))
    desired = current + qty

    if desired > stock:
        cart[pid] = stock
        message = f"Only {stock} left in stock. Cart updated."
        level = "warning"
    else:
        cart[pid] = desired
        message = "Added to cart."
        level = "success"

    session["cart"] = cart
    total_items = sum(cart.values())
    if wants_json:
        return jsonify(
            {
                "ok": True,
                "cart_count": total_items,
                "message": message,
                "level": level,
            }
        )
    set_site_message(message, level)
    return redirect(request.referrer or url_for("home"))


#Cart page route
@app.route("/cart")
def cart():
    cart = session.get("cart", {})
    items = []
    grand_total = 0

    for pid, qty in cart.items():
        product = get_product(int(pid))
        if not product:
            continue

        price = float(product[4])  # adjust index if your price is different
        total = price * int(qty)
        grand_total += total

        items.append({
            "product": product,
            "qty": int(qty),
            "total": total
        })

    return render_template("cart.html", items=items, grand_total=grand_total)


@app.route("/update_cart/<int:product_id>", methods=["POST"])
def update_cart(product_id):
    action = request.form.get("action", "set")  # inc | dec | set
    try:
        qty = int(request.form.get("qty", 1))
    except ValueError:
        qty = 1

    cart = session.get("cart", {})
    pid = str(product_id)
    current = int(cart.get(pid, 0))

    product = get_product(product_id)
    if not product:
        cart.pop(pid, None)
        session["cart"] = cart
        set_site_message("Product no longer exists and was removed.", "warning")
        return redirect(url_for("cart"))

    try:
        stock = int(product[5]) if product[5] is not None else 0
    except (ValueError, TypeError):
        stock = 0

    if action == "inc":
        new_qty = current + 1
    elif action == "dec":
        new_qty = current - 1
    else:
        new_qty = qty

    if stock <= 0:
        cart.pop(pid, None)
        session["cart"] = cart
        set_site_message("This item is out of stock and was removed.", "danger")
        return redirect(url_for("cart"))

    if new_qty > stock:
        new_qty = stock
        set_site_message(f"Only {stock} left in stock. Quantity adjusted.", "warning")

    if new_qty <= 0:
        cart.pop(pid, None)
    else:
        cart[pid] = new_qty

    session["cart"] = cart
    return redirect(url_for("cart"))



@app.route("/remove_from_cart/<int:product_id>")
def remove_from_cart(product_id):
    cart = session.get("cart", {})
    cart.pop(str(product_id), None)
    session["cart"] = cart
    return redirect(url_for("cart"))


@app.route("/clear_cart")
def clear_cart():
    session.pop("cart", None)
    return redirect(url_for("cart"))

@app.route("/checkout")
def checkout():
    return "Checkout coming soon"


def get_db():
    return get_db_connection()



#Whatsapp route
@app.route("/pay_on_delivery", methods=["POST"])
def pay_on_delivery():
    # 1) Require login
    if not session.get("username"):
        session["next_url"] = request.referrer or url_for("home")
        return redirect(url_for("signin"))

    user_id = session["username"]

    # 2) Location required
    location = request.form.get("location", "").strip()
    if not location:
        # return back with a query flag (simple)
        return redirect((request.referrer or url_for("cart")) + "?err=location")

    # 3) Start from cart in session
    cart = session.get("cart", {}).copy()

    # If coming from single.html, include that product too
    product_id = request.form.get("product_id")
    quantity = int(request.form.get("quantity", 1))
    if product_id:
        pid = str(product_id)
        cart[pid] = cart.get(pid, 0) + quantity

    if not cart:
        return redirect(request.referrer or url_for("home"))

    # 4) Fetch user info + products from DB
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT username, email, phone FROM users WHERE id=%s", (user_id,))
    u = cur.fetchone()
    username, email, phone = u if u else ("Customer", "", "")
    email = email or ""
    phone = phone or ""

    ids = list(cart.keys())
    placeholders = ",".join(["%s"] * len(ids))

    cur.execute(f"SELECT * FROM products WHERE product_id IN ({placeholders})", ids)
    products = cur.fetchall()

    product_map = {str(p[0]): p for p in products}  # p[0] = product_id

    # Validate stock before creating order
    updated_cart = cart.copy()
    stock_issue = False
    for pid, qty in cart.items():
        p = product_map.get(pid)
        if not p:
            updated_cart.pop(pid, None)
            stock_issue = True
            continue
        try:
            stock = int(p[5]) if p[5] is not None else 0
        except (ValueError, TypeError):
            stock = 0
        if stock <= 0:
            updated_cart.pop(pid, None)
            stock_issue = True
        elif int(qty) > stock:
            updated_cart[pid] = stock
            stock_issue = True

    if stock_issue:
        session["cart"] = updated_cart
        set_site_message("Some items are out of stock or limited. Please review your cart.", "warning")
        cur.close()
        conn.close()
        return redirect(url_for("cart"))

    # 5) Compute totals and prepare order items
    order_items = []
    subtotal = 0.0

    for pid, qty in cart.items():
        p = product_map.get(pid)
        if not p:
            continue

        name = p[1]                 # product name index
        unit_price = float(p[4])    # price index
        qty = int(qty)
        line_total = unit_price * qty
        subtotal += line_total

        order_items.append({
            "product_id": int(pid),
            "product_name": name,
            "unit_price": unit_price,
            "quantity": qty,
            "line_total": line_total
        })

    if not order_items:
        cur.close()
        conn.close()
        return redirect(request.referrer or url_for("home"))

    # 6) Store order in DB
    cur.execute(
        "INSERT INTO orders (user_id, location, payment_method, status, subtotal) VALUES (%s, %s, %s, %s, %s)",
        (user_id, location, "PAY_ON_DELIVERY", "PENDING", subtotal)
    )
    order_id = cur.lastrowid
    order_reference = None
    if orders_has_reference():
        order_reference = f"ZC-{order_id:06d}"
        cur.execute(
            "UPDATE orders SET order_reference=%s WHERE order_id=%s",
            (order_reference, order_id),
        )

    for it in order_items:
        cur.execute(
            """INSERT INTO order_items
               (order_id, product_id, product_name, unit_price, quantity, line_total)
               VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (order_id, it["product_id"], it["product_name"], it["unit_price"], it["quantity"], it["line_total"])
        )

    conn.commit()
    cur.close()
    conn.close()

    # 7) Build best WhatsApp message
    lines = []
    lines.append("Bigoh ORDER (PAY ON DELIVERY)")
    lines.append("--------------------------------")
    if order_reference:
        lines.append(f"Order Ref: {order_reference}")
    lines.append(f"Order ID: #{order_id}")
    lines.append(f"Customer: {username}")
    if phone: lines.append(f"Phone: {phone}")
    if email: lines.append(f"Email: {email}")
    lines.append("")
    lines.append(f"Delivery Location: {location}")
    lines.append("")
    lines.append("ITEMS:")

    n = 1
    for it in order_items:
        link = url_for("single", product_id=it["product_id"], _external=True)
        lines.append(f"{n}. {it['product_name']}")
        lines.append(f"   Qty: {it['quantity']} | Unit: KES {it['unit_price']:,.2f} | Line: KES {it['line_total']:,.2f}")
        lines.append(f"   Link: {link}")
        n += 1

    lines.append("")
    lines.append(f"SUBTOTAL: KES {subtotal:,.2f}")
    lines.append("")
    lines.append("Kindly send me payment details for my orders.")
    lines.append("Thank you.")

    text = "\n".join(lines)

    # 8) Clear cart (cannot detect WhatsApp send success; clearing happens at redirect time)
    session.pop("cart", None)

    wa_url = f"https://wa.me/{WHATSAPP_NUMBER}?text={quote(text)}"
    session["last_order_id"] = order_id
    session["last_wa_url"] = wa_url
    return redirect(url_for("order_confirmation", order_id=order_id))




#Upload route
@app.route("/upload", methods=["GET", "POST"])
@admin_required
def upload():
    if request.method == "POST":
        product_name = request.form.get("product_name", "").strip()
        category = request.form.get("category", "").strip()
        brand = request.form.get("brand", "").strip()
        price = request.form.get("price", "").strip()
        stock = request.form.get("stock", "0").strip()
        description = request.form.get("description", "").strip()

        file = request.files.get("image")

        # Basic validation
        if not product_name or not category or not price:
            return render_template("upload.html", error="Product name, category, and price are required.")

        if not file or file.filename == "":
            return render_template("upload.html", error="Please choose an image.")

        if not allowed_file(file.filename):
            return render_template("upload.html", error="Invalid image type. Use jpg, jpeg, png, or webp.")

        # Ensure upload folder exists
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

        # Save image with safe filename
        filename = secure_filename(file.filename)
        # avoid overwriting
        base, ext = os.path.splitext(filename)
        i = 1
        final_name = filename
        while os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], final_name)):
            final_name = f"{base}_{i}{ext}"
            i += 1

        save_path = os.path.join(app.config["UPLOAD_FOLDER"], final_name)
        file.save(save_path)

        # Store relative path in DB (matches how you render: /static/....)
        image_url = f"images/{final_name}"  # because it's inside static/images/

        # Insert into DB
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                sql = """
                    INSERT INTO products
                    (product_name, category, brand, price, stock, description, image_url)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (product_name, category, brand, price, stock, description, image_url))
                connection.commit()
        finally:
            connection.close()

        return render_template("upload.html", success="Product uploaded successfully.")

    return render_template("upload.html")


@app.route("/order/confirmation/<int:order_id>")
def order_confirmation(order_id):
    if not session.get("username"):
        return redirect(url_for("signin"))

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            if orders_has_reference():
                cur.execute(
                    """
                    SELECT order_id, user_id, location, payment_method, status, subtotal, order_reference
                    FROM orders
                    WHERE order_id = %s
                    """,
                    (order_id,),
                )
            else:
                cur.execute(
                    """
                    SELECT order_id, user_id, location, payment_method, status, subtotal
                    FROM orders
                    WHERE order_id = %s
                    """,
                    (order_id,),
                )
            order = cur.fetchone()

            if not order or order[1] != session.get("username"):
                return redirect(url_for("home"))

            cur.execute(
                """
                SELECT product_name, unit_price, quantity, line_total
                FROM order_items
                WHERE order_id = %s
                """,
                (order_id,),
            )
            items = cur.fetchall() or []
    finally:
        conn.close()

    reference = f"ZC-{order_id:06d}"
    if order and len(order) > 6 and order[6]:
        reference = order[6]
    wa_url = session.get("last_wa_url")
    return render_template(
        "order_confirmation.html",
        order=order,
        items=items,
        reference=reference,
        wa_url=wa_url,
    )



# Admin dashboard route
@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = None
    error = None
    search = request.args.get("q", "").strip()
    metrics = {
        "users": 0,
        "products": 0,
        "orders": 0,
        "revenue": 0.0,
        "pending": 0,
        "completed": 0,
    }
    orders = []
    top_products = []
    status_rows = []
    category_rows = []
    recent_products = []
    low_stock = []
    flash_sale_active = False
    flash_sale_duration_seconds = 0
    flash_sale_time_label = format_duration(0)
    flash_selected_ids = []
    flash_products = []
    flash_duration_hours = 0
    flash_duration_minutes = 0

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        metrics["users"] = _scalar(cur, "SELECT COUNT(*) FROM users", default=0)
        metrics["products"] = _scalar(cur, "SELECT COUNT(*) FROM products", default=0)
        metrics["orders"] = _scalar(cur, "SELECT COUNT(*) FROM orders", default=0)
        metrics["revenue"] = _scalar(cur, "SELECT COALESCE(SUM(subtotal), 0) FROM orders", default=0.0)
        metrics["pending"] = _scalar(cur, "SELECT COUNT(*) FROM orders WHERE status = %s", ("PENDING",), default=0)
        metrics["completed"] = _scalar(cur, "SELECT COUNT(*) FROM orders WHERE status = %s", ("COMPLETED",), default=0)

        try:
            has_ref = orders_has_reference()
            if has_ref:
                base_query = """
                    SELECT o.order_id, o.order_reference, u.username, u.phone, o.location, o.payment_method, o.status, o.subtotal
                    FROM orders o
                    LEFT JOIN users u ON o.user_id = u.id
                """
            else:
                base_query = """
                    SELECT o.order_id, u.username, u.phone, o.location, o.payment_method, o.status, o.subtotal
                    FROM orders o
                    LEFT JOIN users u ON o.user_id = u.id
                """
            params = []
            if search:
                like = f"%{search}%"
                try:
                    order_id = int(search)
                except ValueError:
                    order_id = -1
                base_query += " WHERE o.order_id = %s OR u.username LIKE %s OR u.phone LIKE %s OR o.location LIKE %s "
                params = [order_id, like, like, like]
            base_query += " ORDER BY o.order_id DESC LIMIT 20 "
            cur.execute(base_query, params)
            orders = cur.fetchall() or []
        except Exception:
            orders = []

        try:
            cur.execute(
                """
                SELECT oi.product_name, SUM(oi.quantity) AS qty, SUM(oi.line_total) AS revenue
                FROM order_items oi
                GROUP BY oi.product_name
                ORDER BY qty DESC
                LIMIT 6
                """
            )
            top_products = cur.fetchall() or []
        except Exception:
            top_products = []

        try:
            cur.execute(
                """
                SELECT status, COUNT(*) AS total
                FROM orders
                GROUP BY status
                """
            )
            status_rows = cur.fetchall() or []
        except Exception:
            status_rows = []

        try:
            cur.execute(
                """
                SELECT p.category, SUM(oi.quantity) AS total_qty
                FROM order_items oi
                JOIN products p ON oi.product_id = p.product_id
                GROUP BY p.category
                ORDER BY total_qty DESC
                """
            )
            category_rows = cur.fetchall() or []
        except Exception:
            category_rows = []

        try:
            cur.execute(
                """
                SELECT product_id, product_name, category, price, stock, image_url
                FROM products
                ORDER BY product_id DESC
                LIMIT 8
                """
            )
            recent_products = cur.fetchall() or []
        except Exception:
            recent_products = []

        try:
            cur.execute(
                """
                SELECT product_id, product_name, category, price, stock
                FROM products
                WHERE stock <= 5
                ORDER BY stock ASC, product_id DESC
                LIMIT 6
                """
            )
            low_stock = cur.fetchall() or []
        except Exception:
            low_stock = []

        try:
            if ensure_flash_sale_tables(cur):
                conn.commit()
                cur.execute(
                    "SELECT is_active, duration_seconds, ends_at FROM flash_sale_settings WHERE id = 1"
                )
                row = cur.fetchone()
                flash_sale_active = bool(_row_at(row, 0, 0)) if row else False
                flash_sale_duration_seconds = int(_row_at(row, 1, 0) or 0) if row else 0
                ends_at = _row_at(row, 2, None) if row else None

                now = datetime.now()
                if flash_sale_active and flash_sale_duration_seconds <= 0:
                    flash_sale_active = False
                if flash_sale_active and flash_sale_duration_seconds > 0 and ends_at is None:
                    ends_at = now + timedelta(seconds=flash_sale_duration_seconds)
                    cur.execute(
                        "UPDATE flash_sale_settings SET ends_at=%s WHERE id=1",
                        (ends_at,),
                    )
                    conn.commit()

                seconds_left = 0
                if flash_sale_active and ends_at:
                    seconds_left = int((ends_at - now).total_seconds())
                    if seconds_left <= 0:
                        flash_sale_active = False
                        seconds_left = 0
                        cur.execute(
                            "UPDATE flash_sale_settings SET is_active=0, ends_at=NULL WHERE id=1"
                        )
                        conn.commit()

                flash_sale_time_label = format_duration(
                    seconds_left if flash_sale_active else 0
                )
                flash_duration_hours = flash_sale_duration_seconds // 3600
                flash_duration_minutes = (flash_sale_duration_seconds % 3600) // 60

                cur.execute(
                    "SELECT product_id FROM flash_sale_items WHERE is_active = 1"
                )
                flash_selected_ids = [int(_row_at(row, 0, 0)) for row in cur.fetchall() or []]

                cur.execute(
                    """
                    SELECT product_id, product_name, category, price, stock, image_url
                    FROM products
                    ORDER BY product_id DESC
                    LIMIT 60
                    """
                )
                flash_products = cur.fetchall() or []
        except Exception:
            flash_sale_active = False
            flash_selected_ids = []
            flash_products = []

    except Exception as exc:
        error = str(exc)
    finally:
        if conn:
            conn.close()

    status_labels = [_row_at(row, 0) for row in status_rows]
    status_values = [int(_row_at(row, 1, 0)) for row in status_rows]

    category_labels = [_row_at(row, 0) for row in category_rows]
    category_values = [int(_row_at(row, 1, 0)) for row in category_rows]

    completion_rate = 0.0
    if metrics["orders"]:
        completion_rate = round((metrics["completed"] / metrics["orders"]) * 100, 2)

    return render_template(
        "admin_dashboard.html",
        metrics=metrics,
        completion_rate=completion_rate,
        orders=orders,
        recent_products=recent_products,
        low_stock=low_stock,
        top_products=top_products,
        status_labels=json.dumps(status_labels),
        status_values=json.dumps(status_values),
        category_labels=json.dumps(category_labels),
        category_values=json.dumps(category_values),
        has_reference=orders_has_reference(),
        search=search,
        error=error,
        flash_sale_active=flash_sale_active,
        flash_sale_duration_seconds=flash_sale_duration_seconds,
        flash_sale_time_label=flash_sale_time_label,
        flash_selected_ids=flash_selected_ids,
        flash_products=flash_products,
        flash_duration_hours=flash_duration_hours,
        flash_duration_minutes=flash_duration_minutes,
    )


@app.route("/admin/flash-sale", methods=["GET", "POST"])
@admin_required
def admin_flash_sale():
    if request.method == "POST":
        is_active = request.form.get("is_active") == "on"

        try:
            duration_hours = int(request.form.get("duration_hours", "0"))
        except ValueError:
            duration_hours = 0
        try:
            duration_minutes = int(request.form.get("duration_minutes", "0"))
        except ValueError:
            duration_minutes = 0

        duration_hours = max(duration_hours, 0)
        duration_minutes = max(duration_minutes, 0)
        duration_seconds = (duration_hours * 3600) + (duration_minutes * 60)
        if is_active and duration_seconds <= 0:
            is_active = False

        selected_ids = []
        for raw in request.form.getlist("flash_products"):
            try:
                selected_ids.append(int(raw))
            except (TypeError, ValueError):
                continue
        if selected_ids:
            selected_ids = sorted(set(selected_ids))

        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                if not ensure_flash_sale_tables(cur):
                    return redirect(url_for("admin_dashboard"))

                cur.execute("DELETE FROM flash_sale_items")
                if selected_ids:
                    cur.executemany(
                        "INSERT INTO flash_sale_items (product_id, is_active) VALUES (%s, 1)",
                        [(pid,) for pid in selected_ids],
                    )

                ends_at = None
                if is_active and duration_seconds > 0:
                    ends_at = datetime.now() + timedelta(seconds=duration_seconds)

                cur.execute(
                    """
                    UPDATE flash_sale_settings
                    SET is_active=%s, duration_seconds=%s, ends_at=%s
                    WHERE id=1
                    """,
                    (1 if is_active else 0, duration_seconds, ends_at),
                )
            conn.commit()
        finally:
            conn.close()

        return redirect(url_for("admin_flash_sale"))

    conn = get_db_connection()
    flash_sale_active = False
    flash_sale_time_label = format_duration(0)
    flash_duration_hours = 0
    flash_duration_minutes = 0
    flash_selected_ids = []
    flash_products = []

    try:
        with conn.cursor() as cur:
            if ensure_flash_sale_tables(cur):
                conn.commit()
                cur.execute(
                    "SELECT is_active, duration_seconds, ends_at FROM flash_sale_settings WHERE id = 1"
                )
                row = cur.fetchone()
                flash_sale_active = bool(_row_at(row, 0, 0)) if row else False
                flash_sale_duration_seconds = int(_row_at(row, 1, 0) or 0) if row else 0
                ends_at = _row_at(row, 2, None) if row else None

                now = datetime.now()
                if flash_sale_active and flash_sale_duration_seconds <= 0:
                    flash_sale_active = False
                if flash_sale_active and flash_sale_duration_seconds > 0 and ends_at is None:
                    ends_at = now + timedelta(seconds=flash_sale_duration_seconds)
                    cur.execute(
                        "UPDATE flash_sale_settings SET ends_at=%s WHERE id=1",
                        (ends_at,),
                    )
                    conn.commit()

                seconds_left = 0
                if flash_sale_active and ends_at:
                    seconds_left = int((ends_at - now).total_seconds())
                    if seconds_left <= 0:
                        flash_sale_active = False
                        seconds_left = 0
                        cur.execute(
                            "UPDATE flash_sale_settings SET is_active=0, ends_at=NULL WHERE id=1"
                        )
                        conn.commit()

                flash_sale_time_label = format_duration(
                    seconds_left if flash_sale_active else 0
                )
                flash_duration_hours = flash_sale_duration_seconds // 3600
                flash_duration_minutes = (flash_sale_duration_seconds % 3600) // 60

                cur.execute(
                    "SELECT product_id FROM flash_sale_items WHERE is_active = 1"
                )
                flash_selected_ids = [int(_row_at(row, 0, 0)) for row in cur.fetchall() or []]

                cur.execute(
                    """
                    SELECT product_id, product_name, category, price, stock, image_url
                    FROM products
                    ORDER BY product_id DESC
                    LIMIT 80
                    """
                )
                flash_products = cur.fetchall() or []
    finally:
        conn.close()

    return render_template(
        "admin_flash_sale.html",
        flash_sale_active=flash_sale_active,
        flash_sale_time_label=flash_sale_time_label,
        flash_duration_hours=flash_duration_hours,
        flash_duration_minutes=flash_duration_minutes,
        flash_selected_ids=flash_selected_ids,
        flash_products=flash_products,
    )


@app.route("/admin/order/<int:order_id>/status", methods=["POST"])
@admin_required
def admin_update_order_status(order_id):
    status = request.form.get("status", "").strip().upper()
    allowed = {"PENDING", "PROCESSING", "COMPLETED", "CANCELLED"}
    if status not in allowed:
        return redirect(request.referrer or url_for("admin_dashboard"))

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE orders SET status=%s WHERE order_id=%s", (status, order_id))
        conn.commit()
    finally:
        conn.close()

    return redirect(request.referrer or url_for("admin_dashboard"))


@app.route("/admin/products")
@admin_required
def admin_products():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM products ORDER BY product_id DESC")
            products = cur.fetchall() or []
    finally:
        conn.close()
    return render_template("admin_products.html", products=products)


@app.route("/admin/products/<int:product_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_product(product_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
            product = cur.fetchone()
            if not product:
                return redirect(url_for("admin_products"))

            if request.method == "POST":
                product_name = request.form.get("product_name", "").strip()
                category = request.form.get("category", "").strip()
                brand = request.form.get("brand", "").strip()
                price = request.form.get("price", "").strip()
                stock = request.form.get("stock", "0").strip()
                description = request.form.get("description", "").strip()

                image_url = product[7]
                file = request.files.get("image")
                if file and file.filename:
                    if allowed_file(file.filename):
                        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
                        filename = secure_filename(file.filename)
                        base, ext = os.path.splitext(filename)
                        i = 1
                        final_name = filename
                        while os.path.exists(os.path.join(app.config["UPLOAD_FOLDER"], final_name)):
                            final_name = f"{base}_{i}{ext}"
                            i += 1
                        save_path = os.path.join(app.config["UPLOAD_FOLDER"], final_name)
                        file.save(save_path)
                        image_url = f"images/{final_name}"

                cur.execute(
                    """
                    UPDATE products
                    SET product_name=%s, category=%s, brand=%s, price=%s, stock=%s, description=%s, image_url=%s
                    WHERE product_id=%s
                    """,
                    (product_name, category, brand, price, stock, description, image_url, product_id),
                )
                conn.commit()
                return redirect(url_for("admin_products"))
    finally:
        conn.close()

    return render_template("admin_product_edit.html", product=product)


@app.route("/admin/products/<int:product_id>/delete", methods=["POST"])
@admin_required
def admin_delete_product(product_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM products WHERE product_id=%s", (product_id,))
        conn.commit()
    finally:
        conn.close()
    return redirect(url_for("admin_products"))


@app.route("/admin/orders")
@admin_required
def admin_orders():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            if orders_has_reference():
                cur.execute(
                    """
                    SELECT o.order_id, o.order_reference, u.username, u.phone, o.location, o.payment_method, o.status, o.subtotal
                    FROM orders o
                    LEFT JOIN users u ON o.user_id = u.id
                    ORDER BY o.order_id DESC
                    """
                )
            else:
                cur.execute(
                    """
                    SELECT o.order_id, u.username, u.phone, o.location, o.payment_method, o.status, o.subtotal
                    FROM orders o
                    LEFT JOIN users u ON o.user_id = u.id
                    ORDER BY o.order_id DESC
                    """
                )
            orders = cur.fetchall() or []
    finally:
        conn.close()
    return render_template("admin_orders.html", orders=orders, has_reference=orders_has_reference())


@app.route("/admin/orders/<int:order_id>")
@admin_required
def admin_order_detail(order_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            if orders_has_reference():
                cur.execute(
                    """
                    SELECT o.order_id, o.location, o.payment_method, o.status, o.subtotal, o.order_reference,
                           u.username, u.email, u.phone
                    FROM orders o
                    LEFT JOIN users u ON o.user_id = u.id
                    WHERE o.order_id = %s
                    """,
                    (order_id,),
                )
            else:
                cur.execute(
                    """
                    SELECT o.order_id, o.location, o.payment_method, o.status, o.subtotal,
                           u.username, u.email, u.phone
                    FROM orders o
                    LEFT JOIN users u ON o.user_id = u.id
                    WHERE o.order_id = %s
                    """,
                    (order_id,),
                )
            order = cur.fetchone()

            cur.execute(
                """
                SELECT product_name, unit_price, quantity, line_total
                FROM order_items
                WHERE order_id = %s
                """,
                (order_id,),
            )
            items = cur.fetchall() or []
    finally:
        conn.close()

    if not order:
        return redirect(url_for("admin_orders"))
    reference = f"ZC-{order_id:06d}"
    if order and orders_has_reference() and len(order) > 5 and order[5]:
        reference = order[5]
    return render_template("admin_order_detail.html", order=order, items=items, reference=reference, has_reference=orders_has_reference())


@app.route("/admin/orders/<int:order_id>/items")
@admin_required
def admin_order_items(order_id):
    conn = get_db_connection()
    items = []
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT product_name, unit_price, quantity, line_total
                FROM order_items
                WHERE order_id = %s
                """,
                (order_id,),
            )
            items = cur.fetchall() or []
    except Exception:
        items = []
    finally:
        conn.close()

    payload = []
    for it in items:
        try:
            payload.append(
                {
                    "name": it[0],
                    "unit_price": float(it[1] or 0),
                    "quantity": int(it[2] or 0),
                    "line_total": float(it[3] or 0),
                }
            )
        except Exception:
            continue
    return jsonify(payload)


@app.route("/whoami")
def whoami():
    return str(dict(session))



 



if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)

