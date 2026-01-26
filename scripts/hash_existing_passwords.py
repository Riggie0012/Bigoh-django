import os
import pymysql
from werkzeug.security import generate_password_hash


def is_hashed(value: str) -> bool:
    if not value:
        return False
    # Common werkzeug formats: "pbkdf2:sha256:..." / "scrypt:..." / "bcrypt:..."
    return value.startswith("pbkdf2:") or value.startswith("scrypt:") or value.startswith("bcrypt:")


def main():
    host = os.getenv("DB_HOST", "localhost")
    user = os.getenv("DB_USER", "root")
    password = os.getenv("DB_PASSWORD", "")
    database = os.getenv("DB_NAME", "zenithcartdb")
    port = int(os.getenv("DB_PORT", "3306"))

    conn = pymysql.connect(host=host, user=user, password=password, database=database, port=port)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, password FROM users")
            rows = cur.fetchall() or []

            updated = 0
            for user_id, pwd in rows:
                if pwd is None:
                    continue
                pwd = str(pwd)
                if is_hashed(pwd):
                    continue
                new_hash = generate_password_hash(pwd)
                cur.execute("UPDATE users SET password=%s WHERE id=%s", (new_hash, user_id))
                updated += 1

        conn.commit()
        print(f"Updated {updated} user password(s) to hashes.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
