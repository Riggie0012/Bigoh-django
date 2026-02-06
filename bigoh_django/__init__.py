import os

if os.getenv("DJANGO_USE_PYMYSQL", "0") == "1":
    try:
        import pymysql

        pymysql.install_as_MySQLdb()
    except Exception:
        pass
