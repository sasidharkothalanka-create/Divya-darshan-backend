"""Creates the database, tables and temple data from ../database/schema.sql.

Usage:  python init_db.py
(Alternative without Python:  mysql -u root -p < ../database/schema.sql)
"""
import os
import re

import pymysql
from dotenv import load_dotenv

load_dotenv()

SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "database", "schema.sql")

conn = pymysql.connect(
    host=os.getenv("DB_HOST", "localhost"),
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER", "root"),
    password=os.getenv("DB_PASSWORD", ""),
    charset="utf8mb4",
)

with open(SCHEMA, encoding="utf-8") as f:
    sql = f.read()

# drop "-- comment" lines, then run statement by statement
sql = re.sub(r"(?m)^\s*--.*$", "", sql)
statements = [s.strip() for s in sql.split(";") if s.strip()]

try:
    with conn.cursor() as cur:
        for stmt in statements:
            cur.execute(stmt)
    conn.commit()
    print(f"Done - ran {len(statements)} statements. Database is ready.")
finally:
    conn.close()
