"""
Standalone, safe bootstrap script for single-owner administrator access in AI-NIDS.

Usage:
  # Via environment variable:
  $env:AI_NIDS_ADMIN_PASSWORD="YourSecurePasswordHere"
  python bootstrap_admin.py

  # Or interactive prompt (if environment variable is not set):
  python bootstrap_admin.py
"""

import os
import sys
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
import getpass
import sqlite3
from contextlib import closing
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(__file__), 'nids.db')
DESIGNATED_ADMIN_EMAIL = 'apashamkirikiri320@gmail.com'
DESIGNATED_ADMIN_USERNAME = 'apashamkirikiri320@gmail.com'


def bootstrap_admin():
    print("==================================================")
    print("   AI-NIDS Single-Owner Administrator Bootstrap   ")
    print("==================================================")

    # 1. Obtain password from environment variable or secure interactive prompt
    password = os.environ.get('AI_NIDS_ADMIN_PASSWORD')
    if not password:
        if sys.stdin.isatty():
            password = getpass.getpass(f"Enter initial password for {DESIGNATED_ADMIN_EMAIL}: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("[ERROR] ❌ Passwords do not match. Aborting.")
                sys.exit(1)
        else:
            print("[ERROR] ❌ AI_NIDS_ADMIN_PASSWORD environment variable is not set.")
            print("Please set the environment variable and re-run:")
            print('  PowerShell: $env:AI_NIDS_ADMIN_PASSWORD="your_password"')
            print('  Command Prompt: set AI_NIDS_ADMIN_PASSWORD=your_password')
            sys.exit(1)

    if not password or len(password) < 4:
        print("[ERROR] ❌ Administrator password must be at least 4 characters long.")
        sys.exit(1)

    # 2. Hash password securely
    pwd_hash = generate_password_hash(password, method='pbkdf2:sha256')

    # 3. Apply transactionally to SQLite
    with closing(sqlite3.connect(DB_PATH)) as conn:
        c = conn.cursor()

        # Ensure schema
        try:
            c.execute("ALTER TABLE users ADD COLUMN email TEXT")
        except Exception:
            pass
        try:
            c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        except Exception:
            pass

        # Demote any other accounts
        c.execute("""
            UPDATE users 
            SET role = 'user' 
            WHERE role = 'admin' 
              AND LOWER(COALESCE(email, '')) != LOWER(?) 
              AND LOWER(username) != LOWER(?)
              AND LOWER(username) != 'apashamkirikiri320'
        """, (DESIGNATED_ADMIN_EMAIL, DESIGNATED_ADMIN_EMAIL))
        demoted_count = c.rowcount

        # Upsert designated admin
        c.execute("""
            SELECT id, username, email FROM users 
            WHERE LOWER(COALESCE(email, '')) = LOWER(?) 
               OR LOWER(username) = LOWER(?)
               OR LOWER(username) = 'apashamkirikiri320'
        """, (DESIGNATED_ADMIN_EMAIL, DESIGNATED_ADMIN_EMAIL))
        row = c.fetchone()

        if row:
            c.execute("""
                UPDATE users 
                SET email = ?, username = ?, password = ?, role = 'admin' 
                WHERE id = ?
            """, (DESIGNATED_ADMIN_EMAIL, DESIGNATED_ADMIN_USERNAME, pwd_hash, row[0]))
            print(f"[SUCCESS] ✅ Existing account (ID: {row[0]}) updated as sole administrator: {DESIGNATED_ADMIN_EMAIL}")
        else:
            c.execute("""
                INSERT INTO users (username, email, password, role) 
                VALUES (?, ?, ?, 'admin')
            """, (DESIGNATED_ADMIN_USERNAME, DESIGNATED_ADMIN_EMAIL, pwd_hash))
            print(f"[SUCCESS] ✅ Designated administrator account created: {DESIGNATED_ADMIN_EMAIL}")

        conn.commit()

        # Audit check
        admin_count = c.execute("SELECT count(*) FROM users WHERE role = 'admin'").fetchone()[0]
        print(f"[AUDIT] Total administrators in database: {admin_count} (Single Owner Enforced)")
        if demoted_count > 0:
            print(f"[AUDIT] Non-designated former admin accounts demoted to USER role: {demoted_count}")

    print("==================================================")


if __name__ == '__main__':
    bootstrap_admin()
