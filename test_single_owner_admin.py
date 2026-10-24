"""
Comprehensive Automated Test Suite for Single-Owner Administrator Access (AI-NIDS).

Verifies all 10 core RBAC security and persistence requirements:
1. Designated owner account can log in and access /admin.
2. Initial password is read from AI_NIDS_ADMIN_PASSWORD and stored hashed.
3. Restarting the application does not reset or overwrite the owner password.
4. Existing non-owner accounts are demoted to USER and cannot access /admin.
5. Attempting to register with the owner email/identity is rejected.
6. Newly registered users are assigned USER even if role=admin is submitted.
7. Authenticated USER accounts receive HTTP 403 on /admin and all administrative APIs.
8. Unauthenticated requests to /admin redirect to /login (or return 401 on /api).
9. Failed login attempts are rate-limited or locked out.
10. Existing flows, predictions, and model evaluation metrics remain intact.
"""

import os
import sys
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

import unittest
import sqlite3
import time
from contextlib import closing
from werkzeug.security import check_password_hash, generate_password_hash

# Ensure working directory is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

import utils
import app as app_module
from utils import DESIGNATED_ADMIN_EMAIL, DESIGNATED_ADMIN_USERNAME, init_db, find_user_by_login_id

TEST_DB_PATH = os.path.join(CURRENT_DIR, 'nids_test_rbac_suite.db')


class SingleOwnerAdminTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Set up an isolated test database
        if os.path.exists(TEST_DB_PATH):
            os.remove(TEST_DB_PATH)

        # Create base tables
        with closing(sqlite3.connect(TEST_DB_PATH)) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT DEFAULT 'user'
            )''')
            # Seed legacy accounts matching original nids.db
            c.execute("INSERT INTO users (username, password, role) VALUES ('admin', ?, 'admin')",
                      (generate_password_hash('adminpass', method='pbkdf2:sha256'),))
            c.execute("INSERT INTO users (username, password, role) VALUES ('testadmin', ?, 'admin')",
                      (generate_password_hash('testpass', method='pbkdf2:sha256'),))
            c.execute("INSERT INTO users (username, password, role) VALUES ('madhan', ?, 'user')",
                      (generate_password_hash('madhanpass', method='pbkdf2:sha256'),))
            conn.commit()

        # Point utils and app to TEST_DB_PATH
        cls.orig_utils_db = utils.DB_PATH
        cls.orig_app_db = app_module.DB_PATH
        cls.orig_env_password = os.environ.get('AI_NIDS_ADMIN_PASSWORD')
        utils.DB_PATH = TEST_DB_PATH
        app_module.DB_PATH = TEST_DB_PATH

        # Initialize test password in environment
        os.environ['AI_NIDS_ADMIN_PASSWORD'] = 'TestSecureAdmin2026!'

        # Run init_db on the test database
        init_db(TEST_DB_PATH)

        # Configure Flask test client
        app_module.app.config['TESTING'] = True
        app_module.app.config['WTF_CSRF_ENABLED'] = False
        cls.client = app_module.app.test_client()

    @classmethod
    def tearDownClass(cls):
        utils.DB_PATH = cls.orig_utils_db
        app_module.DB_PATH = cls.orig_app_db
        if cls.orig_env_password is not None:
            os.environ['AI_NIDS_ADMIN_PASSWORD'] = cls.orig_env_password
        else:
            os.environ.pop('AI_NIDS_ADMIN_PASSWORD', None)
        if os.path.exists(TEST_DB_PATH):
            try:
                os.remove(TEST_DB_PATH)
            except Exception:
                pass

    def setUp(self):
        # Clear rate-limiting tracker before each test
        app_module.LOGIN_ATTEMPTS.clear()

    # -------------------------------------------------------------
    # 1. Designated owner account can log in and access /admin
    # -------------------------------------------------------------
    def test_01_designated_owner_login_and_access(self):
        # Test login via email
        res = self.client.post('/login', data={
            'username': DESIGNATED_ADMIN_EMAIL,
            'password': 'TestSecureAdmin2026!'
        }, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn('/admin', res.headers.get('Location', ''))

        # Check session contains admin role
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get('role'), 'admin')
            self.assertEqual(sess.get('email'), DESIGNATED_ADMIN_EMAIL)

        # Access /admin as owner
        admin_res = self.client.get('/admin')
        self.assertEqual(admin_res.status_code, 200)
        self.assertIn(b'Enterprise SOC', admin_res.data)

    # -------------------------------------------------------------
    # 2. Initial password read from AI_NIDS_ADMIN_PASSWORD & stored hashed
    # -------------------------------------------------------------
    def test_02_password_hashed_not_plaintext(self):
        with closing(sqlite3.connect(TEST_DB_PATH)) as conn:
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE LOWER(email) = LOWER(?)", (DESIGNATED_ADMIN_EMAIL,))
            row = c.fetchone()
            self.assertIsNotNone(row)
            stored_hash = row[0]
            # Ensure not plaintext
            self.assertNotEqual(stored_hash, 'TestSecureAdmin2026!')
            # Ensure it is a valid PBKDF2 hash
            self.assertTrue(stored_hash.startswith('pbkdf2:sha256'))
            self.assertTrue(check_password_hash(stored_hash, 'TestSecureAdmin2026!'))

    # -------------------------------------------------------------
    # 3. Restarting application does NOT reset or overwrite password
    # -------------------------------------------------------------
    def test_03_restarting_preserves_password(self):
        # Get hash before restart
        with closing(sqlite3.connect(TEST_DB_PATH)) as conn:
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE LOWER(email) = LOWER(?)", (DESIGNATED_ADMIN_EMAIL,))
            hash_before = c.fetchone()[0]

        # Simulate restarting with a DIFFERENT environment password
        os.environ['AI_NIDS_ADMIN_PASSWORD'] = 'SomeOtherChangedPassword!'
        init_db(TEST_DB_PATH)

        with closing(sqlite3.connect(TEST_DB_PATH)) as conn:
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE LOWER(email) = LOWER(?)", (DESIGNATED_ADMIN_EMAIL,))
            hash_after = c.fetchone()[0]

        # Hash must be unchanged
        self.assertEqual(hash_before, hash_after)
        # Old password still works, new one does not
        self.assertTrue(check_password_hash(hash_after, 'TestSecureAdmin2026!'))
        self.assertFalse(check_password_hash(hash_after, 'SomeOtherChangedPassword!'))

    # -------------------------------------------------------------
    # 4. Existing non-owner accounts demoted to USER and cannot access /admin
    # -------------------------------------------------------------
    def test_04_non_owner_demoted_to_user(self):
        with closing(sqlite3.connect(TEST_DB_PATH)) as conn:
            c = conn.cursor()
            for username in ['admin', 'testadmin']:
                c.execute("SELECT role FROM users WHERE username = ?", (username,))
                row = c.fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row[0], 'user', f"{username} was not demoted to user!")

        # Attempt to login with former admin and access /admin
        c = app_module.app.test_client()
        login_res = c.post('/login', data={'username': 'admin', 'password': 'adminpass'}, follow_redirects=False)
        self.assertEqual(login_res.status_code, 302)
        self.assertIn('/prediction', login_res.headers.get('Location', ''))

        with c.session_transaction() as sess:
            self.assertEqual(sess.get('role'), 'user')

        # Try to access /admin -> must return 403 Forbidden
        admin_res = c.get('/admin')
        self.assertEqual(admin_res.status_code, 403)
        self.assertIn(b'403', admin_res.data)

    # -------------------------------------------------------------
    # 5. Attempting to register with owner email/identity is rejected
    # -------------------------------------------------------------
    def test_05_register_with_owner_identity_rejected(self):
        c = app_module.app.test_client()
        # Attempt registering with owner email
        res1 = c.post('/register', data={
            'username': 'fakeowner',
            'email': DESIGNATED_ADMIN_EMAIL,
            'password': 'AnyPassword123'
        })
        self.assertEqual(res1.status_code, 400)
        self.assertIn(b'prohibited', res1.data.lower())

        # Attempt registering with owner username
        res2 = c.post('/register', data={
            'username': DESIGNATED_ADMIN_EMAIL,
            'email': 'another@domain.com',
            'password': 'AnyPassword123'
        })
        self.assertEqual(res2.status_code, 400)

        # Attempt registering with 'apashamkirikiri320'
        res3 = c.post('/register', data={
            'username': 'apashamkirikiri320',
            'email': 'test@domain.com',
            'password': 'AnyPassword123'
        })
        self.assertEqual(res3.status_code, 400)

    # -------------------------------------------------------------
    # 6. Newly registered users assigned USER even if role=admin submitted
    # -------------------------------------------------------------
    def test_06_register_role_escalation_prevented(self):
        c = app_module.app.test_client()
        res = c.post('/register', data={
            'username': 'attacker_user',
            'email': 'attacker@example.com',
            'password': 'Password123!',
            'role': 'admin',
            'is_admin': '1',
            'admin': 'true'
        }, follow_redirects=False)
        self.assertEqual(res.status_code, 302)

        # Verify in database that role is strictly 'user'
        with closing(sqlite3.connect(TEST_DB_PATH)) as conn:
            cur = conn.cursor()
            cur.execute("SELECT role FROM users WHERE username = 'attacker_user'")
            row = cur.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], 'user')

    # -------------------------------------------------------------
    # 7. Authenticated USER accounts receive HTTP 403 on /admin and admin APIs
    # -------------------------------------------------------------
    def test_07_user_role_blocked_on_all_admin_endpoints(self):
        c = app_module.app.test_client()
        # Login as regular user
        c.post('/login', data={'username': 'madhan', 'password': 'madhanpass'})

        admin_endpoints = [
            ('/admin', 'GET', None),
            ('/api/admin/overview', 'GET', None),
            ('/download_logs', 'GET', None),
            ('/api/settings', 'POST', {'alpha': 0.5}),
            ('/api/simulation', 'POST', {'action': 'stop'}),
            ('/api/reset_stats', 'POST', {}),
            ('/api/test_email', 'POST', {'email': 'test@example.com'}),
            ('/api/subscribers/delete', 'POST', {'email': 'test@example.com'}),
            ('/api/admin/change_password', 'POST', {'current_password': 'x', 'new_password': 'y', 'confirm_password': 'y'})
        ]

        for path, method, payload in admin_endpoints:
            if method == 'GET':
                res = c.get(path)
            else:
                res = c.post(path, json=payload or {})
            self.assertEqual(res.status_code, 403, f"Endpoint {path} did not return 403 for user role! Got {res.status_code}")

    # -------------------------------------------------------------
    # 8. Unauthenticated requests to /admin redirect to /login
    # -------------------------------------------------------------
    def test_08_unauthenticated_requests_redirected(self):
        c = app_module.app.test_client()
        # Web page unauthenticated -> 302 redirect to /login
        res = c.get('/admin', follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn('/login', res.headers.get('Location', ''))

        # API endpoint unauthenticated -> 401 Unauthorized
        api_res = c.get('/api/admin/overview')
        self.assertEqual(api_res.status_code, 401)

    # -------------------------------------------------------------
    # 9. Failed login attempts are rate-limited or locked out
    # -------------------------------------------------------------
    def test_09_login_rate_limiting(self):
        c = app_module.app.test_client()
        # 5 consecutive failed attempts
        for i in range(5):
            res = c.post('/login', data={'username': 'nobody', 'password': 'badpassword'})
            self.assertEqual(res.status_code, 401, f"Attempt {i+1} did not return 401")

        # 6th attempt must be rate-limited (429)
        locked_res = c.post('/login', data={'username': 'nobody', 'password': 'badpassword'})
        self.assertEqual(locked_res.status_code, 429)
        self.assertIn(b'Too many failed login attempts', locked_res.data)

    # -------------------------------------------------------------
    # 10. Existing flows, predictions, and model evaluation metrics intact
    # -------------------------------------------------------------
    def test_10_database_and_model_pipeline_intact(self):
        # Verify original nids.db still contains all rows
        real_db = os.path.join(CURRENT_DIR, 'nids.db')
        with closing(sqlite3.connect(real_db)) as conn:
            c = conn.cursor()
            c.execute("SELECT count(*) FROM predictions")
            count = c.fetchone()[0]
            self.assertGreaterEqual(count, 133000)

        # Temporarily point utils.DB_PATH to real_db to test metrics
        old_db = utils.DB_PATH
        try:
            utils.DB_PATH = real_db
            metrics = utils.get_metrics_data()
            self.assertIn('basic_metrics', metrics)
            self.assertIn('accuracy', metrics['basic_metrics'])
            self.assertIn('precision', metrics['basic_metrics'])
            self.assertIn('recall', metrics['basic_metrics'])
            self.assertIn('f1', metrics['basic_metrics'])

            overview = utils.get_admin_overview_data()
            self.assertIn('summary', overview)
            self.assertIn('total_flows', overview['summary'])
            self.assertIn('malicious_flows', overview['summary'])
            self.assertIn('system_health', overview)
        finally:
            utils.DB_PATH = old_db


if __name__ == '__main__':
    unittest.main(verbosity=2)
