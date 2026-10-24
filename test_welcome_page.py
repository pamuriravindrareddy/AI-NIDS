"""
Comprehensive Automated Test Suite for AI-NIDS Welcome Page & Access Portals.

Verifies all 10 requirements from Step 6:
1. The welcome page loads.
2. Admin Login opens the correct login flow.
3. A valid designated administrator reaches /admin.
4. A normal user cannot access /admin (and is rejected from the admin portal).
5. User Login works (redirects normal users to permitted user page).
6. Create Account opens registration.
7. New registrations receive USER privileges (and admin identity registration is rejected).
8. Direct URL access does not bypass authorization.
9. Existing /prediction and /analysis pages still work.
10. Existing database records and ML functionality remain intact.
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
from contextlib import closing

# Ensure current working directory is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

import app as app_module
import utils
from utils import DB_PATH, DESIGNATED_ADMIN_EMAIL
from inference import predict_flow


class WelcomePageTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app_module.app.config['TESTING'] = True
        app_module.app.config['WTF_CSRF_ENABLED'] = False
        cls.client = app_module.app.test_client()

    def setUp(self):
        # Clear rate-limiting cache before each test
        app_module.LOGIN_ATTEMPTS.clear()

    # -------------------------------------------------------------
    # 1. The welcome page loads
    # -------------------------------------------------------------
    def test_01_welcome_page_loads(self):
        res = self.client.get('/')
        self.assertEqual(res.status_code, 200)
        html = res.data.decode('utf-8')

        # Check Branding & Titles
        self.assertIn('AI-NIDS', html)
        self.assertIn('AI-Powered Network Intrusion Detection System', html)

        # Check Two Prominent Access Cards
        self.assertIn('Administrator Access', html)
        self.assertIn('Secure access to the AI-NIDS Security Operations Center.', html)
        self.assertIn('User Access', html)
        self.assertIn('Access network monitoring and security analytics.', html)

        # Check Action Links on Cards
        self.assertIn('Admin Login', html)
        self.assertIn('/login?portal=admin', html)
        self.assertIn('User Login', html)
        self.assertIn('/login', html)
        self.assertIn('Create Account', html)
        self.assertIn('/register', html)

        # Ensure no public admin register link
        self.assertNotIn('Admin Register', html)

    # -------------------------------------------------------------
    # 2. Admin Login opens the correct login flow
    # -------------------------------------------------------------
    def test_02_admin_login_opens_correct_flow(self):
        # Test direct URL with portal=admin
        res = self.client.get('/login?portal=admin')
        self.assertEqual(res.status_code, 200)
        html = res.data.decode('utf-8')
        self.assertIn('Administrator Login', html)
        self.assertIn('SOC Administrator Portal', html)
        self.assertIn('Authenticate Administrator', html)
        # Ensure no registration link is presented in admin portal
        self.assertNotIn('Create Account', html)
        self.assertNotIn('Register now', html)

        # Test /admin/login redirect route
        res_redir = self.client.get('/admin/login', follow_redirects=True)
        self.assertEqual(res_redir.status_code, 200)
        self.assertIn('Administrator Login', res_redir.data.decode('utf-8'))

    # -------------------------------------------------------------
    # 3. A valid designated administrator reaches /admin
    # -------------------------------------------------------------
    def test_03_valid_designated_admin_reaches_admin(self):
        c = app_module.app.test_client()
        admin_password = None
        with closing(sqlite3.connect(DB_PATH)) as conn:
            user = utils.find_user_by_login_id(conn, DESIGNATED_ADMIN_EMAIL)
            from werkzeug.security import check_password_hash
            hashed_pw = user[2] if (user and isinstance(user, tuple)) else (user.get('password') if user else None)
            for candidate in ['Reddy@4725p', os.environ.get('AI_NIDS_ADMIN_PASSWORD'), 'admin']:
                if candidate and hashed_pw and check_password_hash(hashed_pw, candidate):
                    admin_password = candidate
                    break
        if not admin_password:
            admin_password = 'Reddy@4725p'

        # Login via admin portal
        res = c.post('/login?portal=admin', data={
            'portal': 'admin',
            'username': DESIGNATED_ADMIN_EMAIL,
            'password': admin_password
        }, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn('/admin', res.headers.get('Location', ''))

        # Access /admin with authenticated session
        admin_page = c.get('/admin')
        self.assertEqual(admin_page.status_code, 200)
        self.assertIn(b'Enterprise SOC', admin_page.data)

    # -------------------------------------------------------------
    # 4. A normal user cannot access /admin (and is rejected from admin portal)
    # -------------------------------------------------------------
    def test_04_normal_user_cannot_access_admin(self):
        c = app_module.app.test_client()
        # Normal user attempting to log in through the Administrator Portal must be rejected
        res = c.post('/login?portal=admin', data={
            'portal': 'admin',
            'username': 'admin',  # demoted former admin account
            'password': 'admin'
        })
        self.assertEqual(res.status_code, 403)
        self.assertIn(b'Standard user accounts cannot log into the SOC Administrator Portal', res.data)

        # Normal user logged in via regular login trying to access /admin must get 403
        c_user = app_module.app.test_client()
        c_user.post('/login', data={'username': 'admin', 'password': 'admin'})
        admin_res = c_user.get('/admin')
        self.assertEqual(admin_res.status_code, 403)
        self.assertIn(b'403', admin_res.data)

    # -------------------------------------------------------------
    # 5. User Login works (redirects to permitted user page)
    # -------------------------------------------------------------
    def test_05_user_login_works(self):
        c = app_module.app.test_client()
        res = c.post('/login', data={
            'portal': 'user',
            'username': 'admin',  # demoted account with user role
            'password': 'admin'
        }, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        # Normal user is redirected to prediction (Live Network Monitor)
        self.assertIn('/prediction', res.headers.get('Location', ''))

        # Access /prediction -> must be 200 OK
        pred_res = c.get('/prediction')
        self.assertEqual(pred_res.status_code, 200)

    # -------------------------------------------------------------
    # 6. Create Account opens registration
    # -------------------------------------------------------------
    def test_06_create_account_opens_registration(self):
        res = self.client.get('/register')
        self.assertEqual(res.status_code, 200)
        html = res.data.decode('utf-8')
        self.assertIn('Registration', html)
        self.assertIn('Username', html)
        self.assertIn('Password', html)
        self.assertIn('standard User privileges', html)

    # -------------------------------------------------------------
    # 7. New registrations receive USER privileges
    # -------------------------------------------------------------
    def test_07_new_registrations_receive_user_role(self):
        c = app_module.app.test_client()
        import random
        rnd = random.randint(10000, 99999)
        new_username = f"analyst_{rnd}"

        # Attempt to inject role=admin
        res = c.post('/register', data={
            'username': new_username,
            'email': f'{new_username}@example.com',
            'password': 'Password123!',
            'role': 'admin',
            'is_admin': '1'
        }, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn('/login', res.headers.get('Location', ''))

        # Check in database
        with closing(sqlite3.connect(DB_PATH)) as conn:
            cur = conn.cursor()
            cur.execute("SELECT role FROM users WHERE username = ?", (new_username,))
            row = cur.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], 'user', "New registration must strictly have 'user' role!")

        # Attempting to register with owner identity must be rejected
        res_blocked = c.post('/register', data={
            'username': 'impostor',
            'email': DESIGNATED_ADMIN_EMAIL,
            'password': 'Password123!'
        })
        self.assertEqual(res_blocked.status_code, 400)

    # -------------------------------------------------------------
    # 8. Direct URL access does not bypass authorization
    # -------------------------------------------------------------
    def test_08_direct_url_access_protection(self):
        c = app_module.app.test_client()
        # Unauthenticated direct access to /admin -> 302 to /login
        r_admin = c.get('/admin', follow_redirects=False)
        self.assertEqual(r_admin.status_code, 302)
        self.assertIn('/login', r_admin.headers.get('Location', ''))

        # Unauthenticated direct access to /api/admin/overview -> 401
        r_api = c.get('/api/admin/overview')
        self.assertEqual(r_api.status_code, 401)

        # Unauthenticated direct access to /download_logs -> 302 to /login
        r_dl = c.get('/download_logs', follow_redirects=False)
        self.assertEqual(r_dl.status_code, 302)

        # Authenticated as user, direct access to /download_logs -> 403 Forbidden
        c.post('/login', data={'username': 'admin', 'password': 'admin'})
        r_dl_user = c.get('/download_logs')
        self.assertEqual(r_dl_user.status_code, 403)

    # -------------------------------------------------------------
    # 9. Existing /prediction and /analysis pages still work
    # -------------------------------------------------------------
    def test_09_existing_prediction_and_analysis_pages_work(self):
        c = app_module.app.test_client()
        c.post('/login', data={'username': 'admin', 'password': 'admin'})

        # /prediction
        r_pred = c.get('/prediction')
        self.assertEqual(r_pred.status_code, 200)
        self.assertIn(b'Live Network Threat Detection', r_pred.data)

        # /analysis
        r_ana = c.get('/analysis')
        self.assertEqual(r_ana.status_code, 200)
        self.assertIn(b'Forensic Analysis', r_ana.data)

        # /api/live_stats
        r_stats = c.get('/api/live_stats')
        self.assertEqual(r_stats.status_code, 200)
        self.assertIn('total_packets', r_stats.get_json())

        # /api/metrics_data
        r_metrics = c.get('/api/metrics_data')
        self.assertEqual(r_metrics.status_code, 200)
        self.assertIn('basic_metrics', r_metrics.get_json())

    # -------------------------------------------------------------
    # 10. Existing database records and ML functionality remain intact
    # -------------------------------------------------------------
    def test_10_database_and_ml_intact(self):
        # Database rows >= 133,000
        with closing(sqlite3.connect(DB_PATH)) as conn:
            cur = conn.cursor()
            cur.execute("SELECT count(*) FROM predictions")
            cnt = cur.fetchone()[0]
            self.assertGreaterEqual(cnt, 133000)

        # Overview data computation intact
        overview = utils.get_admin_overview_data()
        self.assertIn('summary', overview)
        self.assertGreaterEqual(overview['summary']['total_flows'], 133000)

        # ML inference function intact
        dummy_flow = {
            'Destination Port': 80,
            'Flow Duration': 100,
            'Total Fwd Packets': 2,
            'Total Backward Packets': 2,
            'Total Length of Fwd Packets': 100,
            'Total Length of Bwd Packets': 200,
            'Fwd Packet Length Mean': 50.0,
            'Bwd Packet Length Mean': 100.0,
            'Flow IAT Mean': 25.0,
            'Fwd IAT Mean': 10.0,
            'Bwd IAT Mean': 10.0,
            'Fwd PSH Flags': 0,
            'Bwd PSH Flags': 0,
            'Fwd URG Flags': 0,
            'Bwd URG Flags': 0
        }
        res = predict_flow(dummy_flow)
        self.assertIn('label', res)
        self.assertIn('attack_score', res)
        self.assertIn('latency_ms', res)


if __name__ == '__main__':
    unittest.main(verbosity=2)
