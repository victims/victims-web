import json
import re

from test import FlaskTestCase


class TestLogin(FlaskTestCase):
    """
    Tests user login.
    """

    def tearDown(self):
        """
        Issue a logout on every test.
        """
        self.app.get('/logout', follow_redirects=True)

    def _login(self, username, password):
        """
        Shortcut for logging a user in.
        """
        resp = self.app.get('/login')
        csrf_token = re.search(
            '_csrf_token" value="([^"]*)">', resp.data).group(1)

        form_data = {
            'username': username,
            'password': password,
            '_csrf_token': csrf_token
        }
        resp = self.app.post(
            '/login', data=form_data, follow_redirects=False)
        return resp

    def test_unknown_username(self):
        """
        Test a unknown username does not work.
        """
        resp = self._login('idonotexist', 'r9uqwha!ksjdlBBa))kgj')
        assert resp.status_code == 200
        assert 'Invalid username/password' in resp.data

    def test_wrong_login(self):
        """
        Make sure a wrong password does not work.
        """
        username = 'wrongpassword'
        password = 'f30Fw@@Do&itpHGFf'

        resp = self.app.get('/register')
        csrf_token = re.search(
            '_csrf_token" value="([^"]*)">', resp.data).group(1)

        form_data = {
            'username': username,
            'password': password,
            'verify_password': password,
            '_csrf_token': csrf_token
        }
        resp = self.app.post(
            '/register', data=form_data, follow_redirects=False)
        self.app.get('/logout', follow_redirects=True)

        resp = self._login(username, 'WRONGPASSWORD')
        assert resp.status_code == 200
        assert 'Invalid username/password' in resp.data

    def test_successful_login(self):
        """
        Make sure a successful login works.
        """
        username = 'logintest'
        password = 'f30Fw@@Do&itpHGFf'

        resp = self.app.get('/register')
        csrf_token = re.search(
            '_csrf_token" value="([^"]*)">', resp.data).group(1)

        form_data = {
            'username': username,
            'password': password,
            'verify_password': password,
            '_csrf_token': csrf_token
        }
        resp = self.app.post(
            '/register', data=form_data, follow_redirects=False)
        self.app.get('/logout', follow_redirects=True)

        resp = self._login(username, password)
        assert resp.status_code == 302
        assert resp.location == 'http://localhost/'

        # Since we are already logged in it should pass us to /
        resp = self.get('/login')
        assert resp.status_code == 302
        assert resp.location == 'http://localhost/'
