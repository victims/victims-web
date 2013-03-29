import json
import re

from test import FlaskTestCase


class TestRegister(FlaskTestCase):
    """
    Tests user registration.
    """

    def _create_user(self, username, password, password_confirm=None):
        """
        Shortcut for creating users.
        """
        if not password_confirm:
            password_confirm = password

        resp = self.app.get('/register')
        csrf_token = re.search(
            '_csrf_token" value="([^"]*)">', resp.data).group(1)

        form_data = {
            'username': username,
            'password': password,
            'verify_password': password_confirm,
            '_csrf_token': csrf_token
        }
        resp = self.app.post(
            '/register', data=form_data, follow_redirects=False)
        return resp

    def test_inital_request(self):
        """
        Verify the proper results return.
        """
        resp = self.app.get('/register')
        assert resp.status_code == 200

        inp = ('username', 'password', 'verify_password')
        for required in inp:
            test_str = '<input name="%s"' % required
            assert test_str in resp.data

        # We must also have the csrf token
        assert 'input type="hidden" name="_csrf_token"' in resp.data

    def test_duplicate_username_registration(self):
        """
        Test to make sure if a bad or duplicate username is used
        we get do not create a new user.
        """
        self._create_user('duplicateuser', 'arj/^fakhsDDASm491')
        resp = self._create_user('duplicateuser', 'arj/^fakhsDDASm491')
        assert resp.status_code == 200
        assert 'Username is not available.' in resp.data

    def test_password_does_not_match_registration(self):
        """
        Verify passwords must match on registration.
        """
        resp = self._create_user(
            'shouldnotwork', 'arj/^fakhsDDASm491', '4oTiuIsd@fgdjfa')
        assert resp.status_code == 200
        assert 'Passwords do not match.' in resp.data

    def test_password_same_as_user_registration(self):
        """
        Verify passwords and username can not be the same.
        """
        resp = self._create_user('shouldNotwork', 'shouldNotwork')
        assert resp.status_code == 200
        assert 'Password can not be the same as the username' in resp.data

    def test_password_too_simple_registration(self):
        """
        Verify password is not too simple.
        """
        resp = self._create_user('shouldNotwork', 'aaaaaaAaaaa/V')
        assert resp.status_code == 200
        assert 'char for more than 30% of the password' in resp.data

    def test_good_registration(self):
        """
        Makes sure a good registration works.
        """
        resp = self._create_user('goodreguser', 'this_/is_OUR_secret')
        assert resp.status_code == 302
        assert resp.location == 'http://localhost/'
