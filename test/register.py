import json
import re

from test import FlaskTestCase


class TestRegister(FlaskTestCase):
    """
    Tests user registration.
    """

    def _create_user(username, password, password_confirm=None):
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

        # Since we do it 2x let's use an inner function

        self._create_user('duplicateuser', 'arj/^fakhsDDASm491')
        resp = self._create_user('duplicateuser', 'arj/^fakhsDDASm491')
        assert resp.status_code == 200
        assert 'Username is not available.' in resp.data

    def test_good_registration(self):
        """
        Makes sure a good registration works.
        """
        resp = self._create_user('goodreguser', 'this_/is_OUR_secret')
        assert resp.status_code == 302
        assert resp.location == 'http://localhost/'
