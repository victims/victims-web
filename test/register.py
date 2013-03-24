import json
import re

from test import FlaskTestCase


class TestRegister(FlaskTestCase):
    """
    Tests user registration.
    """

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

    def test_good_registration(self):
        """
        Makes sure a good registration works.
        """
        resp = self.app.get('/register')
        assert resp.status_code == 200

        csrf_token = re.search(
            '_csrf_token" value="([^"]*)">', resp.data).group(1)

        form_data = {
            'username': 'anewuser',
            'password': 'this_/is_OUR_secret',
            'verify_password': 'this_/is_OUR_secret',
            '_csrf_token': csrf_token
        }
        resp = self.app.post(
            '/register', data=form_data, follow_redirects=False)
        assert resp.status_code == 302
        assert resp.location == 'http://localhost/'
