# This file is part of victims-web.
#
# Copyright (C) 2013 The Victims Project
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Tests for registration.
"""

from re import search
from test import UserTestCase
from victims_web.models import Account


class TestRegister(UserTestCase):
    """
    Tests user registration.
    """
    def register_user(self, username, password, password_confirm=None):
        """
        Shortcut for creating users.
        """
        if username not in self._created_users:
            self._created_users.append(username)

        if not password_confirm:
            password_confirm = password

        (_, csrf_token) = self.visit('/register')

        form_data = {
            'username': username,
            'password': password,
            'verify_password': password_confirm,
            '_csrf_token': csrf_token,
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
            match = search('<input .*name="%s"' % required, resp.data)
            assert match is not None

        # We must also have the csrf token
        assert 'csrf_field.setAttribute' in resp.data

    def test_duplicate_username_registration(self):
        """
        Don't allow duplicate usernames.
        """
        self.register_user('duplicateuser', 'arj/^fakhsDDASm491')
        self.app.get('/logout', follow_redirects=True)
        resp = self.register_user('duplicateuser', 'arj/^fakhsDDASm491')
        assert resp.status_code == 200
        assert 'Username is not available.' in resp.data

    def test_password_does_not_match_registration(self):
        """
        Verify passwords must match on registration.
        """
        resp = self.register_user(
            'shouldnotwork', 'arj/^fakhsDDASm491', '4oTiuIsd@fgdjfa')
        assert resp.status_code == 200
        assert 'Passwords do not match.' in resp.data

    def test_password_same_as_user_registration(self):
        """
        Verify passwords and username can not be the same.
        """
        resp = self.register_user('shouldNotwork', 'shouldNotwork')
        assert resp.status_code == 200
        assert 'Password can not be the same as the username' in resp.data

    def test_password_too_simple_registration(self):
        """
        Verify password is not too simple.
        """
        resp = self.register_user('shouldNotwork', 'aaaaaaAaaaa/V')
        assert resp.status_code == 200
        assert 'char for more than 30% of the password' in resp.data

        resp = self.register_user('shouldNotwork', '1234567')
        assert resp.status_code == 200
        assert 'Password too simple' in resp.data

    def test_all_data_is_required_registration(self):
        """
        Make sure all data is required.
        """
        # Inner function to test multiple cases
        def try_to_create_user(empty_item):
            (_, csrf_token) = self.visit('/register')

            form_data = {
                'username': 'willnotwork',
                'password': 'rfguw^^^efDFamh3',
                'verify_password': 'rfguw^^^efDFamh3',
                '_csrf_token': csrf_token
            }
            form_data[empty_item] = ''
            resp = self.app.post(
                '/register', data=form_data, follow_redirects=False)
            return resp

        for item in ['username']:
            resp = try_to_create_user(item)
            assert resp.status_code == 200
            assert 'is required.' in resp.data

    def test_good_registration(self):
        """
        Makes sure a good registration works.
        """
        resp = self.register_user('goodreguser', 'this_/is_OUR_secret')
        assert resp.status_code == 302
        assert resp.location == 'http://localhost/'

        # Since we are already logged in it should pass us to /
        resp = self.app.get('/register')
        assert resp.status_code == 302
        assert resp.location == 'http://localhost/'
        self.app.get('/logout', follow_redirects=True)

    def test_api_generation(self):
        """
        Makes sure api keys are generated on registration
        """
        resp = self.register_user('apiuser', 'this_/is_OUR_secret')
        assert resp.status_code == 302

        user = Account.objects(username='apiuser').first()
        assert len(user.apikey) == 32 and len(user.secret) == 40
