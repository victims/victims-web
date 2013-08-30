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
Tests for logins.
"""

from test import UserTestCase


class TestLogin(UserTestCase):
    """
    Tests user login.
    """
    username = 'logintester'
    password = 'f30Fw@@Do&itpHGFf'

    def setUp(self):
        self.create_user(self.username, self.password)
        UserTestCase.setUp(self)

    def tearDown(self):
        """
        Issue a logout on every test.
        """
        self.app.get('/logout', follow_redirects=True)
        UserTestCase.tearDown(self)

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
        resp = self._login(self.username, 'WRONGPASSWORD')
        assert resp.status_code == 200
        assert 'Invalid username/password' in resp.data

    def test_successful_login(self):
        """
        Make sure a successful login works.
        """
        resp = self._login(self.username, self.password)
        assert resp.status_code == 302
        assert resp.location == 'http://localhost/'

        # Since we are already logged in it should pass us to /
        resp = self.app.get('/login')
        assert resp.status_code == 302
        assert resp.location == 'http://localhost/'

    def test_login_redirect_good(self):
        """
        Make sure login redirects work as expected
        """
        resp = self._login(self.username, self.password, '/account')
        assert resp.status_code == 302
        assert resp.location == 'http://localhost/account'

    def test_login_redirect_bad(self):
        """
        Ensure malicious redirects are thwarted
        """
        for redirect in ['http://google.com']:
            resp = self._login(self.username, self.password, redirect, True)
            assert resp.status_code == 200
            assert 'Invalid redirect' in resp.data
