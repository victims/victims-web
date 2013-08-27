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
Unittesting.
"""

import unittest
import re

from victims_web import application
from victims_web.user import delete_user


class FlaskTestCase(unittest.TestCase):

    def setUp(self):
        application.app.config['TESTING'] = True
        self.app = application.app.test_client()

    def visit(self, route):
        """
        Helper method that visits a given route and returns response and
        csrf_token.
        """
        resp = self.app.get(route)

        if '_csrf_token' in resp.data:
            return (
                resp,
                re.search('_csrf_token" value="([^"]*)">', resp.data).group(1)
            )
        return (resp, None)


class UserTestCase(FlaskTestCase):

    _created_users = []

    def tearDown(self):
        for username in self._created_users:
            delete_user(username)

    def _login(self, username, password):
        """
        Shortcut for logging a user in.
        """
        (resp, csrf_token) = self.visit('/login')
        if resp.status_code == 302:
            return resp

        form_data = {
            'username': username,
            'password': password,
            '_csrf_token': csrf_token,
        }

        resp = self.app.post(
            '/login', data=form_data, follow_redirects=False)
        return resp

    def _logout(self):
        """
        Shortcut for logging a user out
        """
        self.app.get('/logout', follow_redirects=True)

    def _create_user(self, username, password, password_confirm=None):
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
