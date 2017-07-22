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
from flask.ext.bcrypt import generate_password_hash

from victims.web import application
from victims.web.models import Account
from victims.web.user import delete_user


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
                re.search(
                    'csrf_field.setAttribute\("value", "([^"]*)',
                    resp.data
                ).group(1)
            )
        return (resp, None)


class UserTestCase(FlaskTestCase):

    _created_users = []

    username = 'defaulttester'
    password = 'f30Fw@@Do&itpHGFf'

    def _login(self, username, password, redirect=None, follow=False):
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

        path = '/login'
        if redirect:
            path = '%s?next=%s' % (path, redirect)

        resp = self.app.post(
            path, data=form_data, follow_redirects=follow)
        return resp

    def _logout(self):
        """
        Shortcut for logging a user out
        """
        self.app.get('/logout', follow_redirects=True)

    def create_user(self, username, password, roles=[]):
        """
        Shortcut for creating users.
        """
        if username not in self._created_users:
            self._created_users.append(username)

        self.account = Account.objects(username=username).first()

        if self.account:
            return

        account = Account()
        account.username = username
        account.password = generate_password_hash(
            password,
            application.app.config['BCRYPT_LOG_ROUNDS']
        )
        account.active = True
        account.roles = roles
        account.save()

        self.account = account

    def tearDown(self):
        for username in self._created_users:
            delete_user(username)
