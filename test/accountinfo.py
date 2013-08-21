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

import re

from test import UserTestCase
from victims_web.user import get_account


class TestAccountInfo(UserTestCase):
    """
    Tests user account managemnet.
    """
    username = 'infotests'
    password = 'arj/^fakhsDDASm491'

    def setUp(self):
        UserTestCase.setUp(self)
        self._create_user(self.username, self.password)
        self._login(self.username, self.password)
        self.account = get_account(self.username)

    def tearDown(self):
        self._logout()
        UserTestCase.tearDown(self)

    def test_account_view(self):
        """
        Verify that account info is correctly displayed.
        """
        resp = self.app.get('/account')
        assert resp.status_code == 200
        tests = [
            self.account.username,
            self.account.email,
            self.account.apikey,
            self.account.secret,
        ]
        for v in tests:
            if v:
                assert v in resp.data

    def update_account(self, form_data):
        """
        Helper function to attempt account details update.
        """
        resp = self.app.get('/account_edit')
        csrf_token = re.search(
            '_csrf_token" value="([^"]*)">', resp.data).group(1)

        form_data['_csrf_token'] = csrf_token

        resp = self.app.post('/account_edit', data=form_data, follow_redirects=True)
        assert resp.status_code == 200
        print(resp.data)
        assert 'Account information was successfully updated!' in resp.data

    def test_account_edit(self):
        """
        Verify that account editing works as expected
        """
        new_pass = self.password[::-1]
        new_email = 'updated@testcase.com'
        form_data = {
            'current_password': self.password,
            'change_password': 'on',
            'password': new_pass,
            'verify_password': new_pass,
            'change_email': 'on',
            'email': new_email,
            'regenerate': 'on',
        }

        self.update_account(form_data)

        updated_account = get_account(self.username)
        assert updated_account.email == new_email
        assert updated_account.password != self.account.password
        assert updated_account.apikey != self.account.apikey
        assert updated_account.secret != self.account.secret

        self.account = updated_account
        self.password = new_pass
