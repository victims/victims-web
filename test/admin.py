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
Tests for Admin views.
"""

from test import UserTestCase


class TestAdmin(UserTestCase):
    """
    Tests user account managemnet.
    """
    username = 'admintests'
    nonadmin = 'nonadmintests'
    password = 'arj/^fakhsDDASm491'
    prefix = '/admin'
    views = [
        '', 'cache', 'cache/clear', 'accounts', 'hashes', 'submissions',
        'downloads', 'uploads'
    ]

    @property
    def routes(self):
        return ['%s/%s' % (self.prefix, view) for view in self.views]

    def setUp(self):
        UserTestCase.setUp(self)
        self.create_user(self.username, self.password, {'admin': 'admin'})
        self.create_user(self.nonadmin, self.password)

    def tearDown(self):
        UserTestCase.tearDown(self)

    def visit_all(self, expected_status):
        for route in self.routes:
            resp = self.app.get(route, follow_redirects=True)
            assert resp.status_code == expected_status

    def test_admin_access(self):
        """
        Ensure access is managed correctly
        """

        self.visit_all(404)

        self._login(self.username, self.password)
        self.visit_all(200)
        self._logout()

        self._login(self.nonadmin, self.password)
        self.visit_all(404)
        self._logout()
