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
Service version 1 testing.
"""

import json

from test import FlaskTestCase


class TestServiceV1(FlaskTestCase):
    """
    Tests for version 1 of the web service.
    """

    points = ['update', 'remove']

    def test_uri_endpoints(self):
        """
        Verify the basic endpoints respond as they should.
        """
        for kind in self.points:
            resp = self.app.get('/service/v1/%s/0/' % kind)
            assert resp.status_code == 200
            assert resp.content_type == 'application/json'

        # V1 returns empty list when nothing is available
        for kind in self.points:
            resp = self.app.get('/service/v1/%s/999999/' % kind)
            assert resp.status_code == 200
            assert resp.content_type == 'application/json'

        # Anything that is not an int should be a 404
        for kind in self.points:
            for badtype in ['NotAnInt', 10.436, u'bleh']:
                resp = self.app.get('/service/v1/%s/%s/' % (kind, badtype))
                print(resp.status_code, kind, resp)
                assert resp.status_code == 400
                assert resp.content_type == 'application/json'

    def test_data_structure(self):
        """
        Ensures the response structure is correct.
        """
        resp = self.app.get('/service/v1/update/0/')
        result = json.loads(resp.data)

        assert len(result) > 0

        expected = {
            'status': basestring,
            'db_version': int,
            'vendor': basestring,
            'name': basestring,
            'format': basestring,
            'version': basestring,
            'submitter': basestring,
            'hash': basestring,
            'cves': basestring,
        }

        for item in result:
            assert 'fields' in item.keys()
            for key, testtype in expected.items():
                assert isinstance(item['fields'][key], testtype)

    def test_status(self):
        """
        Verifies the status data is correct.
        """
        resp = self.app.get('/service/v1/status.json')
        assert resp.content_type == 'application/json'

        result = json.loads(resp.data)

        import datetime
        from victims.web.blueprints.service_v1 import EOL

        assert result['version'] == '1'
        assert result['recommended'] is False
        assert result['eol'] == EOL.isoformat()
        assert result['supported'] == (datetime.datetime.now() <= EOL)
        assert result['endpoint'] == '/service/v1/'
