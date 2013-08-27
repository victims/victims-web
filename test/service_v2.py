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
Service version 2 testing.
"""

import json
from datetime import datetime
from hashlib import md5

from test import UserTestCase
from victims_web.models import Removal
from victims_web.user import generate_signature


class TestServiceV2(UserTestCase):
    """
    Tests for version 2 of the web service.
    """

    username = 'v2tester'
    points = ['update', 'remove']

    def test_uri_endpoints(self):
        """
        Verify the basic endpoints respond as they should.
        """
        for kind in self.points:
            resp = self.app.get('/service/v2/%s/1970-01-01T00:00:00/' % kind)
            assert resp.status_code == 200

        # V1 returns empty list when nothing is available
        for kind in self.points:
            resp = self.app.get('/service/v2/%s/4000-01-01T00:00:00/' % kind)
            assert resp.status_code == 200

        # Anything that is not an int should be a 404
        for kind in self.points:
            for badtype in [0, 'NotAnInt', 10.436, 0x80, u'bleh']:
                resp = self.app.get('/service/v2/%s/%s/' % (kind, badtype))
                assert resp.status_code == 400

    def verify_data_structure(self, result, expected):
        assert len(result) > 0
        for item in result:
            assert 'fields' in item.keys()
            for key, testtype in expected.items():
                assert isinstance(item['fields'][key], testtype)

    def test_data_structure_get(self):
        """
        Ensures the response structure is correct for a GET request.
        """
        resp = self.app.get('/service/v2/update/1970-01-01T00:00:00/')
        result = json.loads(resp.data)

        expected = {
            'date': basestring,
            'name': basestring,
            'version': basestring,
            'format': basestring,
            'hashes': dict,
            'vendor': basestring,
            'cves': list,
            'status': basestring,
            'meta': dict,
            'submitter': basestring,
            'submittedon': basestring,
        }
        self.verify_data_structure(result, expected)
    '''
    def test_data_structure_post(self):
        """
        Ensures the response structure is correct for a POST request.
        """
        testhash = dict(combined="")
        testhashes = dict(sha512=testhash)
        testdata = dict(name="", hashes=testhashes)
        testdata = json.dumps(testdata)
        resp = self.app.post('/service/v2/update/1970-01-01T00:00:00/',
                             data=testdata, follow_redirects=True)
        result = json.loads(resp.data)

        expected = {
            'name': basestring,
            'hashes': dict
        }
        self.verify_data_structure(result, expected)

        # additional verifications
        for item in result:
            hashes = item['fields']['hashes']
            assert isinstance(hashes, dict)
            assert len(hashes) == len(testhashes)
            for alg in hashes.keys():
                assert alg in testhashes.keys()
                hash = hashes[alg]
                assert isinstance(hash, dict)
                assert len(hash) == len(testhash)
                for htype in hash.keys():
                    assert htype in testhash.keys()

    # TODO: Need to import a full hash else this test will always fail
    def test_cves_valid(self):
        """
        Ensures the cve search (/cves) end point works as expected for a
        valid algorithm
        """
        # Test for valid sha512
        sha512 = ''.join(['0' for i in range(128)])
        resp = self.app.get('/service/v2/cves/%s/%s/' % ('sha512', sha512))
        result = json.loads(resp.data)
        assert isinstance(result, list)
        assert 'CVE-1969-0001' in result
    '''

    def test_cves_invalid(self):
        """
        Ensures the cve search (/cves) end point works as expected for a
        valid algorithm
        """
        # Test for invalid algorithm
        resp = self.app.get('/service/v2/cves/%s/%s/' % ('invalid', 'invalid'))
        result = json.loads(resp.data)
        assert resp.status_code == 400
        assert isinstance(result, list)
        assert result[0]['error'].find('Invalid alogrithm') >= 0

        # Test for invalid argument length
        resp = self.app.get('/service/v2/cves/%s/%s/' % ('sha1', '0'))
        result = json.loads(resp.data)
        assert resp.status_code == 400
        assert isinstance(result, list)
        assert result[0]['error'].find('Invalid checksum length for sha1') >= 0

    def test_status(self):
        """
        Verifies the status data is correct.
        """
        resp = self.app.get('/service/v2/status.json')
        result = json.loads(resp.data)

        assert result['version'] == '2'
        assert result['recommended'] is True
        assert result['eol'] is None
        assert result['supported'] is True
        assert result['endpoint'] == '/service/v2/'

    def test_removals(self):
        test_hash = 'ABC123'
        removal = Removal()
        removal.hash = test_hash
        removal.validate()
        removal.save()
        resp = self.app.get(
            '/service/v2/remove/1970-01-01T00:00:00', follow_redirects=True)
        assert resp.status_code == 200
        assert test_hash in resp.data

    def json_submit(self, group, status_code=403, apikey=None, secret=None):
        testhash = dict(combined="")
        testhashes = dict(sha512=testhash)
        testdata = dict(name="", hashes=testhashes, cves=['CVE-2013-0000'])
        testdata = json.dumps(testdata)
        path = '/service/v2/submit/hash/%s/' % (group)
        content_type = 'application/json'
        data_md5 = md5(testdata).hexdigest()
        date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        headers = [('Date', date)]
        if apikey is not None and secret is not None:
            signature = generate_signature(
                apikey, 'PUT', path, content_type, date, data_md5
            )
            headers.append(('Victims-Api', '%s:%s' % (apikey, signature)))
        resp = self.app.put(
            path, headers=headers, data=testdata, content_type=content_type,
            follow_redirects=True
        )
        assert resp.status_code == status_code

    def test_java_submission_authenticated(self):
        """
        Verifies that an authenticated user can submit entries via the JSON API
        """
        self.makeAccount()
        self._login(self.username, self.password)
        self.json_submit('java', 201, self.account.apikey, self.account.secret)
        self._logout()

    def test_java_submission_anon(self):
        """
        Verfies that an unauthenticated user cannot submit via the JSON API
        """
        self.json_submit('java', 403)
