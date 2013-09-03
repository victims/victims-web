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
from StringIO import StringIO
from os import listdir
from shutil import rmtree
from os.path import isdir

from test import UserTestCase

from victims_web.config import UPLOAD_FOLDER, VICTIMS_API_HEADER
from victims_web.models import Removal, Submission
from victims_web.handlers.security import generate_signature


class TestServiceV2(UserTestCase):
    """
    Tests for version 2 of the web service.
    """

    username = 'v2tester'
    points = ['update', 'remove']

    def tearDown(self):
        if isdir(UPLOAD_FOLDER):
            rmtree(UPLOAD_FOLDER)
            for submission in Submission.objects(submitter=self.username):
                submission.delete()

        UserTestCase.tearDown(self)

    def test_uri_endpoints(self):
        """
        Verify the basic endpoints respond as they should.
        """
        for kind in self.points:
            resp = self.app.get('/service/v2/%s/1970-01-01T00:00:00/' % kind)
            assert resp.status_code == 200
            assert resp.content_type == 'application/json'

        # V1 returns empty list when nothing is available
        for kind in self.points:
            resp = self.app.get('/service/v2/%s/4000-01-01T00:00:00/' % kind)
            assert resp.status_code == 200
            assert resp.content_type == 'application/json'

        # Anything that is not an int should be a 404
        for kind in self.points:
            for badtype in [0, 'NotAnInt', 10.436, 0x80, u'bleh']:
                resp = self.app.get('/service/v2/%s/%s/' % (kind, badtype))
                assert resp.status_code == 400
                assert resp.content_type == 'application/json'

    def verify_data_structure(self, result, expected, two_way=False):
        assert len(result) > 0
        for item in result:
            assert 'fields' in item.keys()
            for key, testtype in expected.items():
                assert isinstance(item['fields'][key], testtype)
            if two_way:
                for key in item['fields']:
                    assert key in expected

    def test_updates(self):
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
            'meta': list,
            'submitter': basestring,
            'submittedon': basestring,
        }
        self.verify_data_structure(result, expected)

    def test_filtered_updates(self):
        """
        Ensures the response structure is correct for a POST request.
        """
        resp = self.app.get(
            '/service/v2/update/1970-01-01T00:00:00?fields=name,hashes',
            follow_redirects=True
        )
        result = json.loads(resp.data)

        expected = {
            'name': basestring,
            'hashes': dict
        }
        self.verify_data_structure(result, expected, True)

    '''
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
        assert resp.content_type == 'application/json'

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
        assert resp.content_type == 'application/json'
        assert test_hash in resp.data

    def json_submit(self, path, data, content_type, md5sums, status_code,
                    apikey, secret):
        date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        headers = [('Date', date)]
        if apikey is not None and secret is not None:
            signature = generate_signature(apikey, 'PUT', path, date, md5sums)
            headers.append((VICTIMS_API_HEADER, '%s:%s' % (apikey, signature)))
        resp = self.app.put(
            path, headers=headers,
            data=data,
            follow_redirects=True,
            content_type=content_type
        )
        assert resp.status_code == status_code
        assert resp.content_type == 'application/json'

    def json_submit_hash(self, group, status_code, apikey=None, secret=None):
        testhash = dict(combined="")
        testhashes = dict(sha512=testhash)
        testdata = dict(name="", hashes=testhashes, cves=['CVE-2013-0000'])
        testdata = json.dumps(testdata)
        path = '/service/v2/submit/hash/%s/' % (group)
        md5sums = [md5(testdata).hexdigest()]
        self.json_submit(
            path, testdata, 'application/json',
            md5sums, status_code, apikey, secret
        )

    def json_submit_file(self, group, status_code, argstr=None, apikey=None,
                         secret=None):
        testfilename = 'testfile.jar'
        content = 'test content'
        md5sums = [md5(content).hexdigest()]
        data = {'archive': (StringIO(content), testfilename)}

        path = '/service/v2/submit/archive/%s' % (group)
        if argstr:
            path = '%s?%s' % (path, argstr)

        self.json_submit(
            path, data, 'multipart/form-data',
            md5sums, status_code, apikey, secret
        )

        files = []
        if isdir(UPLOAD_FOLDER):
            files = [
                f for f in listdir(UPLOAD_FOLDER) if f.endswith(testfilename)
            ]

        if status_code == 201:
            assert isdir(UPLOAD_FOLDER)
            assert len(files) > 0
            rmtree(UPLOAD_FOLDER)
        else:
            assert len(files) == 0

    def test_lastapi(self):
        """
        Verify that last api time is updated
        """
        self.create_user(self.username, self.password)
        self._login(self.username, self.password)
        last = datetime.utcnow()
        self.json_submit_hash(
            'java', 201, self.account.apikey, self.account.secret
        )
        self.account.reload()
        assert last < self.account.lastapi

    def test_java_submission_authenticated(self):
        """
        Verifies that an authenticated user can submit entries via the JSON API
        """
        self.create_user(self.username, self.password)
        self._login(self.username, self.password)
        self.json_submit_hash(
            'java', 201, self.account.apikey, self.account.secret
        )
        self.json_submit_file(
            'java', 400, None, self.account.apikey, self.account.secret
        )
        self.json_submit_file(
            'java', 201, 'cves=CVE-2013-000', self.account.apikey,
            self.account.secret
        )
        self._logout()

    def test_java_submission_anon(self):
        """
        Verfies that an unauthenticated user cannot submit via the JSON API
        """
        self.json_submit_hash('java', 403)
        self.json_submit_file('java', 403)
