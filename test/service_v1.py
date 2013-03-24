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

        # V1 returns empty list when nothing is available
        for kind in self.points:
            resp = self.app.get('/service/v1/%s/999999/' % kind)
            assert resp.status_code == 200

        # Anything that is not an int should be a 404
        for kind in self.points:
            for badtype in ['NotAnInt', 10.436, u'bleh']:
                resp = self.app.get('/service/v1/%s/%s/' % (kind, badtype))
                assert resp.status_code == 404

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
        result = json.loads(resp.data)

        import datetime
        from victims_web.blueprints.service_v1 import EOL

        assert result['version'] == '1'
        assert result['recommended'] is False
        assert result['eol'] == EOL.isoformat()
        assert result['supported'] == (datetime.datetime.now() <= EOL)
