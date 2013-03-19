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
                print kind, badtype, resp.status_code, resp.data
                assert resp.status_code == 400

    def test_data_structure(self):
        """
        Ensures the response structure is correct.
        """
        resp = self.app.get('/service/v2/update/1970-01-01T00:00:00/')
        result = json.loads(resp.data)
        assert len(result) > 0

        expected = {
            'date': str,
            'name': str,
            'version': str,
            'format': str,
            'hashes': dict,
            'vendor': str,
            'cves': list,
            'status': str,
            'meta': dict,
            'submitter': str,
            'submittedon': str,
        }

        for item in result:
            assert 'fields' in item.keys()
            for key, testtype in expected.items():
                assert isinstance(testtype, item['fields'][key])

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
