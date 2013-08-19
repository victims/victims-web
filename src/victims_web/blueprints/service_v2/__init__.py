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
Version 2 of the webservice. Remember service versions are not the same as
application versions.
"""
import datetime
import json

from flask import Blueprint, Response, request, current_app
from flask.ext.login import current_user

from victims_web.cache import cache
from victims_web.models import Hash, Submission
from victims_web.blueprints.helpers import check_for_auth


v2 = Blueprint('service_v2', __name__)


# Module globals
EOL = None


def error(msg='Could not understand request.', code=400):
    """
    Returns an error json response.

    :Parameters:
        - `msg`: Error message to be returned in json string.
        - `code`: The code to return as status code for the response.
    """
    return json.dumps([{'error': msg}]), code


class StreamedSerialResponseValue(object):
    """
    A thin wrapper class around the cleaned/filtered results to enable
    streaming and caching simultaneously.
    """

    def __init__(self, result):
        """
        Creates the streamed iterator.

        :Parameters:
           - `result`: The result to iterate over.
        """
        self.result = result.clone()
        # NOTE: We must do the count else the cursor will stop at 100
        self.result_count = self.result.count()

    def __getstate__(self):
        """
        The state returned is just the json string of the object
        """
        return json.dumps(self.result)

    def __setstate__(self, state):
        """
        When unpickling, convert the json string into an py-object
        """
        self.result = json.loads(state)

    def __iter__(self):
        """
        The iterator implementing result to json string generator and
        splitting the results by newlines.
        """
        yield "[\n"
        count = 0
        for item in self.result:
            count += 1
            data = '{"fields": ' + item.jsonify() + '}'
            if count != self.result_count:
                yield data + ",\n"
            else:
                yield data
        yield "]"


@v2.route('/status.json')
@cache.cached()
def status():
    """
    Return the status of the service.
    """
    return json.dumps({
        'eol': EOL,
        'supported': True,
        'version': '2',
        'recommended': True,
        'endpoint': '/service/v2/'
    })


@v2.route('/update/<since>/', methods=['GET'])
def update(since):
    """
    Returns all items to add past a specific date in utc.

    :Parameters:
       - `since`: a specific date in utc
    """
    try:

        items = Hash.objects(date__gt=datetime.datetime.strptime(
                             since, "%Y-%m-%dT%H:%M:%S"))
        if request.args.get('fields', None):
            fields = []
            for field in request.args.get(
                    'fields').replace(' ', '').split(','):
                if field == 'hashes.sha512':
                    fields.append('hashes__sha512')
                elif field == 'hashes.sha256':
                    fields.append('hashes__sha256')
                else:
                    if field in Hash._fields.keys():
                        fields.append(field)

            items = items.only(*fields)
        return Response(StreamedSerialResponseValue(
            items), mimetype='application/json')
    except Exception:
        return error()


@v2.route('/remove/<since>/')
@cache.memoize()
def remove(since):
    """
    Returns all items to remove past a specific date in utc.

    :Parameters:
       - `since`: a specific date in utc
    """
    try:
        datetime.datetime.strptime(since, "%Y-%m-%dT%H:%M:%S")
        return json.dumps([])
    except:
        return error()


@v2.route('/cves/<algorithm>/<arg>/', methods=['GET'])
def cves(algorithm, arg):
    """
    Returns any cves that match the given the request.

    If GET, we check only the combined hashes for the given algorithm for
    matches.

    :Parameters:
       - `algorithm`: Fingerprinting algorithm.
       - `arg`: The fingerprint.
    """
    try:
        algorithms = ['sha512', 'sha1', 'md5']
        if algorithm not in algorithms:
            return error('Invalid alogrithm. Use any of %s.' % (
                ', '.join(algorithms)))
        elif len(arg) not in [32, 40, 128]:
            return error('Invalid checksum length for %s' % (algorithm))

        kwargs = {("hashes__%s__combined" % (algorithm)): arg}
        cves = Hash.objects.only('cves').filter(**kwargs)
        results = []
        for hash in cves:
            results += hash.cves.keys()
        return Response(json.dumps(results), mimetype='application/json')
    except Exception:
        return error()


@v2.route('/submit/<group>/', methods=['PUT'])
@check_for_auth
def submit(group):
    """
    Allows for authenticated users to submit hashes via json.
    """
    allowed_groups = ['java', 'python']
    user = '%s' % current_user.get_id()
    try:
        if group not in allowed_groups:
            raise ValueError('Invalid group specified')
        json_data = json.loads(request.data)
        if 'cves' not in json_data:
            raise ValueError('No CVE provided')
        submission = Submission()
        submission.source = 'json-api'
        submission.group = group
        submission.submitter = user
        submission.approval = 'PENDING_APPROVAL'
        submission.entry = Hash()
        submission.entry.load_json(user, json_data)
        submission.validate()
        submission.save()
        return submission.entry.jsonify(), 201
    except Exception as e:
        current_app.logger.info('Invalid submission by %s' % (user))
        current_app.logger.debug(e)
        return error()
