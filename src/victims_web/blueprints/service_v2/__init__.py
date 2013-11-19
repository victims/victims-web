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

from victims_web.cache import cache
from victims_web.handlers.security import apiauth, api_request_user
from victims_web.handlers.sslify import ssl_exclude
from victims_web.models import Hash, Removal, JsonifyMixin, Coordinates
from victims_web.submissions import submit, upload
from victims_web.util import groups


v2 = Blueprint('service_v2', __name__)


# Module globals
EOL = None
MIME_TYPE = 'application/json'


def make_response(data, code=200):
    return Response(
        response=data,
        status=code,
        mimetype=MIME_TYPE
    )


def error(msg='Could not understand request.', code=400):
    """
    Returns an error json response.

    :Parameters:
        - `msg`: Error message to be returned in json string.
        - `code`: The code to return as status code for the response.
    """
    return make_response(json.dumps([{'error': msg}]), code)


def success(msg='Request successful.', code=201):
    """
    Returns a success json resposne.

    :Paramenters:
        - `msg`: Error message to be returned in json string.
        - `code`: The code to return as status code for the response.
    """
    return make_response(json.dumps([{'success': msg}]), code)


class StreamedSerialResponseValue(object):
    """
    A thin wrapper class around the cleaned/filtered results to enable
    streaming and caching simultaneously.
    """

    def __init__(self, result, fields=None):
        """
        Creates the streamed iterator.

        :Parameters:
           - `result`: The result to iterate over.
        """
        self.result = result.clone()
        self.fields = fields
        # NOTE: We must do the count else the cursor will stop at 100
        self.result_count = self.result.count()

    def _json(self, item):
        if isinstance(item, JsonifyMixin):
            return item.jsonify(self.fields)
        elif isinstance(item, str) or isinstance(item, unicode):
            return str(item)
        else:
            return json.dumps(item)

    def __getstate__(self):
        """
        The state returned is just the json string of the object
        """
        dump = [self._json(o) for o in self.result]
        return json.dumps((dump, self.fields, self.result_count))

    def __setstate__(self, state):
        """
        When unpickling, convert the json string into an py-object
        """
        (self.result, self.fields, self.result_count) = json.loads(state)

    def __iter__(self):
        """
        The iterator implementing result to json string generator and
        splitting the results by newlines.
        """
        yield "[\n"
        count = 0
        for item in self.result:
            count += 1
            jsons = self._json(item)
            if jsons == '{}':
                continue
            data = '{"fields": ' + jsons + '}'
            if count != self.result_count:
                yield data + ",\n"
            else:
                yield data
        yield "]"


def stream_items(items, fields=None):
    return make_response(StreamedSerialResponseValue(items, fields))


@v2.route('/status.json')
@cache.cached()
def status():
    """
    Return the status of the service.
    """
    data = json.dumps({
        'eol': EOL,
        'supported': True,
        'version': '2',
        'recommended': True,
        'endpoint': '/service/v2/'
    })

    return make_response(data)


@v2.route('/update/<group>/<since>/', methods=['GET'])
def update_for_group(group, since):
    """
    Returns all items updated  past a specific date in utc.

    :Parameters:
       - `since`: a specific date in utc
       - `group`: group to limit items to
    """
    try:
        items = Hash.objects(
            date__gt=datetime.datetime.strptime(since, "%Y-%m-%dT%H:%M:%S"),
            group=group
        )

        fields = current_app.config['API_UPDATES_DEFAULT_FIELDS']

        fields_arg = request.args.get('fields', None)
        if fields_arg is not None:
            fields = [
                Hash.modelname(field)
                for field in fields_arg.replace(' ', '').split(',')
            ]

        items = items.only(*fields)
        return stream_items(items, fields)
    except Exception as e:
        current_app.logger.debug(e)
        return error()


@v2.route('/update/<group>/all', methods=['GET'])
def update_all(group):
    """
    A convinience call to get all updates from the begining of time.

    :Parameters:
        - `group`: group to limit items to
    """
    return update_for_group(group, '1970-01-01T00:00:00')


@v2.route('/update/<since>/', methods=['GET'])
def update(since):
    """
    Default update service.

    :Parameters:
       - `since`: a specific date in utc
    """
    return update_for_group(current_app.config['DEFAULT_GROUP'], since)


@v2.route('/remove/<group>/<since>/')
@cache.memoize()
def remove_for_group(group, since):
    """
    Returns all items to remove past a specific date in utc.

    :Parameters:
       - `since`: a specific date in utc
       - `group`: group to limit items to
    """
    try:
        timestamp = datetime.datetime.strptime(since, "%Y-%m-%dT%H:%M:%S")
        items = Removal.objects(date__gt=timestamp, group=group)
        return stream_items(items)
    except:
        return error()


@v2.route('/remove/<since>/')
@cache.memoize()
def remove(since):
    """
    Default remove service.

    :Parameters:
       - `since`: a specific date in utc
    """
    return remove_for_group(current_app.config['DEFAULT_GROUP'], since)


@v2.route('/cves/<algorithm>/<arg>/', methods=['GET'])
def cves_algorithm(algorithm, arg):
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
        return stream_items(cves, ['cves'])
    except Exception:
        return error()


@v2.route('/cves/<group>/', methods=['GET'])
def cves(group):
    """
    Get cves that match the given coordinates for the specified group. Expectes,
    coordinates as arguments.

    :Parameters:
        - `group`: The group for which to search in
    """
    try:
        kwargs = {
            'coordinates__%s' % (coord): request.args.get(coord).strip()
            for coord in current_app.config['SUBMISSION_GROUPS'].get(group)
            if coord in request.args and coord in Coordinates._fields
        }

        if len(kwargs) == 0:
            raise ValueError('No coordinates given')

        kwargs['group'] = group
        cves = Hash.objects.only('cves').filter(**kwargs)
        return stream_items(cves, ['cves'])
    except ValueError as ve:
        return error(ve.message)
    except Exception as e:
        current_app.logger.debug(e.message)
        return error()


@v2.route('/submit/hash/<group>/', methods=['PUT'])
@apiauth
def submit_hash(group):
    """
    Allows for authenticated users to submit hashes via json.
    """
    user = '%s' % api_request_user()
    try:
        if group not in groups():
            raise ValueError('Invalid group specified')
        json_data = request.get_json()
        if 'cves' not in json_data:
            raise ValueError('No CVE provided')
        entry = Hash()
        entry.mongify(json_data)
        entry.submitter = user
        submit(
            user, 'json-api-hash', group, suffix='Hash', entry=entry,
            approval='PENDING_APPROVAL')
        return success()
    except ValueError as ve:
        return error(ve.message)
    except Exception as e:
        current_app.logger.info('Invalid submission by %s' % (user))
        current_app.logger.debug(e)
        return error()


@v2.route('/submit/archive/<group>', methods=['PUT'])
@apiauth
def submit_archive(group):
    """
    Allows for authenticated users to submit archives
    """
    user = '%s' % api_request_user()
    try:
        if group not in groups():
            raise ValueError('Invalid group specified')

        if 'cves' not in request.args:
            raise ValueError('CVE(s) required')

        cves = [cve.strip() for cve in request.args['cves'].split(',')]

        coordinates = Coordinates(**{
            coord: request.args.get(coord).strip()
            for coord in current_app.config['SUBMISSION_GROUPS'].get(group)
            if coord in request.args
        })
        files = upload(group, request.files.get('archive', None), coordinates)

        for (ondisk, filename, suffix) in files:
            submit(
                user, ondisk, group, filename, suffix, cves,
                coordinates=coordinates
            )

        return success()
    except ValueError as ve:
        current_app.logger.info('Invalid submission by %s: %s' %
                                (user, ve.message))
        return error(ve.message)
    except Exception as e:
        current_app.logger.info(e.message)
        return error()

SUBMISSION_ROUTES = [submit_hash, submit_archive]

for v in [update, remove, cves]:
    ssl_exclude(update)
