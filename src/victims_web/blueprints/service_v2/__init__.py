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

#from functools import wraps
from flask import Blueprint, Response
#from flask import current_app, json, request, stream_with_context

from victims_web.cache import cache
#from victims_web.user import authenticate
from victims_web.models import Hash


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
        self.result = result

    '''
    def __getstate__(self):
        """The state returned is just the json string of the object"""
        return json.dumps(self.result)

    def __setstate__(self, state):
        """When unpickling, convert the json string into an py-object"""
        self.result = json.loads(state)
    '''
    def __iter__(self):
        """The iterator implementing result to json string generator"""
        yield "[\n"
        count = 0
        for item in self.result:
            count += 1
            data = '{"fields": ' + item.jsonify() + '}'
            if count != len(self.result):
                yield data + ",\n"
            else:
                yield data
        yield "]"


@v2.route('/status.json')
@cache.memoize()
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
        return Response(StreamedSerialResponseValue(
            items), mimetype='application/json')
    except Exception, ex:
        print ex
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

    If POST, we check combined first, then check content fingerprints too for
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
'''

def make_projection(obj, root=True):
    """
    Creates a mongodb projection from a json-like object. If the object
    provided is None, a default projection {'_id': False} is returned.

    :Parameters:
       - `obj`: A dict like object representing a json object.
       - `first`: Flag to indicate if this is the root object.
    """
    projection = {}
    if obj is not None and len(obj) > 0:
        for key in obj.keys():
            field = obj[key]
            if isinstance(field, dict) and len(field) > 0:
                for child in make_projection(field, False):
                    projection['%s.%s' % (key, child)] = True
            else:
                projection[key] = True
    if root:
        # if this is the root set, filter _id
        projection['_id'] = False
    return projection


@cache.memoize()
def serialize_results(since, jsons=None):
    """
    Serializes results based on query results. If a filter is provided as a
    json string as request data, only the specified fields are returned.

    :Parameters:
       - `items`: The items to serialize.
       - `data` : A json string indicating the projection to be applied on the
       db query. An example filter would be:
       {'hash':'', 'cves':[], 'hashes':{'sha512':{'combined':''}}}
    """
    obj = json.loads(jsons) if jsons else None
    items = current_app.db.Hash.find(
        {'date': {'$gt': datetime.datetime.strptime(
            since, "%Y-%m-%dT%H:%M:%S")}}, make_projection(obj))

    # handle special fields
    result = []
    for item in items:
        if 'cves' in item:
            item['cves'] = item['cves'].keys()
        result.append({'fields': item})

    return StreamedSerialResponseValue(result)


def check_for_auth(view):
    """
    Checks for basic auth in calls and returns a 403 if it's not a
    valid account. Does not stop anonymous users or throttle at this
    point.
    """

    @wraps(view)
    def decorated(*args, **kwargs):
        if request.authorization:
            valid = authenticate(
                current_app,
                request.authorization.username,
                request.authorization.password)
            if not valid:
                return 'Forbidden', 403

        return view(*args, **kwargs)

    return decorated


@v2.route('/status.json')
@check_for_auth
@cache.memoize()
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


def error(msg='Could not understand request.', code=400):
    """
    Returns an error json response.

    :Parameters:
        - `msg`: Error message to be returned in json string.
        - `code`: The code to return as status code for the response.
    """
    return json.dumps([{'error': msg}]), code


@v2.route('/update/<since>/', methods=['GET', 'POST'])
@check_for_auth
def update(since):
    """
    Returns all items to add past a specific date in utc.

    :Parameters:
       - `since`: a specific date in utc
    """
    try:
        return Response(stream_with_context(serialize_results(since,
                                                              request.data)),
                        mimetype='application/json')
    except:
        return error()


@v2.route('/remove/<since>/')
@check_for_auth
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


def search_cve_combined(algorithm, arg):
    """
    Searches the database for any matches for an algorithm/combined-hash
    combination.

    :Parameters:
       - `algorithm`: Fingerprinting algorithm.
       - `arg`: The fingerprint.
    """
    items = current_app.db.Hash.find(
        {'hashes': {algorithm: {'combined': arg}}},
        make_projection({'cves': {}})
    )
    cves = []
    for item in items:
        cves += item['cves'].keys()
    return cves


@v2.route('/cves/<algorithm>/<arg>/', methods=['GET'])
@check_for_auth
@cache.memoize()
def cves(algorithm, arg):
    """
    Returns any cves that match the given the request.

    If GET, we check only the combined hashes for the given algorithm for
    matches.

    If POST, we check combined first, then check content fingerprints too for
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
        cves = search_cve_combined(algorithm, arg)
        # TODO: If post handle file bashes checksums here
        return json.dumps(cves)
    except:
        return error()
'''
