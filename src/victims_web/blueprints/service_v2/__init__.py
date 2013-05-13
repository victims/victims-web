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
Version 1 of the webservice. Remember service versions are not the same as
application versions.
"""
import datetime

from functools import wraps
from flask import Blueprint, current_app, json, request, Response

from victims_web.cache import cache
from victims_web.user import authenticate
from victims_web.models import Hash

v2 = Blueprint('service_v2', __name__)

# Module globals
EOL = None


def filter_item(item, filter):
    """
    Filter out fields not required. The filter is expected to be a python
    object created by json.loads().

    An example filter would be:
    {'hash':'', 'cves':[], 'hashes':{'sha512':{'combined':''}}}

    This will filter the given item to have only the hash, list of cves, and
    combined sha512. Note that all values are currently ignored, filtering
    is only done on keys. Currently only the 'hashes' field supports
    deep-matching.

    :Parameters:
        - `item` : The item to filter
        - `filter` : The filter object.
    """
    result = {}

    # Test for all keys available in the model
    for key in Hash.structure.keys():
        if key in filter.keys():
            # match deep keys for 'hashes'
            if key == 'hashes':
                # identify required algorithms
                algorithms = []
                hashKeys = {}
                if (isinstance(filter[key], dict)
                        and len(filter[key].keys()) > 0):
                    for alg in filter[key].keys():
                        # hash type required (files, combined)
                        if alg in item[key].keys():
                            algorithms.append(alg)
                            hashKeys[alg] = filter[key][alg].keys()
                else:
                    # default is all available
                    algorithms = item[key].keys()

                # populate hashes for enabled algorithms
                for alg in algorithms:
                    result[key] = {alg: {}}
                    for hkey in item[key][alg].keys():
                        if len(hashKeys[alg]) == 0 or hkey in hashKeys[alg]:
                            result[key][alg][hkey] = item[key][alg][hkey]
            else:
                value = item[key]
                # serialize datetime.datetime objects
                if isinstance(value, datetime.datetime):
                    value = value.isoformat()
                result[key] = value
    return result


def filter_results(items, filter):
    """
    Filters and serializes results based on query results.

    :Parameters:
       - `items`: The items to serialize.
       - `filter` : The filter object. (Same as the filter in
       filter_item method.)
    """
    result = []
    for item in items:
        result.append({'fields': filter_item(item, filter)})
    return result


def clean_results(items):
    """
    Removes fields that are not required from the query results and handles
    objects that not serializable by the json encoder.

    :Parameters:
       - `items`: The items to clean.
    """
    result = []
    for item in items:
        # Drop the mongodb _id from the service
        item.pop('_id')
        item['date'] = item['date'].isoformat()
        item['submittedon'] = item['submittedon'].isoformat()
        result.append({'fields': item})
    return result


class StreamedSerialResponseValue():
    """
    A think wrapper class around the cleaned/filtered results to enable
    streaming and caching simultaneously.
    """
    def __init__(self, result):
        self.result = result

    def __getstate__(self):
        """The state returned is just the json string of the object"""
        return json.dumps(self.result)

    def __setstate__(self, state):
        """When unpickling, convert the json string into an py-object"""
        self.result = json.loads(state)

    def __iter__(self):
        """The iterator implementing result to json string generator"""
        for chunk in json.JSONEncoder().iterencode(self.result):
            yield chunk


@cache.memoize()
def serialize_results(items, filter=None):
    """
    Serializes results based on query results. If a filter is provided,
    it is applied.

    :Parameters:
       - `items`: The items to serialize.
       - `filter` : The filter object. (Same as the filter in
       filter_item method.)
    """
    result = []
    if filter is None:
        result = clean_results(items)
    else:
        result = filter_results(items, filter)

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


def isPost():
    """
    Tests if the current request is of type 'POST'
    """
    return request.method == 'POST'


@v2.route('/update/<since>/', methods=['GET', 'POST'])
@check_for_auth
def update(since):
    """
    Returns all items to add past a specific date in utc.

    :Parameters:
       - `since`: a specific date in utc
    """
    try:
        items = current_app.db.Hash.find(
            {'date': {'$gt': datetime.datetime.strptime(
                since, "%Y-%m-%dT%H:%M:%S")}})
        filter = json.loads(request.data) if isPost() else None
        return Response(serialize_results(items, filter),
                        mimetype='application/json')
    except Exception:
        return json.dumps([{'error': 'Could not understand request.'}]), 400


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
        return json.dumps([{'error': 'Could not understand request.'}]), 400
