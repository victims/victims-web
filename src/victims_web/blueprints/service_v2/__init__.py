import datetime

from functools import wraps
from flask import Blueprint, current_app, json, request

from victims_web.cache import cache
from victims_web.user import authenticate
from victims_web.models import Hash

v2 = Blueprint('service_v2', __name__)

# Module globals
EOL = None


def serialize_results(items):
    """
    Serializes results based on query results.

    :Parameters:
       - `items`: The items to serialize.
    """
    result = []
    for item in items:
        # Drop the mongodb _id from the service
        item.pop('_id')
        item['date'] = item['date'].isoformat()
        item['submittedon'] = item['submittedon'].isoformat()
        result.append({'fields': item})
    return json.dumps(result)


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
                result[key] = item[key]
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
    return json.dumps(result)


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
@cache.memoize(unless=isPost)
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
        if isPost():
            return filter_results(items, json.loads(request.data))
        else:
            return serialize_results(items)
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
