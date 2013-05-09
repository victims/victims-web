import datetime

from functools import wraps
from flask import Blueprint, current_app, json, request

from victims_web.cache import cache
from victims_web.user import authenticate

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


@v2.route('/update/<since>/')
@check_for_auth
@cache.cached()
def update(since):
    """
    Returns all items to add past a specific date in utc.

    :Parameters:
       - `since`: a specific date in utc
    """
    try:
        return serialize_results(current_app.db.Hash.find(
            {'date': {'$gt': datetime.datetime.strptime(
                since, "%Y-%m-%dT%H:%M:%S")}}))
    except Exception:
        return json.dumps([{'error': 'Could not understand request.'}]), 400


@v2.route('/remove/<since>/')
@check_for_auth
@cache.cached()
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
