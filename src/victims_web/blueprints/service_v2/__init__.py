import datetime

from flask import Blueprint, current_app, json

from victims_web.cache import cache

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
    })


@v2.route('/update/<since>/')
@cache.cached()
def update(since):
    """
    Returns all items to add past a specific date in utc.

    :Parameters:
       - `since`: a specific date in utc
    """
    try:
        return serialize_results(current_app.db.Hash.find(
            {'date': {'$gt': datetime.datetime.strptime(since, "%Y-%m-%dT%H:%M:%S")}}))
    except Exception, ex:
        return json.dumps([{'error': 'Could not understand request.'}])


@v2.route('/remove/<since>/')
@cache.cached()
def remove(since):
    """
    Returns all items to remove past a specific date in utc.

    :Parameters:
       - `since`: a specific date in utc
    """
    return json.dumps([])
