import datetime

from flask import Blueprint, current_app, json

from victims_web.cache import cache

v1 = Blueprint('service_v1', __name__)

# Module globals
EOL = datetime.datetime(2013, 6, 1)


@v1.route('/status.json')
@cache.cached()
def status():
    """
    Return the status of the service.
    """
    return json.dumps({
        'eol': EOL.isoformat(),
        'supported': datetime.datetime.now() <= EOL,
        'version': '1',
        'recommended': False,
    })


@v1.route('/update/<int:revision>/')
@cache.cached()
def update(revision):
    result = []
    for item in current_app.db.Hash.find(
            {'_v1.db_version': {'$gt': int(revision)}}):
        newitem = {}
        newitem['name'] = item['name']
        newitem['vendor'] = item['vendor']
        newitem['status'] = 'In Database'
        newitem['format'] = item['format'].upper()
        newitem['version'] = item['version']
        newitem['submitter'] = item['submitter']
        newitem['hash'] = item['hashes']['sha512']['combined']
        newitem['db_version'] = int(item['_v1']['db_version'])
        newitem['cves'] = ','.join(item['cves'])
        result.append({'fields': newitem})
    return json.dumps(result)


@v1.route('/remove/<int:revision>/')
@cache.cached()
def remove(revision):
    return json.dumps([])
