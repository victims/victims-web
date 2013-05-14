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
Version 2 of the webservice. Note that service versions are not related to
application versions!
"""
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
        'endpoint': '/service/v1/'
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
        newitem['cves'] = ','.join(item['cves'].keys())
        result.append({'fields': newitem})
    return json.dumps(result)


@v1.route('/remove/<int:revision>/')
@cache.cached()
def remove(revision):
    return json.dumps([])
