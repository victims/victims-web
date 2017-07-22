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

from flask import Blueprint, json, Response

from victims.web.cache import cache
from victims.web.models import Hash

v1 = Blueprint('service_v1', __name__)

# Module globals
EOL = datetime.datetime(2013, 6, 1)
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


@v1.route('/status.json')
@cache.cached()
def status():
    """
    Return the status of the service.
    """
    return make_response(json.dumps({
        'eol': EOL.isoformat(),
        'supported': datetime.datetime.now() <= EOL,
        'version': '1',
        'recommended': False,
        'endpoint': '/service/v1/'
    }))


@v1.route('/update/<revision>/')
def update(revision):
    try:
        revision = int(revision)
        result = []
        for item in Hash.objects(_v1__db_version__gte=int(revision)):
            newitem = {}
            newitem['name'] = item['name']
            newitem['vendor'] = item['vendor']
            newitem['status'] = 'In Database'
            newitem['format'] = item['format'].upper()
            newitem['version'] = item['version']
            newitem['submitter'] = item['submitter']
            newitem['hash'] = item['hashes']['sha512']['combined']
            newitem['db_version'] = int(item['_v1']['db_version'])
            newitem['cves'] = ','.join(item.cve_list())
            newitem['submitter'] = str(item['submitter'])
            result.append({'fields': newitem})
        return make_response(json.dumps(result))
    except:
        return error()


@v1.route('/remove/<revision>/')
@cache.cached()
def remove(revision):
    try:
        revision = int(revision)
        return make_response(json.dumps([]))
    except:
        return error()
