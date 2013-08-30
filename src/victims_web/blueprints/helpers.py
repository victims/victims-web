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
Helpers that can be reused in blueprints.
"""
from urlparse import urlparse, urljoin
from functools import wraps
from flask import Response, current_app, request, flash
from victims_web.user import authenticate, validate_signature


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


def check_api_auth(view):
    """
    Checks for a valid signature in api request. If VICTIMS-API header is not
    present, we try basic auth. If neither is valid, we return a 403.
    """

    @wraps(view)
    def decorated(*args, **kwargs):
        valid = False
        valid = validate_signature()

        if not valid and request.authorization:
            # fallback to basic auth
            valid = authenticate(
                current_app,
                request.authorization.username,
                request.authorization.password)

        if not valid:
            return Response('Forbidden', mimetype='application/json',
                            status=403)

        return view(*args, **kwargs)

    return decorated


def safe_redirect_url():
    forward = request.args.get('next')
    if forward:
        host_url = urlparse(request.host_url)
        redirect_url = urlparse(urljoin(request.host_url, forward))
        if redirect_url.scheme in ('http', 'https') and \
                host_url.netloc == redirect_url.netloc:
            return forward
        else:
            flash('Invalid redirect: %s' % (forward), category='info')
    return None
