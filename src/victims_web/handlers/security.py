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
Identity handlers.
"""
from functools import wraps
from urlparse import urlparse, urljoin

from flask import Response, current_app, request, flash
from flask.ext.login import (
    LoginManager, current_user, login_user, logout_user)

from victims_web.user import (
    AnonymousUser, User, authenticate, validate_signature)


def safe_redirect_url():
    forward = request.args.get('next')
    if forward:
        host_url = urlparse(request.host_url)
        redirect_url = urlparse(urljoin(request.host_url, forward))
        if redirect_url.scheme in ('http', 'https') and \
                host_url.netloc == redirect_url.netloc:
            return forward
        else:
            flash('Invalid redirect requested.', category='info')
    return None


def basicauth(view):
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


def apiauth(view):
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


def require_role(view):
    """
    Ensures that the current user has the required role.
    """
    @wraps(view)
    def decorated(role, *args, **kwargs):
        if current_user.has_role(role):
            return view(*args, **kwargs)

        return Response('Forbidden', status=403)

    return decorated


def require_one_role(view):
    """
    Ensures that the current_user has one of the provided roles
    """
    @wraps(view)
    def decorated(roles, *args, **kwargs):
        for role in roles:
            if role in current_user.roles:
                return view(*args, **kwargs)

        return Response('Forbidden', status=403)

    return decorated


def login(username, password):
    user_data = authenticate(username, password)
    if user_data:
        user = User(username)
        login_user(user=user)
        return True
    return False


def logout():
    logout_user()


def load_user(username):
    return User(username)


def setup_login_manager(app):
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login_user'
    login_manager.login_message = 'Resource access not authorized.'
    login_manager.login_message_category = 'error'
    login_manager.anonymous_user = AnonymousUser
    login_manager.init_app(app)
    login_manager.user_loader(load_user)


def setup_security(app):
    """
    Helper to setup things during app initialization
    """
    setup_login_manager(app)
