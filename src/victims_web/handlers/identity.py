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

from flask import Response, current_app, request
from flask.ext.login import LoginManager, current_user, login_user, logout_user
from flask.ext.principal import (
    Permission, Principal, RoleNeed, UserNeed, identity_loaded
)

from victims_web.config import VICTIMS_ROLES as ROLES
from victims_web.user import User, authenticate, validate_signature


PERMISSIONS = {role: Permission(RoleNeed(role)) for role in ROLES}


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


def require_role(view):
    """
    Ensures that the current user has the required role.
    """
    @wraps(view)
    def decorated(role, *args, **kwargs):
        return PERMISSIONS[role].require(view, args, kwargs)


def login(username, password):
    user_data = authenticate(username, password)
    if user_data:
        user = User(username)
        login_user(user=user)
        return True
    return False


def logout():
    logout_user()


def on_identity_loaded(sender, identity):
    # Set the identity user object
    identity.user = current_user

    # Add the UserNeed to the identity
    if hasattr(current_user, 'username'):
        identity.provides.add(UserNeed(current_user.username))

    # identity with the roles that the user provides
    if hasattr(current_user, 'roles'):
        for role in current_user.roles:
            identity.provides.add(RoleNeed(role.name))


def load_user(userid):
    return User(userid)


def setup_login_manager(app):
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login_user'
    login_manager.login_message = 'You are not authorized to access this resource.'
    login_manager.login_message_category = 'error'
    login_manager.init_app(app)
    login_manager.user_loader(load_user)


def setup_princial(app):
    principal = Principal()
    principal.init_app(app)
    identity_loaded.connect_via(app, on_identity_loaded)


def setup_identity_management(app):
    """
    Helper to setup things during app initialization
    """
    setup_login_manager(app)
