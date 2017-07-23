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
from datetime import datetime, timedelta
from functools import wraps
from hashlib import md5, sha512
from hmac import HMAC
from time import strptime, mktime
from urlparse import urlparse, urljoin

from flask import Response, request, flash
from flask_bcrypt import check_password_hash
from flask_login import (
    LoginManager, current_user, login_user, logout_user, user_logged_in)

from victims.web import config
from victims.web.user import AnonymousUser, User, get_account


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


def authenticate(username, password):
    user = get_account(str(username))
    if user:
        if check_password_hash(user.password, password):
            return True
    return False


def generate_signature(apikey, method, path, date, md5sums):
    md5sums.sort()
    ordered = [method, path, date] + md5sums
    string = ''
    for content in ordered:
        if content is None:
            raise ValueError('Required header not found')
        string += str(content)

    user = get_account(apikey, 'apikey')
    if user is None:
        raise ValueError('Invalid apikey')
    if user.secret is None:
        raise ValueError('No client secret known')

    return HMAC(
        key=bytes(user.secret),
        msg=string.lower(),
        digestmod=sha512
    ).hexdigest().upper()


def api_username(apikey):
    """
    Fetch the username who holds a given apikey. Returns None if no match.

    :Parameters:
        - `apikey`: API Key to search for.
    """
    account = get_account(apikey, 'apikey')
    if account:
        return account.username
    return None


def api_request_tokens():
    """
    Checks for the VICTIMS_API_HEADER (default: X-Victims-Api) in the requst
    and parses the apikey and signature
    """
    header = config.VICTIMS_API_HEADER
    if header not in request.headers:
        raise ValueError('%s header not present in request' % (header))
    (apikey, signature) = request.headers[header].strip().split(':')
    return (apikey, signature)


def api_request_user():
    """
    Get username associated with the API request
    """
    if request.authorization:
        return request.authorization.username

    (apikey, _) = api_request_tokens()
    return api_username(apikey)


def api_request_user_account():
    """
    Get the account associated with the current API requrst
    """
    username = api_request_user()
    return get_account(username)


def validate_signature():
    expiry = config.API_REQUEST_EXPIRY_MINS
    try:
        (apikey, signature) = api_request_tokens()

        t = strptime(request.headers['Date'], '%a, %d %b %Y %H:%M:%S %Z')
        request_date = datetime.fromtimestamp(mktime(t))
        delta = datetime.utcnow() - request_date
        if delta > timedelta(minutes=expiry) or delta < timedelta(0):
            return False

        # prepare path with args
        path = request.path
        if len(request.args) > 0:
            args = []
            for key in request.args.keys():
                args.append('%s=%s' % (key, request.args[key]))
            path = '%s?%s' % (path, '&'.join(args))

        # prepare md5 sums
        md5sums = []
        if len(request.data) > 0:
            md5sums.append(md5(request.data).hexdigest())

        if len(request.files) > 0:
            for f in request.files.values():
                md5sums.append(md5(f.stream.getvalue()).hexdigest())

        expected = generate_signature(
            apikey, request.method, path,
            request.headers['Date'],
            md5sums
        )
        return signature.upper() == expected
    except Exception as e:
        config.LOGGER.debug(e)
        return False


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
                request.authorization.username,
                request.authorization.password)
            if not valid:
                return Response('Forbidden', status=403)
        return view(*args, **kwargs)

    return decorated


def update_api_access():
    """
    Update user information upon API access
    """
    user = api_request_user_account()
    if user:
        user.lastapi = datetime.utcnow()
        user.save()


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
                request.authorization.username,
                request.authorization.password)

        if not valid:
            return Response('Forbidden', mimetype='application/json',
                            status=403)

        update_api_access()
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


def log_login(app, user):
    """
    Logs the users login.
    """
    app.logger.info(user.username + " logged in")


def update_login_details(app, user):
    """
    Updates user information upon login.
    """
    account = user.user_obj
    account.lastlogin = datetime.utcnow()
    try:
        account.lastip = request.headers.getlist('X-Forwarded-For')[0]
    except:
        account.lastip = request.remote_addr
    account.save()
    user.user_obj.reload()


def on_login(app, user):
    """
    Actions to perform when a user is logged in.
    """
    log_login(app, user)
    update_login_details(app, user)


def login(username, password):
    """
    Login, given a username/pasword combination. Returns True if successful,
    else return False.
    """
    user_data = authenticate(username, password)
    if user_data:
        user = User(username)
        login_user(user=user)
        return True
    return False


def logout():
    """
    Helper to logout the current user.
    """
    logout_user()


def load_user(username):
    return User(username)


def setup_login_manager(app):
    """
    Configure the LoginManager for the provided app.
    """
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login_user'
    login_manager.login_message = 'Resource access not authorized.'
    login_manager.login_message_category = 'error'
    login_manager.anonymous_user = AnonymousUser
    login_manager.init_app(app)
    login_manager.user_loader(load_user)
    user_logged_in.connect(on_login, app)


def setup_security(app):
    """
    Helper to setup things during app initialization
    """
    setup_login_manager(app)
