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
User related functions.
"""
from hmac import HMAC
from hashlib import md5, sha512
from time import strptime, mktime
from datetime import datetime, timedelta

from flask import request

from flask.ext.login import UserMixin, AnonymousUserMixin
from flask.ext.bcrypt import check_password_hash

from victims_web import config
from victims_web.models import Account


# Helper functions
def get_account(value, field='username'):
    """
    Retrieve an Account object.

    :Parameters:
        - `value`: Value to filter by.
        - `field`: Field to filter on. Default field is username.
    """
    return Account.objects(**{field: value}).first()


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
    Checks for the 'Victims-Api' header in the requst and parses the apikey
    and signature
    """
    if 'Victims-Api' not in request.headers:
        raise ValueError('Victims-Api header not present in request')
    (apikey, signature) = request.headers['Victims-Api'].strip().split(':')
    return (apikey, signature)


def api_request_user():
    """
    Get username associated with the API request
    """
    (apikey, _) = api_request_tokens()
    return api_username(apikey)


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


def create_user(username, password, roles=[], email=None):
    new_user = Account()
    new_user.username = username
    new_user.set_password(password)
    if email is not None:
        new_user.email = email.strip()

    new_user.roles = roles
    new_user.active = True

    new_user.validate()
    new_user.save()

    return User(username)


def delete_user(username):
    for account in Account.objects(username=username):
        account.delete()


class VictimsUserMixin(object):

    def __init__(self, user_obj=None):
        self.user_obj = user_obj

    @property
    def username(self):
        if not self.is_anonymous() and self.user_obj:
            return self.user_obj.username
        else:
            return '<Anonymous>'

    def is_active(self):
        if self.user_obj:
            return self.user_obj.active
        return False

    def get_id(self):
        return self.username

    @property
    def roles(self):
        if not self.is_anonymous():
            return self.user_obj.roles
        return []

    def has_role(self, role):
        return role in self.roles

    def __repr__(self):
        if self.is_anonymous():
            return '<User: Anonymous>'
        return '<User: username="%s">' % (self.username)

    def __str__(self):
        return self.username


class User(VictimsUserMixin, UserMixin):
    def __init__(self, username, user_obj=None):
        if not user_obj:
            user_obj = get_account(username)
        VictimsUserMixin.__init__(self, user_obj)


class AnonymousUser(VictimsUserMixin, AnonymousUserMixin):
    pass
