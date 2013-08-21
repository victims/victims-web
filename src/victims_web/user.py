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
from uuid import uuid4
from hashlib import md5, sha512
from time import strptime, mktime
from datetime import datetime, timedelta

from flask import redirect, request, url_for, current_app

from flask.ext.login import current_user, make_secure_token
from flask.ext.bcrypt import check_password_hash, generate_password_hash

from victims_web.models import Account


# Helper functions
def generate_client_secret(apikey):
    return str(make_secure_token(apikey).upper())


def generate_apikey(username):
    apikey = HMAC(uuid4().hex, username).hexdigest()
    return apikey.upper()


def authenticate(username, password):
    user = Account.objects(username=str(username)).first()
    if user:
        if check_password_hash(user.password, password):
            return True
    return False


def generate_signature(apikey, method, path, content_type, date, data_md5):
    ordered = [method, path, content_type, date, data_md5]
    string = ''
    for content in ordered:
        if content is None:
            raise ValueError('Required header not found')
        string += str(content)

    user = Account.objects(apikey=apikey).first()
    if user is None:
        raise ValueError('Invalid apikey')
    if user.secret is None:
        raise ValueError('No client secret known')

    return HMAC(user.secret, string.lower(), sha512).hexdigest().upper()


def validate_signature():
    if 'Victims-Api' not in request.headers:
        return False

    expiry = current_app.config.get('API_REQUEST_EXPIRY_MINS', 3)

    try:
        (apikey, signature) = request.headers['Victims-Api'].strip().split(':')
        t = strptime(request.headers['Date'], '%a, %d %b %Y %H:%M:%S %Z')
        request_date = datetime.fromtimestamp(mktime(t))
        delta = datetime.utcnow() - request_date
        if delta > timedelta(minutes=expiry) or delta < timedelta(0):
            return False
        expected = generate_signature(
            apikey, request.method, request.path,
            request.headers['Content-Type'],
            request.headers['Date'],
            md5(request.data)
        )
        return signature.upper() == expected
    except:
        return False


def create_user(username, password, endorsements=[], email=None):
    passhash = generate_password_hash(
        password, current_app.config['BCRYPT_LOG_ROUNDS'])
    new_user = Account()
    new_user.username = username
    new_user.password = passhash
    if email is not None:
        new_user.email = email.strip()

    all_endorsements = {}
    for end in endorsements:
        all_endorsements[end] = end

    new_user.endorsements = all_endorsements
    new_user.active = True

    new_user.apikey = generate_apikey(username)
    new_user.secret = generate_client_secret(new_user.apikey)

    new_user.validate()
    new_user.save()

    return User(username)


def delete_user(username):
    for account in Account.objects(username=username):
        account.delete()


def endorsements_required(endorsements, always_allow=['admin']):
    """
    Enforces required endorsements.

    :Parameters:
       - `endorsements`: List of endorsement names *required* to access
           the resource
       - `always_allow`: List of endorsements which if the user has at
           least one applied to their user let's them access the resource.
    """
    def wraps(fn):

        def decorated_view(*args, **kwargs):
            approved = False
            for always_allowed in always_allow:
                if current_user.has_endorsement(always_allowed):
                    approved = True
            if not approved:
                for endorsement in endorsements:
                    if not current_user.has_endorsement(endorsement):
                        return redirect(url_for('auth.login_user'))
            return fn(*args, **kwargs)

        return decorated_view

    return wraps


def user_allowed(user, endorsements):
    if user.has_endorsement('admin'):
        return True
    for endorsement in endorsements:
        if current_user.has_endorsement(endorsement):
            return True
    return redirect(url_for('auth.login_user'))


class User(object):

    def __init__(self, username, user_obj=None):
        """
        Creates a user instance.
        """
        self.__authenticated = True
        self.__active = False
        self.__username = username
        self.__endorsements = []

        if not user_obj:
            user_obj = Account.objects(username=username).first()

        self.__active = user_obj.active
        self.__endorsements = user_obj.endorsements

    @property
    def authenticated(self):
        return self.__authenticated

    @property
    def active(self):
        return self.__active

    @property
    def endorsements(self):
        return self.__endorsements

    @property
    def username(self):
        return self.__username

    def is_authenticated(self):
        return self.authenticated

    def is_anonymous(self):
        return not self.authenticated

    def is_active(self):
        return self.active

    def get_id(self):
        return unicode(self.__username)

    def has_endorsement(self, name):
        return name in self.__endorsements

    def __repr__(self):
        if self.is_anonymous():
            return '<User: Anonymous>'
        return '<User: username="%s">' % (self.username)

    def __str__(self):
        if self.is_anonymous():
            return 'Anonymous'
        return self.username
