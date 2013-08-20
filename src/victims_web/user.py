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
from flask import redirect, url_for, current_app

from flask.ext.login import current_user
from flask.ext.bcrypt import check_password_hash, generate_password_hash

from victims_web.models import Account

# Helper functions


def authenticate(username, password):
    user = Account.objects(username=str(username)).first()
    if user:
        if check_password_hash(user.password, password):
            return True
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

    new_user.save()

    return User(username)


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

    def is_authenticated(self):
        return self.__authenticated

    def is_active(self):
        return self.__active

    def is_anonymous(self):
        return not self.__authenticated

    def get_id(self):
        return unicode(self.__username)

    def endorsements(self):
        return self.__endorsements

    def has_endorsement(self, name):
        return name in self.__endorsements

    def __repr__(self):
        if self.is_anonymous():
            return '<User: Anonymous>'
        return '<User: username="%s">' % self.__username

    # Read-only properties
    username = property(lambda s: s.__username)
    endorsements = property(lambda s: s.__endorsements)
    active = property(lambda s: s.__active)
    authenticated = property(lambda s: s.__authenticated)
