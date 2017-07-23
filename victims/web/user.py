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

from flask_login import UserMixin, AnonymousUserMixin

from victims.web.models import Account


# Helpers
def create_user(username, password, email=None, roles=[]):
    """
    Create a new user

    :Parameters:
        - `username`: User Name
        - `password`: Plain-text password
        - `roles`: A list of roles to assign the user
        - `email`: The user's email address
    """
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


def get_account(value, field='username'):
    """
    Retrieve an Account object.

    :Parameters:
        - `value`: Value to filter by.
        - `field`: Field to filter on. Default field is username.
    """
    return Account.objects(**{field: value}).first()


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

    def get_account(self):
        if not self.is_anonymous():
            get_account(self.username)
        return None

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
