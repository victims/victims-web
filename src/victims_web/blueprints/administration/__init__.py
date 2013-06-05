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
Administration interface.
"""

from flask.ext.admin.base import Admin, AdminIndexView, MenuLink
from flask.ext.admin.contrib.mongoengine import ModelView
from victims_web.models import Account, Hash

from flask.ext import login


class ViewRequiresAuthorization(object):
    """
    All admin views should mix this in.
    """

    def is_accessible(self):
        """
        The user must be authenticated and have the admin endorsement.
        """
        if login.current_user.is_authenticated():
            if 'admin' in login.current_user.endorsements:
                return True
        return False


class SafeAdminIndexView(ViewRequiresAuthorization, AdminIndexView):
    """
    Mixes in ViewRequiresAuthorization to require authorization.
    """
    pass


class AccountView(ModelView):
    column_filters = ('username', )
    column_exclude_list = ('password', )


class HashView(ModelView):
    column_filters = ('name', )
    column_list = ('name', 'version', 'format',
                   'status', 'submittedon', 'date')


def administration_setup(app):
    """
    Hack to use the backend administration.
    """
    administration = Admin(
        name="Victims Admin", index_view=SafeAdminIndexView())
    administration.init_app(app)
    administration.add_view(ModelView(Account))
    administration.add_view(HashView(Hash))

    # Add links
    administration.add_link(MenuLink(name='Front End', endpoint='ui.index'))
    administration.add_link(MenuLink(
        name='Logout', endpoint='auth.logout_user'))

    return administration
