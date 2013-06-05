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
Connects specific auth related actions with functions.
"""

import datetime

from flask import request
from flask.ext import login

from victims_web.models import Account


def log_login(app, user):
    """
    Logs the users login.
    """
    app.logger.info(user.username + " logged in")


def update_login_details(app, user):
    """
    Updates user information upon login.
    """
    user_obj = Account.objects(username=user.username).first()
    user_obj.lastlogin = datetime.datetime.utcnow()
    try:
        user_obj.lastip = request.headers.getlist('X-Forwarded-For')[0]
    except:
        user_obj.lastip = request.remote_addr
    user_obj.save()


login.user_logged_in.connect(log_login)
login.user_logged_in.connect(update_login_details)
