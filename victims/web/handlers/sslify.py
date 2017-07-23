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
Custom SSLify Wrapper module
"""

from flask import request, current_app
from flask_sslify import SSLify


SSL_EXCLUDE = []


class VSSLify(SSLify):

    def redirect_to_ssl(self):
        if request.url_rule:
            endpoint = request.url_rule.endpoint
            if current_app.view_functions[endpoint] in SSL_EXCLUDE:
                return

        super(VSSLify, self).redirect_to_ssl()


def ssl_exclude(view):
    if view not in SSL_EXCLUDE:
        SSL_EXCLUDE.append(view)
