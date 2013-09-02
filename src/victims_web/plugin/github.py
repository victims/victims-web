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
GitHub plugin
"""

from urlparse import urljoin
from requests import get


class GitHub():
    API_URI = 'https://api.github.com/'

    def __init__(self, user, repo):
        self.user = user
        self.repo = repo

    def _rest(self, service, endpoint, **kwargs):
        uripath = '/'.join([service, self.user, self.repo, endpoint])
        uri = urljoin(self.API_URI, uripath)
        resp = get(uri, params=kwargs)
        return resp.json()

    def get_commits(self, **kwargs):
        return self._rest('repos', 'commits', **kwargs)

    #/repos/:owner/:repo/commits/:sha
    def get_commit(self, sha, **kwargs):
        return self._rest('repos', 'commits/%s' % (sha), **kwargs)
