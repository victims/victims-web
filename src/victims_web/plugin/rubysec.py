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

from victims_web.plugin.github import GitHub


class RubySecDatabase():
    GITHUB_USER = 'rubysec'
    GITHUB_REPO = 'ruby-advisory-db'

    def __init__(self):
        self.github = GitHub(self.GITHUB_USER, self.GITHUB_REPO)
        self.last_updated = '2013-07-14T16:00:49Z'

    def get_updated_files(self):
        updated = []
        commits = self.github.get_commits(
            path='gems/', since=self.last_updated)
        for commit in commits:
            for f in self.github.get_commit(commit['sha']).get('files', []):
                fileurl = f['raw_url']
                if fileurl not in updated:
                    updated.append(fileurl)
        return updated
