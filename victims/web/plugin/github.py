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

from shutil import rmtree
from subprocess import check_output
from urlparse import urljoin

from os import walk, sep
from os.path import join, isdir
from re import search
from requests import get

from victims.web.config import DOWNLOAD_FOLDER

BASE_URI = 'https://github.com/'
API_URI = 'https://api.github.com/'


class GitHub():

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

    # /repos/:owner/:repo/commits/:sha
    def get_commit(self, sha, **kwargs):
        return self._rest('repos', 'commits/%s' % (sha), **kwargs)


class Repository():

    def __init__(self, user, repo, basedir=DOWNLOAD_FOLDER):
        self.user = user
        self.repo = repo
        self.basedir = basedir
        self.repodir = join(basedir, repo)
        self.repourl = urljoin(BASE_URI, '%s/%s' % (user, repo))

    def is_cloned(self):
        return isdir(self.repodir)

    def execute(self, cmd, *args):
        gitcmd = ['git']

        if cmd != 'clone':
            if not self.is_cloned():
                return None
            gitcmd.append('--git-dir=%s/.git' % (self.repodir))
        else:
            if self.is_cloned():
                return None

        gitcmd.append(cmd)

        for arg in args:
            gitcmd.append(arg)
        output = check_output(gitcmd)

        return output

    def clone(self, force=False, *args):
        if force:
            rmtree(self.repodir)
        self.execute('clone', self.repourl + '.git', self.repodir, *args)

    def pull(self, *args):
        return self.execute('pull', *args)

    def log(self, *args):
        return self.execute('log', *args)

    def diff(self, *args):
        return self.execute('diff', *args)

    def head(self):
        return self.log('-n 1', '--pretty=%H').strip()

    def filter_files(self, files, path, pattern=None):
        filtered = []
        for f in files:
            f = f.strip()
            if f.startswith(path):
                if not pattern or search(pattern, f):
                    filtered.append(f)

        return filtered

    def absolute_filepath(self, relative):
        return join(self.repodir, relative)

    def files_changed(self, start=None, end='HEAD', path='', pattern=None):
        self.pull()
        if start:
            files = self.diff('--name-only', start, end).split()
            return self.filter_files(files, path, pattern)
        else:
            return self.files(self, path, pattern)

    def files(self, path='', pattern=None):
        oldpath = path
        path = join(self.repodir, path)
        files = []
        if isdir(path):
            for root, dirs, fs in walk(path):
                for f in fs:
                    if not pattern or search(pattern, f):
                        # add the relative path
                        files.append(join(
                            root.replace(path, oldpath).strip(sep), f))
        return files
