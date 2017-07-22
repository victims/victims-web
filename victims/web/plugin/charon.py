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
Abandon all hope, ye who enter here.

Charon ferries the victims from their repositories to the judge of limbo.
"""
from uuid import uuid4

from abc import ABCMeta, abstractmethod

from victims.web import config
from victims.web.plugin.downloader import DownloadException
from victims.web.plugin.maven import Artifact, MavenHttpRemoteRepos

DOWNLOADS_DIR = config.DOWNLOAD_FOLDER
LOGGER = config.LOGGER

# Set up repositories
REPOSITORIES = {
    'java': [('public', 'http://repo1.maven.org/maven2/')],
}
for (name, uri) in config.MAVEN_REPOSITORIES:
    if (name, uri) not in REPOSITORIES:
        REPOSITORIES['java'].append([name, uri])

MANAGERS = {}


class Manager():
    """
    Abstract class for managers
    """
    __meta__ = ABCMeta

    @abstractmethod
    def download(self, info):
        """
        Download archives using info provided. Info is expected to be a dict
        containing archive metadata required.
        """
        raise NotImplemented


class JavaManager(Manager):
    """
    Provide Charon with Java package knowledge using jip
    """
    def __init__(self):
        self._repos = []

    def update_repos(self):
        for (name, uri) in REPOSITORIES['java']:
            if (name, uri) not in self._repos:
                self._repos.append(MavenHttpRemoteRepos(name, uri))

    @property
    def repos(self):
        self.update_repos()
        return self._repos

    def make_artifact(self, info):
        try:
            groupId = info['groupId']
            artifactId = info['artifactId']
            versionId = info['version']
            return Artifact(groupId, artifactId, versionId)
        except:
            raise ValueError('Could not identify artifact using provided info')

    def download(self, info):
        artifact = self.make_artifact(info)
        queue = {}
        for repo in self.repos:
            uri = repo.get_artifact_uri(artifact, 'jar')
            LOGGER.debug("Downloading from: %s" % uri)
            sha1 = repo.download_check_sum('sha1', uri)
            if sha1 is not None and sha1 not in queue:
                queue[sha1] = repo
                # Use first sha1 found in any repo
                break
            else:
                LOGGER.warn("sha1 not found in rep %s" % uri)

        if len(queue) == 0:
            raise ValueError('No artifact found for %s' % (artifact))

        downloaded = []
        for sha1 in queue:
            repo = queue[sha1]
            prefix = '%s-%s' % (str(uuid4()), repo.name)
            try:
                localfile = repo.download_jar(
                    artifact, DOWNLOADS_DIR, prefix, False)
                downloaded.append((localfile, artifact.to_jip_name(), 'Jar'))
            except DownloadException as de:
                LOGGER.debug(
                    'Skipping download from %s: %s' % (repo.name, de.message)
                )
        return downloaded


MANAGERS = {
    'java': JavaManager(),
}


def download(group, info):
    """
    Let Charon find the archive(s), download them and give them to minos.
    """
    if group not in MANAGERS:
        ValueError('Unknown group')
    LOGGER.info('[%s] Downloading for %s' % (group, info))
    return MANAGERS[group].download(info)
