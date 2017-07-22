# The contents of this file has been derrived and/or shamelessly copied from
# the jip project at https://github.com/sunng87/jip
#
# Copyright (C) 2011 Sun Ning<classicning@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

from logging import getLogger
from string import Template
from time import strptime, mktime
from urllib2 import urlopen, HTTPError
from xml.etree import ElementTree

from os.path import join

from victims.web.plugin.downloader import \
    download, download_string, DownloadException

USER_AGENT = 'victims-web-plugin/maven'
BUF_SIZE = 4096

logger = getLogger('plugin.maven')


class Artifact(object):

    def __init__(self, group, artifact, version=None):
        self.group = group
        self.artifact = artifact
        self.version = version
        self.timestamp = None
        self.build_number = None
        self.exclusions = []
        self.repos = None

    def to_jip_name(self, pattern="$artifact-$version.$ext", ext="jar"):
        template = Template(pattern)
        filename = template.substitute({
            'group': self.group,
            'artifact': self.artifact,
            'version': self.version,
            'ext': ext
        })
        return filename

    def to_maven_name(self, ext):
        group = self.group.replace('.', '/')
        return "%s/%s/%s/%s-%s.%s" % (
            group, self.artifact, self.version, self.artifact, self.version,
            ext
        )

    def to_maven_snapshot_name(self, ext):
        group = self.group.replace('.', '/')
        version_wo_snapshot = self.version.replace('-SNAPSHOT', '')
        return "%s/%s/%s/%s-%s-%s-%s.%s" % (
            group, self.artifact, self.version, self.artifact,
            version_wo_snapshot, self.timestamp, self.build_number, ext
        )

    def __eq__(self, other):
        if isinstance(other, Artifact):
            return (
                other.group == self.group and
                other.artifact == self.artifact and
                other.version == self.version
            )
        else:
            return False

    def __str__(self):
        return "%s:%s:%s" % (self.group, self.artifact, self.version)

    def __repr__(self):
        return self.__str__()

    def is_snapshot(self):
        return self.version.find('SNAPSHOT') > 0

    def is_same_artifact(self, other):
        # TODO: need to support wildcard
        group_match = True if (
            self.group == '*' or
            other.group == '*'
        ) else self.group == other.group
        artif_match = True if (
            self.artifact == '*' or
            other.artifact == '*'
        ) else self.artifact == other.artifact
        return group_match and artif_match

    @classmethod
    def from_id(cls, artifact_id):
        group, artifact, version = artifact_id.split(":")
        artifact = Artifact(group, artifact, version)
        return artifact


class MavenRepos(object):

    def __init__(self, name, uri):
        self.name = name
        self.uri = uri

    def __eq__(self, other):
        if isinstance(other, MavenRepos):
            return self.uri == other.uri
        else:
            return False

    def get_artifact_uri(self, artifact, ext):
        pass

    def download_jar(self, artifact, local_path, prefix='', async=True):
        """
        download or copy file to local path, raise exception when failed
        """
        pass

    def download_pom(self, artifact):
        """ return a content string """
        pass

    def last_modified(self, artifact):
        """ return last modified timestamp """
        pass

    def download_check_sum(self, checksum_type, origin_file_name):
        """
        return pre calculated checksum value, only avaiable for remote repos
        """
        pass


class MavenHttpRemoteRepos(MavenRepos):

    def __init__(self, name, uri):
        MavenRepos.__init__(self, name, uri)
        self.pom_cache = {}
        self.pom_not_found_cache = []

    def download_jar(self, artifact, local_path, prefix='', async=True):
        maven_path = self.get_artifact_uri(artifact, 'jar')
        logger.info('[Downloading] jar from %s' % maven_path)
        local_jip_path = join(
            local_path, '%s-%s' % (prefix, artifact.to_jip_name())
        )
        local_f = open(local_jip_path, 'w')
        download(maven_path, local_f, async)
        logger.info('[Finished] %s downloaded ' % maven_path)
        return local_jip_path

    def download_pom(self, artifact):
        if artifact in self.pom_not_found_cache:
            return None

        if artifact in self.pom_cache:
            return self.pom_cache[artifact]

        if artifact.is_snapshot():
            snapshot_info = self.get_snapshot_info(artifact)
            if snapshot_info is not None:
                ts, bn = snapshot_info
                artifact.timestamp = ts
                artifact.build_number = bn

        maven_path = self.get_artifact_uri(artifact, 'pom')
        try:
            logger.info('[Checking] pom file %s' % maven_path)
            data = download_string(maven_path)
            # cache
            self.pom_cache[artifact] = data
            return data
        except DownloadException:
            self.pom_not_found_cache.append(artifact)
            logger.info('[Skipped] Pom file not found at %s' % maven_path)
            return None

    def get_artifact_uri(self, artifact, ext):
        if not artifact.is_snapshot():
            maven_name = artifact.to_maven_name(ext)
        else:
            maven_name = artifact.to_maven_snapshot_name(ext)

        if self.uri.endswith('/'):
            maven_path = self.uri + maven_name
        else:
            maven_path = self.uri + '/' + maven_name

        return maven_path

    def get_snapshot_info(self, artifact):
        metadata_path = self.get_metadata_path(artifact)

        try:
            data = download_string(metadata_path)
            eletree = ElementTree.fromstring(data)
            timestamp = eletree.findtext('versioning/snapshot/timestamp')
            build_number = eletree.findtext('versioning/snapshot/buildNumber')

            return (timestamp, build_number)
        except DownloadException:
            return None

    def get_metadata_path(self, artifact):
        group = artifact.group.replace('.', '/')
        metadata_path = "%s/%s/%s/%s/maven-metadata.xml" % (
            self.uri, group, artifact.artifact, artifact.version
        )
        return metadata_path

    def last_modified(self, artifact):
        metadata_path = self.get_metadata_path(artifact)
        try:
            fd = urlopen(metadata_path)
            if 'last-modified' in fd.headers:
                ts = fd.headers['last-modified']
                fd.close()
                last_modified = strptime(ts, '%a, %d %b %Y %H:%M:%S %Z')
                return mktime(last_modified)
            else:
                fd.close()
                return 0
        except HTTPError:
            return None

    def download_check_sum(self, checksum_type, origin_file_name):
        """
        return pre calculated checksum value, only avaiable for remote repos
        """
        checksum_url = origin_file_name + "." + checksum_type
        try:
            data = download_string(checksum_url)
            return data
        except DownloadException:
            return None
