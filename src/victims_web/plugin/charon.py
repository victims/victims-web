"""
Abandon all hope, ye who enter here.

Charon ferries the victims from their repositories to the judge of limbo.
"""
from abc import ABCMeta, abstractmethod
from uuid import uuid4
from os import makedirs
from os.path import join, isdir
from logging import getLogger
from jip.maven import Artifact
from jip.repository import MavenHttpRemoteRepos
from jip.util import download as mavendownload
from jip.util import DownloadException


REPOSITORIES = [
    ('public', 'http://repo1.maven.org/maven2/'),
]
DOWNLOADS_DIR = './downloads'
LOGGER = getLogger('plugin.charon')
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
        for (name, uri) in REPOSITORIES:
            self._repos.append(MavenHttpRemoteRepos(name, uri))

    @property
    def repos(self):
        return self._repos

    def make_artifact(self, info):
        try:
            groupId = info['groupId']
            artifactId = info['artifactId']
            versionId = info['versionId']
            return Artifact(groupId, artifactId, versionId)
        except:
            ValueError('Could not identify artifact using provided info')

    def _download(self, queue, filename):
        assert filename.endswith('.jar')
        downloaded = []
        for sha1 in queue:
            (repo, uri) = queue[sha1]
            sfilename = '%s-%s-%s' % (str(uuid4()), repo.name, filename)
            localfile = join(DOWNLOADS_DIR, sfilename)
            try:
                with open(localfile, 'w') as local:
                    mavendownload(uri, local)

                if repo.checksum(localfile, 'sha1') != sha1:
                    raise DownloadException('Checksum mismatch.')
            except DownloadException as de:
                LOGGER.debug(
                    'Skipping download from %s: %s' % (repo.name, de.message)
                )
                continue

            downloaded.append((localfile, filename, 'Jar'))

        return downloaded

    def download(self, info):
        artifact = self.make_artifact(info)
        name = artifact.to_jip_name()
        print(name)
        queue = {}
        for repo in self.repos:
            uri = repo.get_artifact_uri(artifact, 'jar')
            sha1 = repo.download_check_sum('sha1', uri)
            if sha1 not in queue:
                queue[sha1] = (repo, uri)

            downloaded = self._download(queue, name)

        if len(downloaded) == 0:
            raise ValueError('No artifact found for %s' % (artifact))

        return downloaded


_initialized = False


def is_initialized():
    """
    Has the module been initialized in context?
    """
    return _initialized


def _initialize():
    """
    Helper method to initiate plugin dynamically if not initiated.
    Initilization is skipped if there is no flask context or if previously
    initialized.
    """
    if is_initialized():
        return

    try:
        from flask import current_app as app
        global _initialized

        download_dir = app.config.get('DOWNLOADS_FOLDER', DOWNLOADS_DIR)
        repositories = app.config.get('MAVEN_REPOSITORIES', [])

        if not isdir(download_dir):
            makedirs(download_dir)

        initialize(download_dir, repositories, app.logger)
        _initialized = True
    except ImportError:
        LOGGER.warn('Skipping dynamic initialization since not in app context')


def initialize(downloads_dir='./downloads', repositories=[], logger=LOGGER):
    """
    Initialize this ferry.
    """
    global MANAGERS, REPOSITORIES, DOWNLOADS_DIR, LOGGER

    DOWNLOADS_DIR = downloads_dir
    LOGGER = logger

    for (name, uri) in repositories:
        if (name, uri) not in REPOSITORIES:
            REPOSITORIES.append(name, uri)

    MANAGERS = {
        'java': JavaManager(),
    }


def download(group, info):
    """
    Let Charon find the archive(s), download them and give them to minos.
    """
    _initialize()
    if group not in MANAGERS:
        ValueError('Unknown group')
    LOGGER.info('[%s] Downloading for %s' % (group, info))
    return MANAGERS[group].download(info)
