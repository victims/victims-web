"""
Abandon all hope, ye who enter here.

Charon ferries the victims from their repositories to the judge of limbo.
"""
from abc import ABCMeta, abstractmethod
from uuid import uuid4
from os import makedirs
from os.path import isdir
from logging import getLogger
from victims_web.plugin.maven import (
    Artifact, MavenHttpRemoteRepos, DownloadException
)


DEFAULT_DOWNLOADS_DIR = './downloads'
DEFAULT_LOGGER = getLogger('plugin.charon')


DOWNLOADS_DIR = DEFAULT_DOWNLOADS_DIR
LOGGER = DEFAULT_LOGGER
REPOSITORIES = [
    ('public', 'http://repo1.maven.org/maven2/'),
]
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
        for (name, uri) in REPOSITORIES:
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
            versionId = info['versionId']
            return Artifact(groupId, artifactId, versionId)
        except:
            raise ValueError('Could not identify artifact using provided info')

    def download(self, info):
        artifact = self.make_artifact(info)
        queue = {}
        for repo in self.repos:
            uri = repo.get_artifact_uri(artifact, 'jar')
            sha1 = repo.download_check_sum('sha1', uri)
            if sha1 and sha1 not in queue and sha1.strip != '':
                queue[sha1] = repo

        if len(queue) == 0:
            raise ValueError('No artifact found for %s' % (artifact))

        downloaded = []
        for sha1 in queue:
            repo = queue[sha1]
            prefix = '%s-%s' % (str(uuid4()), repo.name)
            try:
                localfile = repo.download_jar(
                    artifact, DOWNLOADS_DIR, prefix, True)
                downloaded.append((localfile, artifact.to_jip_name(), 'Jar'))
            except DownloadException as de:
                LOGGER.debug(
                    'Skipping download from %s: %s' % (repo.name, de.message)
                )
        return downloaded


MANAGERS = {
    'java': JavaManager(),
}


def _initialize(downloads_dir=DEFAULT_DOWNLOADS_DIR, repositories=[],
                logger=DEFAULT_LOGGER):
    """
    Initialize this ferry.
    """
    global MANAGERS, REPOSITORIES, DOWNLOADS_DIR, LOGGER

    DOWNLOADS_DIR = downloads_dir
    LOGGER = logger

    for (name, uri) in repositories:
        if (name, uri) not in REPOSITORIES:
            REPOSITORIES.append(name, uri)


def initialize():
    """
    Helper method to initiate plugin dynamically. If flask context is
    available, use app config, else use defaults.
    """
    try:
        from flask import current_app as app

        download_dir = app.config.get('DOWNLOADS_FOLDER', DOWNLOADS_DIR)
        repositories = app.config.get('MAVEN_REPOSITORIES', [])

        if not isdir(download_dir):
            makedirs(download_dir)

        _initialize(download_dir, repositories, app.logger)
    except ImportError:
        LOGGER.warn('Skipping dynamic initialization since not in app context')
        _initialize()


def download(group, info):
    """
    Let Charon find the archive(s), download them and give them to minos.
    """
    initialize()
    if group not in MANAGERS:
        ValueError('Unknown group')
    LOGGER.info('[%s] Downloading for %s' % (group, info))
    return MANAGERS[group].download(info)