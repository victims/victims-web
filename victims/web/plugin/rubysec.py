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

from urlparse import urljoin

from mongoengine import (
    StringField, URLField, LongField, DateTimeField, ListField)
from yaml import load

from victims.web.models import Hash, ValidatedDocument, JsonifyMixin
from victims.web.plugin import PluginConfig
from victims.web.plugin.github import Repository

_CONFIG = PluginConfig('rubysec')


class RubySecAdvisory(JsonifyMixin, ValidatedDocument):
    """
    A RubySec Advisory
    """
    meta = {'collection': 'rubysec'}

    source = URLField()
    title = StringField()
    description = StringField()
    url = URLField()
    cve = StringField()
    cvss_2 = StringField()
    osvdb = LongField()
    date = DateTimeField()
    gem = StringField()
    framework = StringField()
    patched_versions = ListField(StringField())

    def get_hash_entry(self):
        entry = Hash()
        entry.group = 'ruby'
        entry.submitter = 'plugin.rubysec'
        entry.append_cves([
            'CVE-%s' % (cve) for cve in self.cve.strip().split(',')
        ])
        return entry

    def save(self):
        # add/update a hash entry
        ValidatedDocument.save(self)


def get_advisory(source):
    advisory = RubySecAdvisory.objects(source=source).first()
    if advisory is None:
        advisory = RubySecAdvisory()
        advisory.source = source
    return advisory


class RubySecDatabase():
    GITHUB_USER = 'rubysec'
    GITHUB_REPO = 'ruby-advisory-db'

    def __init__(self):
        self.repository = Repository(self.GITHUB_USER, self.GITHUB_REPO)
        if not self.repository.is_cloned():
            self.repository.clone()

    def update(self):
        previous = _CONFIG.get.prev_head
        files = []
        self.repository.pull()
        files = self.repository.files_changed(
            previous, 'HEAD', 'gems/', '\.yml')

        for f in files:
            content = open(self.repository.absolute_filepath(f), 'r')
            obj = load(content)
            advisory = get_advisory(
                urljoin(self.repository.repourl, f.strip()))
            advisory.mongify(obj)
            advisory.save()

        _CONFIG.prev_head = self.repository.head()
