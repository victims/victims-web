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
Data models.
"""

import datetime

import json

from bson.dbref import DBRef

from flask.ext.mongoengine import Document
from mongoengine import (StringField, DateTimeField, DictField, BooleanField,
                         EmbeddedDocument, EmbeddedDocumentField, ListField,
                         EmailField)


class ValidatedDocument(Document):
    """
    Extended MongoEngine document which can use custom validators.
    """

    _pre_save_hooks = []

    meta = {
        'allow_inheritance': False,
        'abstract': True
    }

    def save(self, *args, **kwargs):
        """
        Saves the document to the database.

        :Parameters:
           - `args`: All non-keyword args.
           - `kwargs`: All keyword args.
        """
        for hook in self._pre_save_hooks:
            hook(self)

        super(ValidatedDocument, self).save(*args, **kwargs)


class JsonifyMixin(object):

    def jsonify(self):
        """
        Converts an instance into json.
        """

        def handle_special_objs(obj):
            if hasattr(obj, 'isoformat'):
                return obj.isoformat()
            elif isinstance(obj, DBRef):
                return str(Account.objects.get(id=obj.id).username)
            return str(obj)

        data = self.to_mongo()

        for key in data.keys():
            if key.startswith('_'):
                del data[key]

        return json.dumps(data, default=handle_special_objs)


class Account(ValidatedDocument):
    """
    A user account.
    """
    meta = {'collection': 'users'}

    username = StringField(regex='^[a-zA-Z0-9]*$')
    password = StringField()
    endorsements = DictField(default={})
    active = BooleanField(default=False)
    createdon = DateTimeField(default=datetime.datetime.utcnow)
    lastlogin = DateTimeField(default=datetime.datetime.utcnow)
    lastip = StringField()
    email = EmailField()
    apikey = StringField(min_length=32, max_length=32)
    secret = StringField(min_length=40, max_length=40)
    lastapi = DateTimeField(default=None)

    def __str__(self):
        return str(self.username)


class Hash(JsonifyMixin, ValidatedDocument, EmbeddedDocument):
    """
    A hash record.
    """
    meta = {'collection': 'hashes'}

    # Temporary item for v1 mapping
    _v1 = DictField(default={})
    date = DateTimeField(default=None)
    hash = StringField(regex='^[a-fA-F0-9]*$')
    name = StringField(regex='^[a-zA-Z0-9_\-\.]*$')
    version = StringField(
        default='UNKNOWN', regex='^[a-zA-Z0-9_\-\.]*$')
    format = StringField(regex='^[a-zA-Z0-9_\-\.]*$')
    hashes = DictField(default={})
    vendor = StringField(
        default='UNKNOWN', regex='^[a-zA-Z0-9_\-\.]*$')
    cves = DictField(default={})
    status = StringField(
        choices=(('SUBMITTED', 'SUBMITTED'), ('RELEASED', 'RELEASED')),
        default='SUBMITTED')
    metadata = DictField(db_field='meta', default={})
    submitter = StringField()
    submittedon = DateTimeField(default=datetime.datetime.utcnow)

    def jsonify(self):
        """
        Update jsonify to flatten some fields.
        """
        new_cves = []
        # Workaround to handle both old lists, and newer dicts
        for cve in self.cves:
            new_cves.append(cve)
        self.cves = new_cves

        return JsonifyMixin.jsonify(self)

    def load_json(self, submitter, json_data):
        """
        Load from json
        """
        fields = [
            'name', 'version', 'format', 'vendor', 'hash', 'hashes', 'meta'
        ]
        field_names = {
            'meta': 'metadata',
        }
        for field in fields:
            key = field_names.get(field, field)
            if field in json_data:
                setattr(self, key, json_data[field])

        cves = {}
        for cve in json_data['cves']:
            cves[cve] = datetime.datetime.utcnow()

        self.cves = cves
        self.submitter = submitter
        self.submittedon = datetime.datetime.utcnow()


class Submission(JsonifyMixin, ValidatedDocument):
    """
    A Submission Hash
    """
    meta = {'collection': 'submissions'}

    submitter = StringField()
    submittedon = DateTimeField(default=datetime.datetime.utcnow)
    source = StringField()
    filename = StringField()
    format = StringField(regex='^[a-zA-Z0-9_\-\.]*$')
    metadata = DictField(default={})
    cves = ListField()
    group = StringField()
    comment = StringField()
    approval = StringField(
        choices=(
            ('REQUESTED', 'REQUESTED'),
            ('PENDING_APPROVAL', 'PENDING_APPROVAL'),
            ('APPROVED', 'APPROVED'),
            ('IN_DATABASE', 'IN_DATABASE'),
            ('DECLINED', 'DECLINED'),
            ('INVALID', 'INVALID')
        ),
        default='REQUESTED'
    )
    entry = EmbeddedDocumentField(Hash)


# All the models in the event something would like to grab them all
MODELS = [Hash, Account, Submission]
