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

from os import urandom
from hashlib import sha1
from hmac import HMAC
from uuid import uuid4
from bson.dbref import DBRef

from flask.ext.bcrypt import generate_password_hash
from flask.ext.mongoengine import Document
from mongoengine import (
    StringField, DateTimeField, DictField, BooleanField, EmbeddedDocument,
    EmbeddedDocumentField, ListField, EmailField
)

from victims_web.config import BCRYPT_LOG_ROUNDS


def generate_client_secret(apikey):
    return HMAC(bytes(urandom(24)), apikey, sha1).hexdigest().upper()


def generate_apikey(username):
    apikey = HMAC(uuid4().hex, username).hexdigest()
    return apikey.upper()


def generate_api_tokens(username):
    apikey = generate_apikey(username)
    secret = generate_client_secret(apikey)
    return (apikey, secret)


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

    def jsonify(self, fields=None):
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

        # workaround to remove default values when using only(*fields)
        # Note that this will not work for embedded documents with defaults
        if fields:
            fields = [f.split('.', 1)[0].strip() for f in fields]

        for key in data.keys():
            if key.startswith('_') or (fields and key not in fields):
                del data[key]

        return json.dumps(data, default=handle_special_objs)

    def mongify(self, data):
        for field in self._db_field_map:
            if self._db_field_map[field] in data:
                setattr(self, self._db_field_map[field], data[field])


class Account(ValidatedDocument):
    """
    A user account.
    """
    meta = {'collection': 'users'}

    username = StringField(regex='^[a-zA-Z0-9_\-\.]*$')
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

    def update_api_tokens(self):
        (self.apikey, self.secret) = generate_api_tokens(self.username)

    def set_password(self, plain):
        self.password = generate_password_hash(plain, BCRYPT_LOG_ROUNDS)

    def save(self):
        if self.apikey is None or len(self.apikey) == 0:
            self.update_api_tokens()
        ValidatedDocument.save(self)


class Removal(JsonifyMixin, ValidatedDocument):
    """
    A removal entry
    """
    meta = {'collection': 'removals'}

    date = DateTimeField(default=datetime.datetime.utcnow)
    hash = StringField(regex='^[a-fA-F0-9]*$')
    reason = StringField(
        choices=(
            ('DELETE', 'DELETE'),
            ('WRONG', 'WRONG'),
            ('UPDATE', 'UPDATE')
        ),
        default='DELETE'
    )


class CVE(EmbeddedDocument):
    """
    A CVE record for embedded use.
    """
    id = StringField(required=True)
    addedon = DateTimeField(default=datetime.datetime.utcnow, required=True)


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
    group = StringField()
    format = StringField(regex='^[a-zA-Z0-9_\-\.]*$')
    hashes = DictField(default={})
    vendor = StringField(
        default='UNKNOWN', regex='^[a-zA-Z0-9_\-\.]*$')
    cves = ListField(EmbeddedDocumentField(CVE), default=[])
    status = StringField(
        choices=(('SUBMITTED', 'SUBMITTED'), ('RELEASED', 'RELEASED')),
        default='SUBMITTED')
    metadata = DictField(db_field='meta', default={})
    submitter = StringField()
    submittedon = DateTimeField(default=datetime.datetime.utcnow)

    def cve_list(self):
        """
        Get the CVE(s) associated with this hash object as a list.
        """
        cves = []
        for cve in self.cves:
            cves.append(cve.id)
        return cves

    def append_cves(self, cves=[]):
        """
        Append a list of cves to this instance. The current datetime is used.
        """
        for cve in cves:
            self.cves.append(CVE(id=cve, addedon=datetime.datetime.utcnow()))

    def jsonify(self, fields=None):
        """
        Update jsonify to flatten some fields.
        """
        self.cves = self.cve_list()
        return JsonifyMixin.jsonify(self, fields)

    def mongify(self, data):
        """
        Load from json
        """
        obj = data
        if 'cves' in obj:
            self.append_cves(obj['cves'])
            obj.pop('cves', None)
        JsonifyMixin.mongify(self, obj)


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
    cves = ListField(StringField())
    group = StringField()
    comment = StringField()
    approval = StringField(
        choices=(
            ('REQUESTED', 'REQUESTED'),
            ('PENDING_APPROVAL', 'PENDING APPROVAL'),
            ('APPROVED', 'APPROVED'),
            ('IN_DATABASE', 'IN DATABASE'),
            ('DECLINED', 'DECLINED'),
            ('INVALID', 'INVALID')
        ),
        default='REQUESTED'
    )
    entry = EmbeddedDocumentField(Hash)


# All the models in the event something would like to grab them all
MODELS = [Hash, Account, Submission]
