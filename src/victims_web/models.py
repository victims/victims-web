import datetime
import hashlib
import re

from mongokit import ValidationError

from flask.ext.mongokit import Document


class RegExValidator(object):

    def __init__(self, rx, is_list=False):
        self.__rx_str = rx
        self.__rx = re.compile(rx)
        self.__is_list = is_list

    def _validate(self, item):
        if bool(self.__rx.match(item)):
            return True
        raise ValidationError('%s must match ' + self.__rx_str)

    def __call__(self, value):
        if self.__is_list:
            for item in value:
                self._validate(item)
        else:
            self._validate(value)
        return True


class Hash(Document):
    __collection__ = 'hashes'

    structure = {
        #'id': int,
        'date': datetime.datetime,
        'name': basestring,
        'version': basestring,
        'format': basestring,
        'hashes': dict,
        'vendor': basestring,
        'cves': list,
        'status': basestring,
        'meta': dict,
        'submitter': basestring,
        'submittedon': datetime.datetime
    }
    use_dot_notation = True
    required_fields = [
        'name', 'version', 'format',
        'status', 'cves', 'submitter']
    default_values = {
        'status': u'SUBMITTED',
        'vendor': u'Unknown',
        #'db_version': None,
        'hashes': {},
        'submittedon': datetime.datetime.utcnow(),
    }
    validators = {
        'name': RegExValidator('^[a-zA-Z0-9_\-\.]*$'),
        'version': RegExValidator('^[a-zA-Z0-9_\-\.]*$'),
        'format': RegExValidator('^[a-zA-Z0-9\-]*$'),
        'vendor': RegExValidator('^[a-zA-Z0-9_ \-]*$'),
        'cves': RegExValidator('^CVE-\d{4}-\d{4}$', True),
        'submitter': RegExValidator('^[a-zA-Z0-9]*$'),
    }


class Account(Document):
    __collection__ = 'users'

    structure = {
        'username': basestring,
        'password': basestring,
        'endorsements': list,
        'active': bool,
        'createdon': datetime.datetime,
        'lastlogin': datetime.datetime,
        'lastip': basestring,
    }

    use_dot_notation = True
    required_fields = ['username', 'password']

    default_values = {
        'endorsements': [],
        'active': False,
        'lastlogin': datetime.datetime.utcnow(),
        'createdon': datetime.datetime.utcnow(),
        'lastip': None,
    }
    validators = {
        'username': RegExValidator('^[a-zA-Z0-9]*$'),
    }


class Traceback(Document):
    __collection__ = 'tracebacks'

    structure = {
        'uid': basestring,
        'ip': basestring,
        'timestamp': datetime.datetime,
        'type': basestring,
        'traceback': basestring,
        'headers': dict,
        'username': basestring,
        'acknowledged': bool,
    }

    default_values = {
        'timestamp': datetime.datetime.utcnow(),
        'acknowledged': False,
        'uid': hashlib.sha1(str(datetime.datetime.utcnow())).hexdigest(),
    }

    required_fields = ['traceback', 'type', 'uid']


# Place all models that should get registered in MODELS
MODELS = [Hash, Account, Traceback]
