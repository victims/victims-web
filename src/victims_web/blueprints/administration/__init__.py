import datetime

from flask.ext.admin import Admin, AdminIndexView
from flask.ext import wtf
from flask.ext.admin.contrib.pymongo import ModelView
from flask_admin.contrib.pymongo.filters import FilterEqual

from flask.ext import login


class ViewRequiresAuthorization(object):
    """
    All admin views should mix this in.
    """

    def is_accessible(self):
        """
        The user must be authenticated and have the admin endorsement.
        """
        if login.current_user.is_authenticated():
            if 'admin' in login.current_user.endorsements:
                return True
        return False


class SafeAdminIndexView(ViewRequiresAuthorization, AdminIndexView):
    """
    Mixes in ViewRequiresAuthorization to require authorization.
    """
    pass


# TODO: Fix me :-)
from flask.ext.mongokit import Connection



class HashForm(wtf.Form):
    """
    Defines a Hash's form.
    """
    name = wtf.TextField('name')
    version = wtf.TextField('version')
    format = wtf.TextField('format')
    date = wtf.DateTimeField('date')
    vendor = wtf.TextField('vendor')
    cves = wtf.FieldList(wtf.TextField('cves'))
    submitter = wtf.TextField('submitter')
    submittedon = wtf.DateTimeField('submittedon')

    status = wtf.SelectField('status', choices=[
        ('SUBMITTED', 'SUBMITTED'), ('RELEASED', 'RELEASED')])

    def validate_status(form, field):
        """
        Set release date when moved to RELEASED status.
        """
        if form.status.data == 'RELEASED':
            form.date.data = datetime.datetime.utcnow()
        else:
            form.date.data = None

class AccountForm(wtf.Form):
    """
    Defines an Account's form.
    """
    username = wtf.TextField('username')
    endorsements = wtf.FieldList(wtf.TextField('endorsements'))
    active = wtf.BooleanField('active')
    createdon = wtf.DateTimeField('createdon')
    lastlogin = wtf.DateTimeField('lastlogin')
    lastip = wtf.TextField('lastip')


class TracebackForm(wtf.Form):
    """
    Defines a Traceback's form.
    """
    uid = wtf.TextField('uid')
    ip = wtf.TextField('ip')
    acknowledged = wtf.BooleanField('acknowledged')
    timestamp = wtf.DateTimeField('timestamp')
    type = wtf.TextField('type')
    traceback = wtf.TextAreaField('traceback')
    # FIXME: Doesn't shot properly
    headers = wtf.FieldList(wtf.TextField('headers'))
    username = wtf.TextField('username')


class HashView(ModelView):
    """
    Admin view for Hahes using it's form.
    """
    column_list = ('name', 'version', 'format', 'status', 'submittedon')
    column_sortable_list = ('name', 'submittedon')
    column_filters = (
        FilterEqual('format', 'format'),
        FilterEqual('status', 'status', (
            ('SUBMITTED', 'SUBMITTED'), ('RELEASED', 'RELEASED'))))

    form = HashForm


class AccountView(ModelView):
    """
    Admin view for Account using it's form.
    """
    column_list = ('username', 'active', 'lastlogin', 'lastip', 'createdon')
    column_sortable_list = ('username', 'lastlogin', 'active', 'submittedon')
    column_filters = (
        FilterEqual('username', 'username'), )

    form = AccountForm


class TracebackView(ModelView):
    """
    Admin view for Tracebacks using it's form.
    """
    column_list = ('timestamp', 'type', 'ip', 'username')
    column_sortable_list = ('timestamp', 'type', 'ip', 'username')

    form = TracebackForm


# Bind and expose the views
administration = Admin(name="Victims Admin", index_view=SafeAdminIndexView())
administration.add_view(HashView(
    Connection('127.0.0.1').victims.hashes, name='Hashes', url='hashes'))
administration.add_view(AccountView(
    Connection('127.0.0.1').victims.users, name='Accounts', url='accounts'))
administration.add_view(TracebackView(
    Connection('127.0.0.1').victims.tracebacks, name='Tracebacks', url='tracebacks'))
