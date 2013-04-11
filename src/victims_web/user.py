from flask import current_app, redirect, url_for

from flask.ext.login import current_user
from flask.ext.bcrypt import check_password_hash, generate_password_hash

# Helper functions


def authenticate(app, username, password):
    user = app.db.Account.find_one({'username': str(username)})
    if user:
        if check_password_hash(user['password'], password):
            return True
    return False


def create_user(app, username, password, endorsements=[]):
    passhash = generate_password_hash(
        password, app.config['BCRYPT_LOG_ROUNDS'])
    new_user = app.db.Account()
    new_user.username = username
    new_user.password = passhash
    new_user.endorsements = endorsements
    new_user.active = True
    new_user.save()

    return User(username)


def endorsements_required(endorsements, always_allow=['admin']):
    """
    Enforces required endorsements.

    :Parameters:
       - `endorsements`: List of endorsement names *required* to access
           the resource
       - `always_allow`: List of endorsements which if the user has at
           least one applied to their user let's them access the resource.
    """
    def wraps(fn):

        def decorated_view(*args, **kwargs):
            approved = False
            for always_allowed in always_allow:
                if current_user.has_endorsement(always_allowed):
                    approved = True
            if not approved:
                for endorsement in endorsements:
                    if not current_user.has_endorsement(endorsement):
                        return redirect(url_for('auth.login_user'))
            return fn(*args, **kwargs)

        return decorated_view

    return wraps


def user_allowed(user, endorsements):
    if user.has_endorsement('admin'):
        return True
    for endorsement in endorsements:
        if current_user.has_endorsement(endorsement):
            return True
    return redirect(url_for('auth.login_user'))


class User(object):

    def __init__(self, username, user_obj=None):
        """
        Creates a user instance.
        """
        self.__authenticated = True
        self.__active = False
        self.__username = username
        self.__endorsements = []

        if not user_obj:
            user_obj = current_app.db.Account.find_one({'username': username})

        self.__active = user_obj.get('active', False)
        self.__endorsements = user_obj.get('endorsements', [])

    def is_authenticated(self):
        return self.__authenticated

    def is_active(self):
        return self.__active

    def is_anonymous(self):
        return not self.__authenticated

    def get_id(self):
        return unicode(self.__username)

    def endorsements(self):
        return self.__endorsements

    def has_endorsement(self, name):
        return name in self.__endorsements

    def __repr__(self):
        if self.is_anonymous():
            return '<User: Anonymous>'
        return '<User: username="%s">' % self.__username

    # Read-only properties
    username = property(lambda s: s.__username)
    endorsements = property(lambda s: s.__endorsements)
    active = property(lambda s: s.__active)
    authenticated = property(lambda s: s.__authenticated)
