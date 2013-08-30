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
Module which results with a ready to use wsgi application.
"""

import logging.config
import os

from flask import Flask, render_template
from flask.ext.mongoengine import MongoEngine, MongoEngineSessionInterface
from flask.ext.seasurf import SeaSurf
from flask.ext import login
from flask_sslify import SSLify

from victims_web.blueprints.service_v1 import v1
from victims_web.blueprints.service_v2 import v2, SUBMISSION_ROUTES
from victims_web.blueprints.ui import ui
from victims_web.blueprints.auth import auth
from victims_web.blueprints.administration import administration_setup

from victims_web.cache import cache
from victims_web.user import User

# Set up the application
app = Flask('victims_web')

# SSLify
sslify = SSLify(app)

# CSRF protection
csrf = SeaSurf(app)

# configuration
app.config.from_object('victims_web.config')

# logging
logging.basicConfig(
    filename=os.path.join(app.config.get('LOG_FOLDER'), 'server.log'),
    format='%(asctime)s - %(levelname)s: %(message)s',
    datefmt='%a %b %d %Y %H:%M:%S %Z',
    level=logging.DEBUG,
)
app._logger = app.config.get('LOGGER')

# debug enhancements
if app.debug and not app.testing:
    try:
        from flask_debugtoolbar import DebugToolbarExtension
        toolbar = DebugToolbarExtension(app)
    except:
        # Helpful for debugging but not needed
        pass

# mongodb and sessions
app.db = MongoEngine(app)
app.session_interface = MongoEngineSessionInterface(app.db)

# cache
cache.init_app(app)

# admin setup
administration_setup(app)

# CSRF exemptions
for submit in SUBMISSION_ROUTES:
    csrf.exempt(submit)


# Login manager
login_manager = login.LoginManager()
login_manager.login_view = 'auth.login_user'
login_manager.login_message = 'You are not authorized to access this resource.'
login_manager.login_message_category = 'error'
login_manager.init_app(app)


@app.errorhandler(500)
def error_500(e):
    return render_template('500.html'), 500


@login_manager.user_loader
def load_user(userid):
    return User(userid)


# Register blueprints
app.register_blueprint(v1, url_prefix='/service/v1')
app.register_blueprint(v2, url_prefix='/service/v2')
app.register_blueprint(v2, url_prefix='/service')
app.register_blueprint(ui)
app.register_blueprint(auth)

if app.config.get('SENTRY_DSN', None):
    from raven.contrib.flask import Sentry
    sentry = Sentry(app)


if __name__ == '__main__':
    # If we are called locally run with debug on
    app.run(debug=True)
