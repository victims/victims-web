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
from flask.ext.sslify import SSLify

from victims_web.admin import administration_setup
from victims_web.blueprints.service_v1 import v1
from victims_web.blueprints.service_v2 import v2, SUBMISSION_ROUTES
from victims_web.blueprints.ui import ui
from victims_web.blueprints.auth import auth

from victims_web.cache import cache
from victims_web.handlers.security import setup_security

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
    except Exception as e:
        # Helpful for debugging but not needed
        app.logger.debug('Skipping Debug Toolbar')
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


# SetUp identity management
setup_security(app)


@app.errorhandler(403)
def error_403(e):
    return render_template(
        'error.html',
        header='403 Forbidden',
        message='Hmm, looking for the bat cave?'
        + 'Perhaps try logging in as Bruce or Alfred? Unless you are "him"!'
    ), 403


@app.errorhandler(404)
def error_404(e):
    return render_template(
        'error.html',
        header='Resource not found!',
        message='Oops, think you are lost. Or we are, if so, report a bug!'
    ), 404


@app.errorhandler(500)
def error_500(e):
    return render_template(
        'error.html',
        title='Be back soon!',
        message='Victi.ms is undergoing maintenance (or possibly a bug). '
        + 'We should be back up shortly.'
    ), 500


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
