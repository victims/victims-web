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
from flask import Flask, render_template, session
from flask_bootstrap import Bootstrap
from flask_mongoengine import MongoEngine, MongoEngineSessionInterface
from flask_seasurf import SeaSurf
from flask_reggie import Reggie

# Set up the application
app = Flask('victims.web')

# say hello to reggie
reggie = Reggie(app)

# CSRF protection
csrf = SeaSurf(app)

# Twitter Bootstrap
bootstrap = Bootstrap(app)

# configuration
from victims.web import config
app.config.from_object(config)

# logging
logging.basicConfig(
    filename=os.path.join(app.config.get('LOG_FOLDER'), 'server.log'),
    format='%(asctime)s - %(levelname)s: %(message)s',
    datefmt='%a %b %d %Y %H:%M:%S %Z',
    level=app.config['LOG_LEVEL'],
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

# web setup
# this happens after basic setup to facilitate database availability
from victims.web.admin import administration_setup
from victims.web.blueprints.service_v1 import v1
from victims.web.blueprints.service_v2 import v2, SUBMISSION_ROUTES
from victims.web.blueprints.ui import ui
from victims.web.blueprints.auth import auth

from victims.web.cache import cache
from victims.web.handlers.security import setup_security
from victims.web.handlers.sslify import VSSLify
from victims.web.handlers.task import taskman
from victims.web.plugin.crosstalk import session_reaper

# Custom SSLify
sslify = VSSLify(app)

# cache
cache.init_app(app)

# admin setup
administration_setup(app)

# CSRF exemptions
for submit in SUBMISSION_ROUTES:
    csrf.exempt(submit)


# SetUp identity management
setup_security(app)


@app.after_request
def reap_sessions(response):
    if session.modified:
        taskman.add_task(session_reaper.reap)
    return response


@app.errorhandler(403)
def error_403(e):
    return render_template(
        'error.html',
        header='The box says 403',
        message='Looking for the bat cave? '
        'Perhaps try logging in as Bruce or Alfred? Unless you are "him"!'
    ), 403


@app.errorhandler(404)
def error_404(e):
    return render_template(
        'error.html',
        header='404: Nemo is not here',
        message='Oops, think you are lost. Or we are, if so, report a bug!'
    ), 404


@app.errorhandler(500)
def error_500(e):
    return render_template(
        'error.html',
        title='Ruh-roh, Raggy',
        message='We are undergoing maintenance '
        '(or possibly are being eaten by zombies).'
        ' We should be back up shortly.'
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
    app.run(debug=app.config['DEBUG'])
