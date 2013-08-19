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
from flask.ext.mongoengine import MongoEngine
from flask.ext.seasurf import SeaSurf
from flask.ext import login

from victims_web.blueprints.service_v1 import v1
from victims_web.blueprints.service_v2 import v2, submit
from victims_web.blueprints.ui import ui
from victims_web.blueprints.auth import auth
from victims_web.blueprints.administration import administration_setup

from victims_web.cache import cache
from victims_web.user import User

# Set up the application
app = Flask('victims_web')

log_dir = os.environ.get('VICTIMS_LOG_DIR', 'logs/')
if not os.path.isdir(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    filename=os.path.join(log_dir, 'server.log'),
    format='%(asctime)s - %(levelname)s: %(message)s',
    datefmt='%a %b %d %Y %H:%M:%S %Z',
    level=logging.DEBUG,
)

app._logger = logging.getLogger()
csrf = SeaSurf(app)

CFG_KEY = 'VICTIMS_CONFIG'
if CFG_KEY in os.environ and os.path.exists(os.environ[CFG_KEY]):
    app.config.from_pyfile(os.environ[CFG_KEY])
else:
    app.config.from_pyfile('application.cfg')

if app.debug and not app.testing:
    try:
        from flask_debugtoolbar import DebugToolbarExtension
        toolbar = DebugToolbarExtension(app)
    except:
        # Helpful for debugging but not needed
        pass

app.db = MongoEngine(app)
cache.init_app(app)
administration_setup(app)

# CSRF exemptions
csrf.exempt(submit)

# Login manager
login_manager = login.LoginManager()
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
