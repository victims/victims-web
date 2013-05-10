import logging.config
import os

from flask import Flask, render_template
from flask.ext.mongokit import MongoKit
from flask.ext.seasurf import SeaSurf
from flask.ext import login

from victims_web.blueprints.service_v1 import v1
from victims_web.blueprints.service_v2 import v2, update
from victims_web.blueprints.ui import ui
from victims_web.blueprints.auth import auth
from victims_web.blueprints.administration import administration_setup

from victims_web.cache import cache
from victims_web.user import User
from victims_web.models import MODELS

# Set up the application
app = Flask('victims_web')


logging.basicConfig(
    filename=os.environ.get('OPENSHIFT_DATA_DIR', 'logs/') + 'server.log',
    format='%(asctime)s - %(levelname)s: %(message)s',
    datefmt='%a %b %d %Y %H:%M:%S %Z',
    level=logging.DEBUG,
)

app._logger = logging.getLogger()
csrf = SeaSurf(app)
app.config.from_pyfile('application.cfg')
app.db = MongoKit(app)
cache.init_app(app)
app.db.register(MODELS)
administration_setup(app)

# CSRF exemptions
csrf.exempt(update)

# Login manager
login_manager = login.LoginManager()
login_manager.setup_app(app)


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
