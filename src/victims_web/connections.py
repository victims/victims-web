import flask

import sys
import traceback

from flask.ext import login


def store_exception(app, exception):
    exc_info = sys.exc_info()
    exc_str = ''.join(traceback.format_exception(*exc_info))
    # Log the exception
    app.logger.warn(str(exc_str))

    # Store the exception in mongodb to look at later
    tb = app.db.Traceback()
    tb['headers'] = {}
    for item in flask.request.headers.items():
        tb['headers'][item[0]] = item[1]
    try:
        tb['username'] = login.current_user.username
    except:
        tb['username'] = 'AnonymousUser'

    try:
        tb['ip'] = flask.request.headers.getlist(
            'X-Forwarded-For')[0]
    except:
        tb['ip'] = flask.request.remote_addr

    tb['type'] = exc_info[1].__class__.__name__
    tb['traceback'] = str(exc_str)
    tb.save()
    # Let others continue with processing if needed
    return app, exception


# Connections happen here
flask.got_request_exception.connect(store_exception)
