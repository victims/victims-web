import datetime

from flask import request
from flask.ext import login


def log_login(app, user):
    """
    Logs the users login.
    """
    app.logger.info(user.username + " logged in")


def update_login_details(app, user):
    """
    Updates user information upon login.
    """
    user_obj = app.db.Account.find_one({'username': user.username})
    user_obj.lastlogin = datetime.datetime.utcnow()
    try:
        user_obj.lastip = request.headers.getlist('X-Forwarded-For')[0]
    except:
        user_obj.lastip = request.remote_addr
    user_obj.save()


login.user_logged_in.connect(log_login)
login.user_logged_in.connect(update_login_details)
