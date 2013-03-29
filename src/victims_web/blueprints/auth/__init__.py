from flask import (
    Blueprint, current_app, flash, render_template, request,
    url_for, redirect)

from flask.ext import login

from victims_web.user import authenticate, create_user, User
from victims_web.blueprints.auth.connections import *

from victims_web import errors


auth = Blueprint('auth', __name__, template_folder='templates')


@auth.route("/login", methods=['GET', 'POST'])
def login_user():
    # If you are already logged in, go away!
    if not login.current_user.is_anonymous():
        return redirect(url_for('ui.index'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        user_data = authenticate(
            current_app, username,
            request.form.get('password', ''))
        if user_data:
            if login.login_user(User(username)):
                flash("Logged in successfully.", category='info')
                return redirect(url_for('ui.index'))
        flash("Invalid username/password", category='error')

    return render_template("login.html")


@auth.route("/logout", methods=['GET'])
@login.login_required
def logout_user():
    login.logout_user()
    return redirect(url_for('ui.index'))


@auth.route("/register", methods=['GET', 'POST'])
def register_user():
    # Someone with a session can not make a new user
    if login.current_user.is_authenticated():
        return redirect(url_for('ui.index'))

    # Request to make a new user
    if request.method == 'POST':
        try:
            # Password checks to make sure they are at least somewhat sane
            for char in request.form['password']:
                cnt = request.form['password'].count(char)
                if cnt/float(len(request.form['password'])) > 0.3:
                    raise errors.ValidationError((
                        'You can not use the same '
                        'char for more than 30% of the password'))
            if request.form['password'] == request.form['username']:
                raise errors.ValidationError(
                    'Password can not be the same as the username.')
            if len(request.form['password']) <= 8:
                raise errors.ValidationError('Password to simple.')
            if request.form['password'] != request.form['verify_password']:
                raise errors.ValidationError('Passwords do not match.')

            if current_app.db.users.find_one(
                    {'username': request.form['username']}):
                raise errors.ValidationError('Username is not available.')

            user = create_user(
                current_app, request.form['username'],
                request.form['password'])
            login.login_user(user)
            return redirect(url_for('ui.index'))
        except errors.ValidationError, ve:
            flash(ve.message, category='error')
        except (KeyError, IndexError), ke:
            flash('Missing information.', category='error')
        except Exception, ex:
            print ex
            flash('An unknown error has occured.', category='error')

    # Default
    return render_template('register.html')
