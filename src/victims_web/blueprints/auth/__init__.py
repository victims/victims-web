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
Authentication related views.
"""

from flask import (
    Blueprint, current_app, flash, render_template, request,
    url_for, redirect)

from flask.ext import login
from recaptcha.client import captcha

from victims_web.user import authenticate, create_user, User
from victims_web.models import Account

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
            username,
            request.form.get('password', ''))
        if user_data:
            if login.login_user(user=User(username), remember=True):
                flash("Logged in successfully.", category='info')
                return redirect(url_for('ui.index'))
        flash("Invalid username/password", category='error')

    return render_template("login.html")


@auth.route("/logout", methods=['GET'])
@login.login_required
def logout_user():
    login.logout_user()
    return redirect(url_for('ui.index'))


def validate_password():
    # Password checks to make sure they are at least somewhat sane
    for char in request.form['password']:
        cnt = request.form['password'].count(char)
        if cnt / float(len(request.form['password'])) > 0.3:
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


def validate_username():
    if Account.objects(username=request.form['username']).first():
        raise errors.ValidationError('Username is not available.')


def validate_captcha():
    if (not current_app.config['DEBUG'] or not current_app.config['TESTING']):
        # First things first, test the captcha
        response = captcha.submit(
            request.form['recaptcha_challenge_field'],
            request.form['recaptcha_response_field'],
            current_app.config['RECAPTCHA_PRIVATE_KEY'],
            request.remote_addr,
        )
        if not response.is_valid:
            raise errors.ValidationError('Captcha did not match.')


@auth.route("/register", methods=['GET', 'POST'])
def register_user():

    fields = {
        'Username': {'name': 'username', 'req': True},
        'Password': {'name': 'password', 'type': 'password', 'req': True},
        'Verify Password': {'name': 'verify_password', 'type': 'password',
                            'req': True},
        'Email': {'name': 'email', 'type': 'email'},
    }

    # Someone with a session can not make a new user
    if login.current_user.is_authenticated():
        return redirect(url_for('ui.index'))

    # Request to make a new user
    if request.method == 'POST':
        try:
            for fname in fields:
                field = fields[fname]
                if field.get('req', False):
                    key = field['name']
                    if (key not in request.form.keys() or
                            len(request.form[key].strip()) == 0):
                        raise ValueError('%s is required' % (fname))

            # perform validation
            validate_captcha()
            validate_username()
            validate_password()

            email = request.form['email'].strip()
            email = None if len(email) == 0 else email
            user = create_user(
                request.form['username'],
                request.form['password'],
                email=email)
            login.login_user(user)
            return redirect(url_for('ui.index'))
        except errors.ValidationError, ve:
            flash(ve.message, category='error')
        except ValueError, ve:
            flash(ve.message, category='error')
        except (KeyError, IndexError):
            flash('Missing information.', category='error')
        except Exception, ex:
            current_app.logger.info(ex)
            flash('An unknown error has occured.', category='error')

    # Default
    recaptcha = {
        'public_key': current_app.config['RECAPTCHA_PUBLIC_KEY'],
        'theme': current_app.config['RECAPTCHA_THEME'],
    }
    return render_template('register.html', recaptcha=recaptcha, fields=fields)
