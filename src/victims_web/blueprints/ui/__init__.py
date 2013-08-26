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
Main web ui.
"""

import re

from flask import (
    Blueprint, current_app, render_template, helpers,
    url_for, request, redirect, flash)

from flask.ext import login

from victims_web.errors import ValidationError
from victims_web.models import Hash, Submission
from victims_web.cache import cache
from victims_web.submissions import groups, process_metadata, submit, upload


ui = Blueprint(
    'ui', __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/static/')  # Last argument needed since we register on /


def _is_hash(data):
    """
    Verifies the hash is a sha1 hash.
    """
    if re.match('^([a-zA-Z0-9]{128})$', data):
        return True
    return False


@ui.route('/', methods=['GET'])
def index():

    @cache.cached()
    def get_data():
        """
        Caching results via inner function.
        """
        stats = {}
        stats['hashes'] = Hash.objects(status='RELEASED')
        stats['submitted'] = Submission.objects(approval='REQUESTED')
        stats['pending'] = Submission.objects(approval='PENDING_APPROVAL')

        # Generate counts for objects and for each format
        # data will contain hashes, hashes_jars, hashes_eggs etc.
        data = {}
        formats = ['Jar', 'Egg']
        for key in stats:
            data[key.lower()] = len(stats[key])
            for fmt in formats:
                entry = '%s_%ss' % (key.lower(), fmt.lower())
                data[entry] = len(stats[key].filter(format=fmt))

        return data

    return render_template('index.html', **get_data())


@ui.route('/hashes/', methods=['GET'])
@ui.route('/hashes/<format>/', methods=['GET'])
@cache.memoize()
def hashes(format=None):
    hashes = Hash.objects(status='RELEASED')

    if format:
        if format not in Hash.objects.distinct('format'):
            flash('Format not found', 'error')
        else:
            hashes = hashes.filter(format=format)

    return render_template('hashes.html', hashes=hashes)


@ui.route('/hash/<hash>/', methods=['GET'])
def hash(hash):
    if _is_hash(hash):
        a_hash = Hash.objects.get_or_404(hashes__sha512__combined=hash)
        return render_template('onehash.html', hash=a_hash)
    flash('Not a valid hash', 'error')
    return redirect(url_for('ui.hashes'))


@ui.route('/submit_archive/', methods=['GET', 'POST'])
@login.login_required
def submit_archive():
    # If a file is submitted
    if request.method == "POST":
        try:
            cve_field = request.form['cves'].strip()
            if len(cve_field) == 0:
                raise ValueError('No CVE provided')
            cves = []
            for cve in cve_field.split(','):
                cve = cve.strip().upper()
                if re.match('^CVE-\d+-\d+$', cve) is None:
                    raise ValueError('Invalid CVE provided: "%s"' % (cve))
                cves.append(cve)

            group = request.form['group']
            meta = process_metadata(group, request.form)

            files = upload(group, request.files.get('archive', None))

            for (ondisk, filename, suffix) in files:
                submit(login.current_user.username, ondisk, group, filename,
                       suffix, cves, meta)
            flash('Archive Submitted for processing', 'info')
        except ValueError, ve:
            flash(ve.message, 'error')
        except ValidationError, ve:
            flash(ve.message, 'error')
        except OSError, oe:
            flash('Could not upload file due to a server side error', 'error')
            current_app.logger.debug(oe)
    return render_template('submit_archive.html', groups=groups())


@ui.route('/<page>.html', methods=['GET'])
def static_page(page):
    # These are the only 'static' pages
    if page in ['about', 'client', 'bugs']:
        return render_template('%s.html' % page)
    return helpers.NotFound()
