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

import os.path
import re
from uuid import uuid4

from flask import (
    Blueprint, current_app, render_template, helpers,
    url_for, request, redirect, flash)
from werkzeug import secure_filename

from flask.ext import login

from victims_web.errors import ValidationError
from victims_web.models import Hash, Submission
from victims_web.cache import cache


ui = Blueprint(
    'ui', __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/static/')  # Last argument needed since we register on /


submission_groups = {'---': []}


def _groups():
    if 'SUBMISSION_GROUPS' in current_app.config:
        return current_app.config['SUBMISSION_GROUPS']
    else:
        return submission_groups


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


def submit(source, filename=None, suffix=None, cves=[], meta={}):
    current_app.logger.debug('Submitting: (%s, %s, %s, %s)' %
                             (source, filename, cves, meta))
    submission = Submission()
    submission.source = source
    if filename:
        submission.filename = filename
    if suffix:
        submission.format = suffix.title()
    submission.cves = cves
    submission.metadata = meta
    submission.submitter = login.current_user.username
    submission.validate()
    submission.save()


def get_upload_folder():
    """
    Helper methed to fetch configured upload directory. If the directory does
    not exist, it is created.
    """
    upload_dir = current_app.config['UPLOAD_FOLDER']
    if not os.path.isdir(upload_dir):
        current_app.logger.info('Creating upload directory: %s' % (upload_dir))
        os.makedirs(upload_dir, 0755)
    return upload_dir


def upload_file(archive):
    """
    Given a FileStorage object, the file is securely uploaded to the server
    to the configured upload directory. A random prefix is added to the
    filename.
    """
    if len(archive.filename) == 0:
        raise ValueError('No archive provided')

    upload_dir = get_upload_folder()

    suffix = archive.filename[archive.filename.rindex('.') + 1:]
    if suffix not in current_app.config['ALLOWED_EXTENSIONS']:
        raise ValueError('Invalid archive: %s' % (archive.filename))

    filename = secure_filename(archive.filename)
    sfilename = '%s-%s' % (str(uuid4()), filename)
    ondisk = os.path.join(upload_dir, sfilename)
    archive.save(ondisk)

    current_app.logger.info(
        'User %s has uploaded %s' % (login.current_user.username, filename))

    return (ondisk, filename, suffix)


def process_metadata():
    """
    Process any group specific metadata that was provided in the submission
    form.
    """
    meta = {}
    group = request.form['group'].strip()
    current_groups = _groups()
    if group in current_groups:
        for field in current_groups[group]:
            name = '%s-%s' % (group, field)
            if name in request.form:
                value = request.form[name].strip()
                if len(value) > 0:
                    meta[field] = value
    return meta


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

            if 'archive' in request.files:
                try:
                    (ondisk, filename, suffix) = upload_file(
                        request.files['archive'])
                except Exception, e:
                    # TODO: implement maven/pypi fetch
                    raise e
            else:
                raise ValueError('Archive not submitted')

            meta = process_metadata()

            submit(ondisk, filename, suffix, cves, meta)
            flash('Archive Submitted for processing', 'info')
        except ValueError, ve:
            flash(ve.message, 'error')
        except ValidationError, ve:
            flash(ve.message, 'error')
        except OSError, oe:
            flash('Could not upload file due to a server side error', 'error')
            current_app.logger.debug(oe)
    return render_template('submit_archive.html', groups=_groups())


@ui.route('/<page>.html', methods=['GET'])
def static_page(page):
    # These are the only 'static' pages
    if page in ['about', 'client', 'bugs']:
        return render_template('%s.html' % page)
    return helpers.NotFound()
