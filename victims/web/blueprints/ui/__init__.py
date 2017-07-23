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

import flask_login as login
import re
from flask import (
    Blueprint, current_app, escape, render_template, helpers,
    url_for, request, redirect, flash)

from victims.web.cache import cache
from victims.web.config import SUBMISSION_GROUPS
from victims.web.errors import ValidationError
from victims.web.handlers.forms import \
    SUBMISSION_FORMS, ArtifactSubmit, flash_errors
from victims.web.models import Hash, CoordinateDict
from victims.web.plugin.crosstalk import indexmon
from victims.web.submissions import submit, upload
from victims.web.util import groups

ui = Blueprint(
    'ui', __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/static/')  # Last argument needed since we register on /


_GROUP_REGEX = '<regex("%s"):group>' % ('|'.join(SUBMISSION_GROUPS.keys()))


def _is_hash(data):
    """
    Verifies the hash is a sha1 hash.
    """
    if re.match('^([a-zA-Z0-9]{128})$', data):
        return True
    return False


@ui.route('/', methods=['GET'])
def index():
    _cache_key = 'view/%s/get_data' % (request.path)

    @cache.cached(key_prefix=_cache_key)
    def get_data():
        indexmon.refresh(True)
        return indexmon.get_data()

    if indexmon.refreshed_flag:
        cache.delete(_cache_key)
        # make sure cached hashes for ui.hashes are cleared
        cache.delete_memoized(hashes)
        indexmon.refreshed_flag = False
    return render_template('index.html', **get_data())


@cache.memoize()
def hashes(groups):
    hashes = Hash.objects(
        status='RELEASED', group__in=groups
    ).only('name', 'version', 'hashes.sha512.combined')
    return render_template('hashes.html', hashes=hashes)


@ui.route('/hashes/%s/' % (_GROUP_REGEX), methods=['GET'])
def hashes_singlegroup(group):
    if group not in groups():
        flash(
            '%s is not a known group. Displaying all hashes.' % (group),
            'error')
        return render_template('hashes.html', hashes=[])
    return hashes([group])


@ui.route('/hashes/', methods=['GET'])
def hashes_multigroup():
    # expect a comma seperated arg
    _groups = request.args.get('groups')

    if _groups is None:
        # default to all groups
        _groups = groups()
    else:
        _groups = [str(g.strip()) for g in _groups.split(',')]

    return hashes(_groups)


@ui.route('/hash/<value>', methods=['GET'])
def onehash(value):
    if _is_hash(value):
        a_hash = Hash.objects.get_or_404(hashes__sha512__combined=value)
        return render_template('onehash.html', hash=a_hash)
    else:
        flash('Not a valid hash', 'error')
    return redirect(url_for('ui.hashes_multigroup'))


def process_submission(form, group=None):
    try:
        cves = []
        for cve in form.cves.data.split(','):
            cves.append(cve.strip())

        if group is None:
            group = form.group.data

        coordinates = CoordinateDict({
            coord: form._fields.get('%s' % coord).data.strip()
            for coord in SUBMISSION_GROUPS.get(group, [])
        })

        # remove any empty values
        coordinates = dict(
            (k, v)
            for k, v in coordinates.iteritems()
            if v is not None and len(v) > 0
        )

        # if no coordinates given, make None
        if len(coordinates) == 0:
            coordinates = None

        files = upload(group, request.files.get('archive', None), coordinates)
        for (ondisk, filename, suffix) in files:
            submit(
                login.current_user.username, ondisk, group, filename, suffix,
                cves, coordinates=coordinates
            )

        current_app.config['INDEX_REFRESH_FLAG'] = True

        flash('Archive Submitted for processing', 'info')
    except ValueError, ve:
        flash(escape(ve.message), 'error')
    except ValidationError, ve:
        flash(escape(ve.message), 'error')
    except OSError, oe:
        flash('Could not upload file due to a server side error', 'error')
        current_app.logger.debug(oe)


@ui.route('/submit/%s/' % (_GROUP_REGEX), methods=['GET', 'POST'])
@login.login_required
def submit_artifact(group):
    form = SUBMISSION_FORMS.get(group, ArtifactSubmit)()
    if form.validate_on_submit():
        process_submission(form, group)
        return redirect(url_for('ui.index'))
    elif request.method == 'POST':
        flash_errors(form)
    return render_template(
        'submit_artifact.html', form=form, group=group)


@ui.route('/<page>.html', methods=['GET'])
def static_page(page):
    # These are the only 'static' pages
    if page in ['about', 'client', 'bugs']:
        return render_template('%s.html' % page)
    return helpers.NotFound()
