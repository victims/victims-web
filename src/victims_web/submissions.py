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
Submission module. Handle submission related logic.
"""
from os import makedirs
from os.path import isdir, join
from uuid import uuid4

from werkzeug import secure_filename

from victims_web import config
from victims_web.models import Submission
from victims_web.plugin.charon import download
from victims_web.util import allowed_groups, set_hash


def submit(submitter, source, group=None, filename=None, suffix=None, cves=[],
           meta={}, entry=None, approval='REQUESTED'):
    config.LOGGER.info('Submitting: %s' % (
        ', '.join(['%s:%s' % (k, v) for (k, v) in locals().items()])))
    submission = Submission()
    submission.source = source
    submission.group = group
    submission.filename = filename
    if suffix:
        submission.format = suffix.title()
    submission.cves = cves
    if entry and entry.cves:
        for cve in entry.cves:
            if cve not in entry.cves:
                submission.cves.append(cve)
    submission.metadata = meta
    submission.submitter = submitter
    submission.entry = entry
    submission.approval = approval
    submission.validate()
    submission.save()

    # TODO: Make this async
    set_hash(submission)


def get_upload_folder():
    """
    Helper methed to fetch configured upload directory. If the directory does
    not exist, it is created.
    """
    upload_dir = config.UPLOAD_FOLDER
    if not isdir(upload_dir):
        config.LOGGER.info('Creating upload directory: %s' % (upload_dir))
        makedirs(upload_dir, 0755)
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

    try:
        suffix = archive.filename[archive.filename.rindex('.') + 1:]
    except ValueError:
        raise ValueError('Filename has no extension')

    if suffix not in config.ALLOWED_EXTENSIONS:
        raise ValueError('Invalid archive: %s' % (archive.filename))

    filename = secure_filename(archive.filename)
    sfilename = '%s-%s' % (str(uuid4()), filename)
    ondisk = join(upload_dir, sfilename)
    archive.save(ondisk)

    config.LOGGER.info(
        'Uploaded %s' % (filename))

    return (ondisk, filename, suffix)


def upload_from_metadata(group, meta):
    """
    Given only metadata of an archive ask charon to retrive it where possible
    """
    if group not in allowed_groups():
        raise ValueError('Invalid group')
    return download(group, meta)


def upload(group, archive=None, meta=None):
    """
    Helper method to upload files using archive file in request or metadata
    provided. If no files get uploaded a ValueError is raised.
    """
    files = []

    try:
        if archive:
            files.append(upload_file(archive))
        else:
            raise ValueError('No Archive provided')
    except ValueError as ve:
        if meta:
            print(meta)
            files = upload_from_metadata(group, meta)
        else:
            raise ve

    if len(files) == 0:
        raise ValueError('Invalid submissions, no archives could be resolved.')

    return files
