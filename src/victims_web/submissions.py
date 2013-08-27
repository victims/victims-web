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
import json

from os import makedirs, remove
from os.path import isdir, isfile, join
from uuid import uuid4
from subprocess import check_output, CalledProcessError

from flask import current_app
from werkzeug import secure_filename

from victims_web.models import Hash, Submission
from victims_web.plugin.charon import download


def groups():
    """
    Retrieve a list of groups with the default '---' group added.
    """
    submission_groups = {'---': []}
    if 'SUBMISSION_GROUPS' in current_app.config:
        configured_groups = current_app.config['SUBMISSION_GROUPS']
        for group in configured_groups:
            submission_groups[group] = configured_groups[group]
    return submission_groups


def allowed_groups():
    """
    Retrieve a list of groups that we know of. All configured group names are
    returned.
    """
    if 'SUBMISSION_GROUPS' in current_app.config:
        return current_app.config['SUBMISSION_GROUPS'].keys()
    return []


def group_keys(group):
    """
    Retrieve the metadata keys associated with a given group.
    """
    return groups().get(group, [])


def process_metadata(group, values={}, noprefix=False):
    """
    Process any group specific metadata that was provided in the submission
    form.
    """
    meta = {}
    current_groups = groups()
    if group.strip().lower() in current_groups:
        for field in current_groups[group]:
            if noprefix:
                name = field
            else:
                name = '%s-%s' % (group, field)
            if name in values:
                value = values[name].strip()
                if len(value) > 0:
                    meta[field] = value
    return meta


def get_hash(submission):
    """
    Helper method to process an archive at source where possible from a
    submission.
    """
    if not isfile(submission.source):
        return

    config = current_app.config
    key = 'HASHING_COMMANDS'

    if key not in config or submission.group not in config[key]:
        return

    command = config[key][submission.group].format(archive=submission.source)
    try:
        output = check_output(command, shell=True).strip()
        json_data = json.loads(output)
        json_data['cves'] = submission.cves
        entry = Hash()
        entry.load_json(submission.submitter, json_data)
        submission.entry = entry
        submission.approval = 'PENDING_APPROVAL'
        submission.validate()
        submission.save()

        # we are done safely, now remove the source
        try:
            remove(submission.source)
        except:
            current_app.logger.warn(
                'Deletion failed for %s' % (submission.source))
    except CalledProcessError:
        current_app.logger.debug(
            'Command execution failed for "%s"' % (command))
    except Exception as e:
        current_app.logger.warn('Failed to hash: ' + e.message)


def submit(submitter, source, group=None, filename=None, suffix=None, cves=[],
           meta={}, entry=None, approval='REQUESTED'):
    current_app.logger.debug('Submitting: %s' % (
        ', '.join(['%s:%s' % (k, v) for (k, v) in locals().items()])))
    submission = Submission()
    submission.source = source
    submission.group = group
    submission.filename = filename
    if suffix:
        submission.format = suffix.title()
    submission.cves = cves
    submission.metadata = meta
    submission.submitter = submitter
    submission.entry = entry
    submission.approval = approval
    submission.validate()
    submission.save()

    if entry is None:
        # TODO: Make this async
        get_hash(submission)

    current_app.config['INDEX_REFRESH_FLAG'] = True


def get_upload_folder():
    """
    Helper methed to fetch configured upload directory. If the directory does
    not exist, it is created.
    """
    upload_dir = current_app.config['UPLOAD_FOLDER']
    if not isdir(upload_dir):
        current_app.logger.info('Creating upload directory: %s' % (upload_dir))
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

    suffix = archive.filename[archive.filename.rindex('.') + 1:]
    if suffix not in current_app.config['ALLOWED_EXTENSIONS']:
        raise ValueError('Invalid archive: %s' % (archive.filename))

    filename = secure_filename(archive.filename)
    sfilename = '%s-%s' % (str(uuid4()), filename)
    ondisk = join(upload_dir, sfilename)
    archive.save(ondisk)

    current_app.logger.info(
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
