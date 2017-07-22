from copy import deepcopy
from json import loads
from subprocess import check_output, CalledProcessError
from urlparse import urlparse, urljoin

from flask import request, flash
from os.path import isfile

from victims.web import config
from victims.web.handlers.task import task
from victims.web.models import Hash, Submission


def groups():
    """
    Retrieve a list of groups that we know of. All configured group names are
    returned.
    """
    return config.SUBMISSION_GROUPS.keys()


def group_keys(group):
    """
    Retrieve the metadata keys associated with a given group.
    """
    return groups().get(group, [])


@task
def hash_submission(submission_id):
    """
    Helper method to process an archive at source where possible from a
    submission.
    """
    submission = Submission.objects(id=submission_id).first()

    if not submission:
        config.LOGGER.debug('Submission %s not found.' % (submission_id))
        return

    if submission.entry is not None:
        submission.add_comment('Entry alread exits. Skipping hashing.')
        return

    if not isfile(submission.source):
        submission.add_comment('Source file not found.')
        return

    if submission.group not in config.HASHING_COMMANDS:
        submission.add_comment('Hashing command for this group not found.')
        return

    command = config.HASHING_COMMANDS[submission.group].format(
        archive=submission.source)
    try:
        output = check_output(command, shell=True).strip()
        count = 0
        for line in output.split('\n'):
            json_data = loads(line)
            json_data['cves'] = submission.cves

            # make sure metadata is a list
            meta = json_data.get('metadata', [])
            if isinstance(meta, dict):
                meta = [meta]
            json_data['metadata'] = meta

            entry = Hash()
            entry.mongify(json_data)
            entry.status = 'SUBMITTED'
            entry.submitter = submission.submitter
            entry.coordinates = submission.coordinates
            if count > 0:
                # create a new submission for each embedded entry
                s = deepcopy(submission)
                s.id = None
            else:
                s = submission
            s.entry = entry
            s.approval = 'PENDING_APPROVAL'
            s.validate()
            s.save()
            s.add_comment('Auto hash entry added')
            count += 1
        # we are done safely, now remove the source
        submission.remove_source_file()
    except CalledProcessError as e:
        submission.add_comment(e)
        config.LOGGER.debug('Command execution failed for "%s"' % (command))
    except Exception as e:
        submission.add_comment(e)
        config.LOGGER.warn('Failed to hash: ' + e.message)


def set_hash(submission):
    if isinstance(submission, basestring):
        sid = str(submission)
    else:
        sid = str(submission.id)
    hash_submission(sid)


def safe_redirect_url():
    """
    Returns request.args['next'] if the url is safe, else returns none.
    """
    forward = request.args.get('next')
    if forward:
        host_url = urlparse(request.host_url)
        redirect_url = urlparse(urljoin(request.host_url, forward))
        if redirect_url.scheme in ('http', 'https') and \
                host_url.netloc == redirect_url.netloc:
            return forward
        else:
            flash('Invalid redirect requested.', category='info')
    return None
