from copy import deepcopy
from json import loads
from os import remove
from os.path import isfile
from subprocess import check_output, CalledProcessError
from urlparse import urlparse, urljoin

from flask import request, flash

from victims_web import config
from victims_web.models import Hash


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


def set_hash(submission):
    """
    Helper method to process an archive at source where possible from a
    submission.
    """
    if not submission.entry is None:
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
            meta = json_data.get('metadata', [])
            if isinstance(meta, dict):
                meta = [meta]
            json_data['metadata'] = meta
            entry = Hash()
            entry.mongify(json_data)
            entry.status = 'SUBMITTED'
            entry.submitter = submission.submitter
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
            count += 1
        # we are done safely, now remove the source
        try:
            remove(submission.source)
        except:
            config.LOGGER.warn('Deletion failed for %s' % (submission.source))
    except CalledProcessError as e:
        submission.add_comment(e)
        config.LOGGER.debug('Command execution failed for "%s"' % (command))
    except Exception as e:
        submission.add_comment(e)
        config.LOGGER.warn('Failed to hash: ' + e.message)


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
