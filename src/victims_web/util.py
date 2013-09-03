from copy import deepcopy
from json import loads
from os import remove
from os.path import isfile
from subprocess import check_output, CalledProcessError
from urlparse import urlparse, urljoin

from flask import request, flash

from victims_web import config
from victims_web.models import Hash


DEFAULT_GROUP = '---'


def groups():
    """
    Retrieve a list of groups with the default '---' group added.
    """
    submission_groups = {DEFAULT_GROUP: []}
    for group in config.SUBMISSION_GROUPS:
        submission_groups[group] = config.SUBMISSION_GROUPS[group]
    return submission_groups


def allowed_groups():
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


def set_hash(submission):
    """
    Helper method to process an archive at source where possible from a
    submission.
    """
    if not submission.entry is None:
        return

    if not isfile(submission.source):
        return

    if submission.group not in config.HASHING_COMMANDS:
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
    except CalledProcessError:
        config.LOGGER.debug('Command execution failed for "%s"' % (command))
    except Exception as e:
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
