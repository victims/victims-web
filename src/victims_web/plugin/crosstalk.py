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
Cross Talk plugin

This plugin allows for different instances of the app to communicate.
"""

from victims_web.config import SUBMISSION_GROUPS
from victims_web.handlers.task import taskman
from victims_web.models import Hash, Submission
from victims_web.plugin import PluginConfig


_CONFIG = PluginConfig('crosstalk')


def update_front_page_stats():
    stats = {}
    stats['hashes'] = Hash.objects(status='RELEASED').only('group')
    stats['submitted'] = Submission.objects(
        approval='REQUESTED').only('group')
    stats['pending'] = Submission.objects(
        approval='PENDING_APPROVAL').only('group')

    # Generate counts for objects and for each format
    # data will contain hashes, hashes_jars, hashes_eggs etc.
    groups = SUBMISSION_GROUPS.keys()
    groups.sort()
    groups = ['all'] + groups
    data = {'groups': groups, 'stats': {}}
    for group in groups:
        stat = {}
        for key in stats:
            if group == 'all':
                stat[key] = len(stats[key])
            else:
                stat[key] = len(stats[key].filter(group=group))
        data['stats'][group] = stat
    _CONFIG.front_page_stats = data


class IndexPageMonitor():

    def __init__(self):
        self.refreshed_flag = False
        self.refresh()

    def refresh(self, blocking=False):
        if blocking:
            update_front_page_stats()
        else:
            taskman.add_task(update_front_page_stats)
        self.refreshed_flag = True

    def get_data(self):
        _CONFIG.reload()
        return _CONFIG.front_page_stats


indexmon = IndexPageMonitor()
