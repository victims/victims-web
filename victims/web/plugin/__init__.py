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

from victims.web.models import Plugin


class PluginConfig(object):
    """
    A plugin configuration object to wrap a persisted configuration in the DB.

    If a previous configuration exists for this plugin an empty one is created.
    """
    def __init__(self, plugin):
        self._config = Plugin.objects(plugin=plugin).first()
        if self._config is None:
            self._config = Plugin()
            self._config.plugin = plugin
            self._config.save()

    def __getattr__(self, attr):
        try:
            return object.__getattr__(self, attr)
        except AttributeError:
            return self._config.get(attr)

    def __setattr__(self, attr, value):
        if attr in self.__dict__ or '_config' not in self.__dict__:
            # If this instance has this attr or _config not yet set
            object.__setattr__(self, attr, value)
        else:
            self._config.set(attr, value)

    def keys(self):
        return self._config.config.keys()

    def clear(self):
        self._config.config = {}
        self._config.save()

    def delete(self):
        self._config.config = {}
        self._config.delete()

    def pop(self):
        self._config.pop()

    def reload(self):
        self._config.reload()

    def __repr__(self):
        return str(self._config.config)
