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
An asynchronous task manager. A simple implementation for background task
handing.
"""

from multiprocessing import Process
from threading import Thread
from Queue import Queue


class Waiter(Thread):
    """
    Waiter thread
    """
    def __init__(self):
        self.__q = Queue()

    def run(self):
        while True:
            child = self.__q.get()
            if child is None:
                return
            child.join()

    def waiton(self, process):
        self.__q.put(process)

    def stop(self):
        self.__q.put(None)


class TaskManager():
    """
    Task Manager implementation. This class allows for any function to be fired
    as their own process. Once fired the parent procsses can continue on doing
    their business.
    """
    def __init__(self):
        self._waiter = Waiter()

    def __del__(self):
        self._waiter.stop()

    def add_task(self, fn, *args):
        process = Process(target=fn, args=args)
        process.start()
        self._waiter.waiton(process)


manager = TaskManager()
