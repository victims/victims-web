# The contents of this file has been derived and/or shamelessly copied from
# the jip project at https://github.com/sunng87/jip
#
# Copyright (C) 2011 Sun Ning<classicning@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

from hashlib import md5, sha1
from logging import getLogger
from Queue import Queue
from StringIO import StringIO
from threading import Thread
from time import time
from urllib2 import Request, urlopen, HTTPError, URLError

USER_AGENT = 'victims-web-plugin/downloader'
BUF_SIZE = 4096

logger = getLogger('plugin.downloader')


class DownloadException(Exception):
    pass


def download(url, target, async=False, close_target=False, quiet=True):
    # download file to target (target is a file-like object)
    if async:
        _pool.submit(url, target)
    else:
        request = Request(url=url)
        request.add_header('User-Agent', USER_AGENT)
        try:
            t0 = time()
            source = urlopen(request)
            size = source.headers.getheader('Content-Length')
            if not quiet:
                logger.info(
                    '[Downloading] %s %s bytes to download' % (url, size)
                )
            buf = source.read(BUF_SIZE)
            while len(buf) > 0:
                target.write(buf)
                buf = source.read(BUF_SIZE)
            source.close()
            if close_target:
                target.close()
            t1 = time()
            if not quiet:
                logger.info(
                    '[Downloading] Download %s completed in %f secs' %
                    (url, (t1 - t0))
                )
        except HTTPError, e:
            raise DownloadException(url, e)
        except URLError, e:
            raise DownloadException(url, e)


def download_string(url):
    buf = StringIO()
    download(url, buf)
    data = buf.getvalue()
    buf.close()
    return data


class DownloadThreadPool(object):
    def __init__(self, size=3):
        self.queue = Queue()
        self.workers = [Thread(target=self._do_work) for _ in range(size)]
        self.initialized = False

    def init_threads(self):
        for worker in self.workers:
            worker.setDaemon(True)
            worker.start()
        self.initialized = True

    def _do_work(self):
        while True:
            url, target = self.queue.get()
            download(url, target, close_target=True, quiet=False)
            self.queue.task_done()

    def join(self):
        self.queue.join()

    def submit(self, url, target):
        if not self.initialized:
            self.init_threads()
        self.queue.put((url, target))

_pool = DownloadThreadPool(3)


def checksum(filepath, checksum_type):
    if checksum_type == 'md5':
        hasher = md5()
    elif checksum_type == 'sha1':
        hasher = sha1()

    buf_size = 1024 * 8
    file_to_check = file(filepath, 'r')
    buf = file_to_check.read(buf_size)
    while len(buf) > 0:
        hasher.update(buf)
        buf = file_to_check.read(buf_size)

    file_to_check.close()
    return hasher.hexdigest()
