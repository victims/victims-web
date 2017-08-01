Victims Web Service |Build Status| |PyPI version|
=================================================

The victims web application.

Report an Issue
---------------

If you find an issue with the service at http://victi.ms or the code,
either

-  Create a new issue at https://github.com/victims/victims-web/issues
-  Email vicitms@librelist.com

Contributing
------------

| If you have a patch or a feature that you want considered to be added
  to the project, feel free to send us a pull request.
| Make sure you run pep8 before committing.

.. code:: sh

    pep8 --repeat .

Using PyPI Package
------------------
You can install and use the server by installing the `PyPI Package`_ and
use the provided entrypoint. Do ensure that the required database services
are available and/or configured.

.. code:: sh

    pip install --user victims-web
    victims-web-server

Development
-----------

This is short guide on how to work on this code base using the provided
``docker-compose`` configuration and development ``Dockerfile``. *Note*
that the ``Dockerfile`` provided in the base directory is not to be used
in production and is only for development use.

Docker builds
~~~~~~~~~~~~~

Building the image
^^^^^^^^^^^^^^^^^^

The image can be built to provide a working environment with all
dependencies installed.

.. code:: sh

    docker build -t local/victims-web .

Using the docker image
^^^^^^^^^^^^^^^^^^^^^^

The docker image built as shown above will not contain the application
source code but it expects the working directory to be mounted at
``/opt/source``.

.. code:: sh

    docker run --rm -it -v `pwd`:/opt/source local/victims-web

Docker Compose
~~~~~~~~~~~~~~

The ``docker-compose.yml`` file defines services required to run a
working copy of the server on your local machine. Starting the server
via ``docker-compose`` will;

#. start a supported version of MongoDB instance
#. seed the database with test data
#. start the web server using ``python -m victims.web``
#. bind to port 5000 on your localhost

Starting a server
^^^^^^^^^^^^^^^^^

This will start an instance of the server as described above. Note that
this is started with both ``DEBUG`` and ``TESTING`` enabled. This will
also ensure that your code is auto re-loaded if changed.

.. code:: sh

    docker-compose up server

Executing tests against your working copy
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In order to execute tests against your working copy of code, you may use
the ``test`` service as described in the ``docker-compose.yml`` file.
This will start up dependant services, load seed data and then execute
application tests and ``pep8``.

.. code:: sh

    docker-compose up test

Usage
-----

Secured API Access
~~~~~~~~~~~~~~~~~~

Submission endpoints like ``/service/submit/archive/java`` are secured
by an implementation similar to what is used by AWS. The authentication
token is expected in a HTTP header configured via the
``VICTIMS_API_HEADER`` configuration (default: ``X-Victims-Api``). If
this is not present or if validation/authentication fails, then it falls
back to *BASIC AUTH*.

An example using curl is as follows:

.. code:: sh

    $ curl -v -X PUT -H "X-Victims-Api: $APIKEY:$SIGNATURE" -H "Date: Thu, 22 Aug 2013 15:20:37 GMT" -F archive=@$ARCHIVE https://$VICTIMS_SERVER/service/submit/archive/java?version=VID\&groupId=GID\&artifactId=AID\&cves=CVE-2013-0000,CVE-2013-0001

This can also be done using *BASIC-AUTH* as follows:

.. code:: sh

    curl -v -u $USERNAME:$PASSWORD -X PUT -F archive=@$ARCHIVE_FILE https://$VICTIMS_SERVER/service/submit/archive/java?version=VID\&groupId=GID\&artifactId=AID\&cves=CVE-2013-0000,CVE-2013-0001

API Key and Client Secret Key
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Each account on victi.ms is allocated an API Key and Secret key by
default. This can be retrieved by visiting ``https://victi.ms/account``.
These can be regenerated using the form at
``https://victi.ms/account_edit``.

Signature
^^^^^^^^^

The signature is generated using ``HTTP Method``, ``Path``, ``Date`` and
the *MD5 hexdigest*.

**Notes\:**

-  The ``Path`` includes the query string parameters, e.g:
   ``/service/submit/archive/java?cves=CVE-0000-0000``
-  The MD5 checksum includes the data (if available) of all files that
   are being submitted. The checksums are sorted in ascending order
   before adding to the string.
-  The date is expected to be in ``GMT``. Eg:
   ``Thu, 22 Aug 2013 15:20:37 GMT``.

The following is a reference implementation in python:

.. code:: py

    from hmac import HMAC

    def generate_signature(secret, method, path, date, md5sums):
        md5sums.sort()
        ordered = [method, path, date] + md5sums
        string = ''

        for content in ordered:
            if content is None:
                raise ValueError('Required header not found')
            string += str(content)

        return HMAC(
            key=bytes(secret),
            msg=string.lower(),
            digestmod=sha512
        ).hexdigest().upper()

.. |Build Status| image:: https://travis-ci.org/victims/victims-web.png
   :target: https://travis-ci.org/victims/victims-web
.. |PyPI version| image:: https://badge.fury.io/py/victims-web.svg
   :target: https://badge.fury.io/py/victims-web
.. _PyPI Package: https://pypi.python.org/pypi/victims-web
