#!/usr/bin/env python
#
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
Source build and installation script.
"""
from os import path, sep, walk
from pip.download import PipSession
from pip.req import parse_requirements
from setuptools import setup, find_packages


def extract_requirements(filename):
    return [
        str(r.req)
        for r in parse_requirements(filename, session=PipSession)
    ]


def find_package_data(source, strip=''):
    pkg_data = []
    for root, dirs, files in walk(source):
        pkg_data += map(
            lambda f: path.join(root.replace(strip, '').lstrip(sep), f),
            files
        )
    return pkg_data


base_dir = path.dirname(__file__)

with open(path.join(base_dir, 'README.rst')) as f:
    long_description = f.read()

install_requires = extract_requirements('requirements.txt')
test_require = extract_requirements('test-requirements.txt')

setup(
    name='victims-web',
    version='2.2.0',
    description='Victims Web Service',
    author='Steve Milner',
    url='http://victi.ms',
    long_description=long_description,
    license='AGPLv3',
    classifiers=[
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Framework :: Flask',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Server',
        'Topic :: Security'
    ],
    packages=find_packages(
        exclude=['*.tests', '*.tests.*', 'tests.*', 'tests', 'test']
    ),
    include_package_data=True,
    package_data={
        'victims.web':
            find_package_data(
                'victims/web/templates', 'victims/web')
            + find_package_data(
                'victims/web/static', 'victims/web')
            + find_package_data(
                'victims/web/blueprints/ui/templates', 'victims/web')
            + find_package_data(
                'victims/web/blueprints/ui/static', 'victims/web')
    },
    install_requires=install_requires,
    tests_require=test_require,
    entry_points={
        'console_scripts': [
            'victims-web-server = victims.web.__main__:main',
        ],
    }
)
