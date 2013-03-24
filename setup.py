from setuptools import setup

setup(
    name='victims_web',
    version='1.9.0',
    description='The victi.ms language package to CVE service.',
    author='Steve Milner',
    url='http://www.victi.ms',

    install_requires=[
        'Flask>=0.8',
        'Flask-Login>=0.1.1',
        'Flask-Bcrypt',
        'Flask-SeaSurf',
        'Flask-Cache',
        'Flask-Admin',
        'pymongo>=2.3',
        'mongokit>=0.8.1',
        'Flask-MongoKit',
        'blinker>=1.2',
        'PyYAML'],
)
