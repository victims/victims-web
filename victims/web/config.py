from os import environ, makedirs
from os.path import isfile, isdir, join
from datetime import timedelta
from imp import load_source
from logging import getLogger, DEBUG as LOG_LEVEL_DEBUG

_ENFORCE = True
_ENFORCE_KEYS = ['SECRET_KEY', 'DEBUG', 'TESTING']

# Base Dir
VICTIMS_BASE_DIR = environ.get('VICTIMS_BASE_DIR', './victims-web-runtime')

LOGGER = getLogger()
LOG_FOLDER = environ.get('VICTIMS_LOG_DIR', join(VICTIMS_BASE_DIR, 'logs'))
LOG_LEVEL = LOG_LEVEL_DEBUG

FLASK_HOST = environ.get('FLASK_HOST', '127.0.0.1')
FLASK_PORT = int(environ.get('FLASK_PORT', 5000))

DEBUG = 'VICTIMS_DEBUG' in environ
TESTING = 'VICTIMS_TESTING' in environ
SECRET_KEY = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
PERMANENT_SESSION_LIFETIME = timedelta(1)

# File upload
UPLOAD_FOLDER = join(VICTIMS_BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = set(['egg', 'jar', 'gem'])

# File download
DOWNLOAD_FOLDER = join(VICTIMS_BASE_DIR, "downloads")

# Cache Configuration
CACHE_TYPE = 'null'
CACHE_DIR = environ.get('VICTIMS_CACHE_DIR', join(VICTIMS_BASE_DIR, 'cache'))
CACHE_NO_NULL_WARNING = True
CACHE_DEFAULT_TIMEOUT = 60 * 60
CACHE_THRESHOLD = 20

# MongoDB Configuration
MONGODB_SETTINGS = {
    'DB': environ.get('VICTIMS_DB', 'victims'),
    'HOST': environ.get('MONGODB_DB_HOST', 'localhost'),
    'PORT': int(environ.get('MONGODB_DB_PORT', 27017)),
}

# Available roles
VICTIMS_ROLES = ['admin', 'trusted']

# Auth Configuration
SESSION_PROTECTION = 'strong'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_NAME = 'victims'

# MongoEngine Session reaps are performed every SESSION_REAP_PERIOD
SESSION_REAP_PERIOD = timedelta(days=1)

# Cookie
REMEMBER_COOKIE_NAME = 'remember_token'
REMEMBER_COOKIE_DURATION = timedelta(1)
REMEMBER_COOKIE_DOMAIN = None

# CSRF Protection
CSRF_COOKIE_NAME = 'victimsc'
# CSRF_COOKIE_TIMEOUT = timedelta(1)
CSRF_DISABLED = False

# Captcha
RECAPTCHA_USE_SSL = True
RECAPTCHA_PRIVATE_KEY = 'PLACE_A_PRIVATE_KEY_HERE'
RECAPTCHA_PUBLIC_KEY = 'PLACE_A_PUBLIC_KEY_HERE'
RECAPTCHA_THEME = 'blackglass'

# Hashing options
BCRYPT_LOG_ROUNDS = 13

# Group settings
DEFAULT_GROUP = 'java'
SUBMISSION_GROUPS = {
    'java': ['groupId', 'artifactId', 'version'],
    'python': ['package', 'version'],
    'ruby': ['gem', 'version'],
}

# API Configuration
VICTIMS_API_HEADER = 'X-Victims-Api'
API_REQUEST_EXPIRY_MINS = 3
API_UPDATES_DEFAULT_FIELDS = [
    'cves', 'metadata', 'hash', 'hashes.sha512'
]

# plugin.charon
MAVEN_REPOSITORIES = [('jboss-ga', 'https://maven.repository.redhat.com/ga/')]

# WTF Config
WTF_CSRF_ENABLED = False

# Hashing config
HASHING_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512']

# Hashing commands for each group
# This will be used as command.format(archive=filename)
# Eg: 'java': 'victims-java hash {archive!s}'
HASHING_COMMANDS = {
}

# Optional settings

# Sentry Configuration
# SENTRY_DSN = ''

# Load custom configuration if available, this will override defaults above
CFG_KEY = 'VICTIMS_CONFIG'
if CFG_KEY in environ and isfile(environ[CFG_KEY]):
    envconfig = load_source('envconfig', environ[CFG_KEY])
    if _ENFORCE:
        for key in _ENFORCE_KEYS:
            if key not in envconfig.__dict__:
                raise ImportError(
                    'Custom config requires the following keys to be set: %s' %
                    (','.join(_ENFORCE_KEYS))
                )
    for key in envconfig.__dict__:
        if not key.startswith('_') and key in globals():
            globals()[key] = envconfig.__dict__[key]

# Post load actions

SESSION_COOKIE_SECURE = not DEBUG

# We do not need https when debugging
if DEBUG:
    PREFERRED_URL_SCHEME = 'http'
else:
    PREFERRED_URL_SCHEME = 'https'

# Create any required directories
for folder in [LOG_FOLDER, UPLOAD_FOLDER, DOWNLOAD_FOLDER, CACHE_DIR]:
    if not isdir(folder):
        makedirs(folder)

# Debug Toolbar
if DEBUG:
    DEBUG_TB_HOSTS = '127.0.0.1'
    DEBUG_TB_PROFILER_ENABLED = True
    DEBUG_TB_PANELS = (
        'flask_debugtoolbar.panels.versions.VersionDebugPanel',
        'flask_debugtoolbar.panels.timer.TimerDebugPanel',
        'flask_debugtoolbar.panels.headers.HeaderDebugPanel',
        'flask_debugtoolbar.panels.request_vars.RequestVarsDebugPanel',
        'flask_debugtoolbar.panels.template.TemplateDebugPanel',
        'flask_mongoengine.panels.MongoDebugPanel',
        'flask_debugtoolbar.panels.logger.LoggingPanel',
        'flask_debugtoolbar.panels.profiler.ProfilerDebugPanel',
    )
