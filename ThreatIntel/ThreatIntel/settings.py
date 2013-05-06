#
# Utility values
#

# Courtesy of http://www.morethanseven.net/2009/02/11/django-settings-tip-setting-relative-paths/
import os.path
SITE_BASE = os.path.dirname(os.path.realpath(__file__))

#
# Core settings
#

DEBUG = True
TEMPLATE_DEBUG = DEBUG
ALLOWED_HOSTS = [] # FIXME
WSGI_APPLICATION = "ThreatIntel.wsgi.application"
ROOT_URLCONF = "ThreatIntel.urls"
SECRET_KEY = "z$a6sqedr$ni2zil+7oktg9_4e@!znm_4pufmm9bw=3n#@&amp;fo@" # FIXME
LOGGING_CONFIG = None

#
# Time and date
#

TIME_ZONE = "Etc/UTC"
USE_L10N = False
USE_TZ = True
DATE_FORMAT = "d M Y"
DATETIME_FORMAT = "d M Y H:i:s"

#
# i18n/l10n
#

LANGUAGE_CODE = "en-us"
USE_I18N = True
LOCALE_PATHS = [
        os.path.join(SITE_BASE, "../locale")
]

#
# Backends
#

TEMPLATE_LOADERS = [
    "django.template.loaders.filesystem.Loader",
    "django.template.loaders.app_directories.Loader",
#     "django.template.loaders.eggs.Loader",
]
MIDDLEWARE_CLASSES = [
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware", 
    #"django.middleware.csrf.CsrfResponseMiddleware",
    # Uncomment the next line for simple clickjacking protection:
    # "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
TEMPLATE_DIRS = [
    os.path.join(SITE_BASE, "../templates")
]
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    #"django.contrib.sites",
    "django.contrib.messages",
    #"django.contrib.staticfiles",
    "manage",
    # Uncomment the next line to enable the admin:
    # "django.contrib.admin",
    # Uncomment the next line to enable admin documentation:
    # "django.contrib.admindocs",
]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(SITE_BASE, "db.sqlite3")
    }
}

#
# Static files
#

STATIC_ROOT = ""
STATIC_URL = "/static/"
STATICFILES_DIRS = [
	os.path.join(SITE_BASE, "../static")
]
STATICFILES_FINDERS = [
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
#    "django.contrib.staticfiles.finders.DefaultStorageFinder",
]

#
# Authentication
#

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend"
]
LOGIN_URL = "/login"
LOGIN_REDIRECT_URL = "/query"
LOGOUT_URL = "/logout"
