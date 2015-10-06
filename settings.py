# -*- coding: utf-8 -*-
import argparse
import os
import logging
import logging.config
import logging.handlers
import configparser
import transaction

import tornado.template
from tornado.log import LogFormatter
from tornado.options import (
    define
)
from handlers.notifications import Error404

# Make filepaths relative to settings.
path = lambda root,*a: os.path.join(root, *a)
ROOT = os.path.dirname(os.path.abspath(__file__))

STATIC_ROOT = path(ROOT, 'static')
TEMPLATE_ROOT = path(ROOT, 'templates')
LOG_FOLDER = 'logs'

formatter = LogFormatter()
SMTPhandler = logging.handlers.SMTPHandler('smtp.megiteam.pl', 'noreply@talksinthecity.pl', 'bookm.Marcin.Ola+webapp@biokod.flowdock.com', 'Bookm Log',
                                           ('noreply@talksinthecity.pl', 'AQqWxayK9iy3'))
sql_log =  logging.getLogger('sqlalchemy.engine')
sql_log.setLevel(logging.WARNING)

sqlLogHandler = logging.handlers.TimedRotatingFileHandler(os.path.join(ROOT, LOG_FOLDER, 'bookm-sql.log'), when='midnight')
sqlLogHandler.setFormatter(formatter)
sql_log.addHandler(sqlLogHandler)

app_log = logging.getLogger("tornado.application")
app_log.setLevel(logging.DEBUG)
appLogHandler = logging.handlers.TimedRotatingFileHandler(os.path.join(ROOT, LOG_FOLDER, 'bookm-app.log'), when='midnight')
appLogHandler.setFormatter(formatter)
app_log.addHandler(appLogHandler)
#app_log.addHandler(SMTPhandler)

access_log = logging.getLogger("tornado.access")
access_log.setLevel(logging.DEBUG)
accessLogHandler = logging.handlers.TimedRotatingFileHandler(os.path.join(ROOT, LOG_FOLDER, 'bookm-access.log'), when='midnight')
accessLogHandler.setFormatter(formatter)
access_log.addHandler(accessLogHandler)

general_log = logging.getLogger("tornado.general")
general_log.setLevel(logging.DEBUG)
generalLogHandler = logging.handlers.TimedRotatingFileHandler(os.path.join(ROOT, LOG_FOLDER, 'bookm-general.log'), when='midnight')
generalLogHandler.setFormatter(formatter)
general_log.addHandler(generalLogHandler)
#general_log.addHandler(SMTPhandler)

define("debug", default=True)
define("port", default=8929)
define("static_path", default=STATIC_ROOT)
define("cookie_secret", default="lsidur$n9328unonceqpw#@$23x90n@#f")
define("xsrf_cookies", default=False)
define("template_loader", default=tornado.template.Loader(TEMPLATE_ROOT))
define("sqlalchemy_url", default="mysql+pymysql://cuckoo:123456@127.0.0.1/cuckoo?charset=utf8")
define("sqltest_url", default="mysql+pymysql://cuckoo:123456@127.0.0.1/cuckoo_test?charset=utf8")