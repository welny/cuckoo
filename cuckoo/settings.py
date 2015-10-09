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
# Make filepaths relative to settings.
path = lambda root,*a: os.path.join(root, *a)
ROOT = os.path.dirname(os.path.abspath(__file__))

STATIC_ROOT = path(ROOT, 'static')
TEMPLATE_ROOT = path(ROOT, 'templates')
LOG_FOLDER = 'logs'

formatter = LogFormatter()
SMTPhandler = logging.handlers.SMTPHandler('smtp.megiteam.pl', 'noreply@talksinthecity.pl', 'bookm.Marcin.Ola+webapp@biokod.flowdock.com', 'Cuckoo Log',
                                           ('noreply@talksinthecity.pl', 'AQqWxayK9iy3'))
provider_log = logging.getLogger("cuckoo")
provider_log.setLevel(logging.DEBUG)
providerLogHandler = logging.handlers.TimedRotatingFileHandler(os.path.join(ROOT, LOG_FOLDER, 'cuckoo-general.log'), when='midnight')
providerLogHandler.setFormatter(formatter)
provider_log.addHandler(providerLogHandler)
#provider_log.addHandler(SMTPhandler)

define("debug", default=True)
define("port", default=8929)
define("static_path", default=STATIC_ROOT)
define("cookie_secret", default="lsidur$n9328unonceqpw#@$23x90n@#f")
define("xsrf_cookies", default=False)
define("template_loader", default=tornado.template.Loader(TEMPLATE_ROOT))
define("sqlalchemy_url", default="mysql+pymysql://cuckoo:123456@127.0.0.1/cuckoo?charset=utf8")
define("sqltest_url", default="mysql+pymysql://cuckoo:123456@127.0.0.1/cuckoo_test?charset=utf8")