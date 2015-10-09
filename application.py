# -*- coding: utf-8 -*-
from sqlalchemy import engine_from_config

import tornado.httpserver
import tornado.ioloop
import tornado.web
from tornado.options import options

import settings
from urls import url_patterns
from model import (
    DBSession,
    Base
)
# from model.users import User


class Application(tornado.web.Application):
    def __init__(self):
        tornado.web.Application.__init__(self, url_patterns, **options.as_dict())


def db_connection(prefix='sqlalchemy_'):
    """Konfiguracja bazy danych i połączenie z nią"""
    engine = engine_from_config(options, prefix)
    DBSession.configure(bind=engine)
    Base.metadata.bind = engine
    Base.metadata.create_all(engine)


if __name__ == "__main__":

    #db_connection()

    app = Application()

    from model.connections import APNService
    from model.messages import Payload

    apn = APNService(cert_file="certs/pushcert_dev.pem", key_file=None, sandbox=True)
    payload = Payload(alert="Hello World!", badge=1)
    apn.gateway_server.send_notification("99036da8fa94117c2ac999fdb3fa7275f42cc5fa851e2cccc1ad03937c7ed8d1", payload)

    #http_server = tornado.httpserver.HTTPServer(app)
    #http_server.listen(options.port)
    #tornado.ioloop.IOLoop.current().start()