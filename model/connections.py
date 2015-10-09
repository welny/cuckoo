# -*- coding: utf-8 -*-
from binascii import a2b_hex, b2a_hex
from datetime import datetime
from socket import (
    socket,
    timeout,
    AF_INET,
    SOCK_STREAM
)
from socket import error as socket_error
import sys, ssl, select, time, collections, itertools
import threading

try:
    from ssl import wrap_socket, SSLError
except ImportError:
    from socket import ssl as wrap_socket, sslerror as SSLError

from _ssl import SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE

from model.utils import *
from settings import provider_log



NOTIFICATION_COMMAND = 0
ENHANCED_NOTIFICATION_COMMAND = 1

NOTIFICATION_FORMAT = (
     '!'   # network big-endian
     'B'   # command
     'H'   # token length
     '32s' # token
     'H'   # payload length
     '%ds' # payload
    )

ENHANCED_NOTIFICATION_FORMAT = (
     '!'   # network big-endian
     'B'   # command
     'I'   # identifier
     'I'   # expiry
     'H'   # token length
     '32s' # token
     'H'   # payload length
     '%ds' # payload
    )

ERROR_RESPONSE_FORMAT = (
     '!'   # network big-endian
     'B'   # command
     'B'   # status
     'I'   # identifier
    )

TOKEN_LENGTH = 32
ERROR_RESPONSE_LENGTH = 6
DELAY_RESEND_SEC = 0.0
SENT_BUFFER_QTY = 100000
WAIT_WRITE_TIMEOUT_SEC = 10
WAIT_READ_TIMEOUT_SEC = 10
WRITE_RETRY = 3

class APNService:

    def __init__(self, cert_file=None, key_file=None, sandbox=False):
        """
        Set use_sandbox to True to use the sandbox (test) APNs servers.
        Default is False.
        """
        super(APNService, self).__init__()
        self.sandbox = sandbox
        self.cert_file = cert_file
        self.key_file = key_file
        self._feedback_connection = None
        self._gateway_connection = None

    @property
    def feedback_server(self):
        if not self._feedback_connection:
            self._feedback_connection = FeedbackConnection(
                sandbox = self.sandbox,
                cert_file = self.cert_file,
                key_file = self.key_file
            )
        return self._feedback_connection

    @property
    def gateway_server(self):
        if not self._gateway_connection:
            self._gateway_connection = GatewayConnection(
                sandbox = self.sandbox,
                cert_file = self.cert_file,
                key_file = self.key_file
            )
        return self._gateway_connection


class Connection(object):
    """
    A generic connection class for communicating with the APNs
    """
    def __init__(self, cert_file=None, key_file=None, timeout=None):
        super(Connection, self).__init__()
        self.cert_file = cert_file
        self.key_file = key_file
        self.timeout = timeout
        self._socket = None
        self._ssl = None
        self.connection_alive = False

    def __del__(self):
        self._disconnect();

    def _connect(self):
        # Establish an SSL connection
        provider_log.debug("%s APNS connection establishing..." % self.__class__.__name__)

        # Fallback for socket timeout.
        for i in range(3):
            try:
                self._socket = socket(AF_INET, SOCK_STREAM)
                self._socket.settimeout(self.timeout)
                self._socket.connect((self.server, self.port))
                break
            except timeout:
                pass
            except:
                raise

        self._last_activity_time = time.time()
        self._socket.setblocking(False)
        self._ssl = wrap_socket(self._socket, self.key_file, self.cert_file,
                                    do_handshake_on_connect=False)
        while True:
            try:
                self._ssl.do_handshake()
                break
            except ssl.SSLError as err:
                if ssl.SSL_ERROR_WANT_READ == err.args[0]:
                    select.select([self._ssl], [], [])
                elif ssl.SSL_ERROR_WANT_WRITE == err.args[0]:
                    select.select([], [self._ssl], [])
                else:
                    raise

        self.connection_alive = True
        provider_log.debug("%s APNS connection established" % self.__class__.__name__)

    def _disconnect(self):
        if self.connection_alive:
            if self._socket:
                self._socket.close()
            if self._ssl:
                self._ssl.close()
            self.connection_alive = False
            provider_log.info(" %s APNS connection closed" % self.__class__.__name__)

    def _connection(self):
        if not self._ssl or not self.connection_alive:
            self._connect()
        return self._ssl

    def read(self, n=None):
        return self._connection().read(n)

    def write(self, string):

        self._last_activity_time = time.time()
        _, wlist, _ = select.select([], [self._connection()], [], WAIT_WRITE_TIMEOUT_SEC)

        if len(wlist) > 0:
            length = self._connection().sendall(string)
            if length == 0:
                provider_log.debug("sent length: %d" % length) #DEBUG
        else:
            provider_log.warning("write socket descriptor is not ready after " + str(WAIT_WRITE_TIMEOUT_SEC))


class FeedbackConnection(Connection):
    """
    A class representing a connection to the APNs Feedback server
    """
    def __init__(self, sandbox=False, **kwargs):
        super(FeedbackConnection, self).__init__(**kwargs)
        self.server = (
            'feedback.push.apple.com',
            'feedback.sandbox.push.apple.com')[sandbox]
        self.port = 2196

    def _chunks(self):
        BUF_SIZE = 4096
        while 1:
            data = self.read(BUF_SIZE)
            yield data
            if not data:
                break

    def items(self):
        """
        A generator that yields (token_hex, fail_time) pairs retrieved from
        the APNs feedback server
        """
        buff = ''
        for chunk in self._chunks():
            buff += chunk

            # Quit if there's no more data to read
            if not buff:
                break

            # Sanity check: after a socket read we should always have at least
            # 6 bytes in the buffer
            if len(buff) < 6:
                break

            while len(buff) > 6:
                token_length = unpacked_ushort_big_endian(buff[4:6])
                bytes_to_read = 6 + token_length
                if len(buff) >= bytes_to_read:
                    fail_time_unix = unpacked_uint_big_endian(buff[0:4])
                    fail_time = datetime.utcfromtimestamp(fail_time_unix)
                    token = b2a_hex(buff[6:bytes_to_read])

                    yield (token, fail_time)

                    # Remove data for current token from buffer
                    buff = buff[bytes_to_read:]
                else:
                    # break out of inner while loop - i.e. go and fetch
                    # some more data and append to buffer
                    break

class GatewayConnection(Connection):
    """
    A class that represents a connection to the APNs gateway server
    """

    def __init__(self, sandbox=False, **kwargs):
        super(GatewayConnection, self).__init__(**kwargs)
        self.server = (
            'gateway.push.apple.com',
            'gateway.sandbox.push.apple.com')[sandbox]
        self.port = 2195

        self._last_activity_time = time.time()

        self._send_lock = threading.RLock()
        self._error_response_handler_worker = None
        self._response_listener = None

        self._sent_notifications = collections.deque(maxlen=SENT_BUFFER_QTY)

    def _init_error_response_handler_worker(self):
        self._send_lock = threading.RLock()
        self._error_response_handler_worker = self.ErrorResponseHandlerWorker(apns_connection=self)
        self._error_response_handler_worker.start()
        provider_log.debug("initialized error-response handler worker")

    def _get_notification(self, token_hex, payload):
        """
        Takes a token as a hex string and a payload as a Python dict and sends
        the notification
        """
        token_bin = a2b_hex(token_hex)
        token_length_bin = packed_ushort_big_endian(len(token_bin))
        payload_json = payload.json()
        payload_length_bin = packed_ushort_big_endian(len(payload_json))

        zero_byte = '\0'
        if sys.version_info[0] != 2:
            zero_byte = bytes(zero_byte, 'utf-8')
        notification = (zero_byte + token_length_bin + token_bin
            + payload_length_bin + payload_json)

        return notification

    def _get_enhanced_notification(self, token_hex, payload, identifier, expiry):
        """
        form notification data in an enhanced format
        """
        token = a2b_hex(token_hex)
        payload = payload.json()
        fmt = ENHANCED_NOTIFICATION_FORMAT % len(payload)
        notification = pack(fmt, ENHANCED_NOTIFICATION_COMMAND, identifier, expiry,
                            TOKEN_LENGTH, token, len(payload), payload)
        return notification

    def send_notification(self, token_hex, payload, identifier=0, expiry=0):
        """
        in enhanced mode, send_notification may return error response from APNs if any
        """
        self._last_activity_time = time.time()
        message = self._get_enhanced_notification(token_hex, payload,
                                                       identifier, expiry)

        for i in range(WRITE_RETRY):
            try:
                with self._send_lock:
                    self._make_sure_error_response_handler_worker_alive()
                    self.write(message)
                    self._sent_notifications.append(dict({'id': identifier, 'message': message}))
                break
            except socket_error as e:
                delay = 10 + (i * 2)
                provider_log.exception("sending notification with id:" + str(identifier) +
                             " to APNS failed: " + str(type(e)) + ": " + str(e) +
                             " in " + str(i+1) + "th attempt, will wait " + str(delay) + " secs for next action")
                time.sleep(delay) # wait potential error-response to be read

    def _make_sure_error_response_handler_worker_alive(self):
        if (not self._error_response_handler_worker
            or not self._error_response_handler_worker.is_alive()):
            self._init_error_response_handler_worker()
            TIMEOUT_SEC = 10
            for _ in range(TIMEOUT_SEC):
                if self._error_response_handler_worker.is_alive():
                    provider_log.debug("error response handler worker is running")
                    return
                time.sleep(1)
            provider_log.warning("error response handler worker is not started after %s secs" % TIMEOUT_SEC)

    def send_notification_multiple(self, frame):
        self._sent_notifications += frame.get_notifications(self)
        return self.write(frame.get_frame())

    def register_response_listener(self, response_listener):
        self._response_listener = response_listener

    def force_close(self):
        if self._error_response_handler_worker:
            self._error_response_handler_worker.close()

    def _is_idle_timeout(self):
        TIMEOUT_IDLE = 30
        return (time.time() - self._last_activity_time) >= TIMEOUT_IDLE

    class ErrorResponseHandlerWorker(threading.Thread):
        def __init__(self, apns_connection):
            threading.Thread.__init__(self, name=self.__class__.__name__)
            self._apns_connection = apns_connection
            self._close_signal = False

        def close(self):
            self._close_signal = True

        def run(self):
            while True:
                if self._close_signal:
                    provider_log.debug("received close thread signal")
                    break

                if self._apns_connection._is_idle_timeout():
                    idled_time = (time.time() - self._apns_connection._last_activity_time)
                    provider_log.debug("connection idle after %d secs" % idled_time)
                    break

                if not self._apns_connection.connection_alive:
                    time.sleep(1)
                    continue

                try:
                    rlist, _, _ = select.select([self._apns_connection._connection()], [], [], WAIT_READ_TIMEOUT_SEC)

                    if len(rlist) > 0: # there's some data from APNs
                        with self._apns_connection._send_lock:
                            buff = self._apns_connection.read(ERROR_RESPONSE_LENGTH)
                            if len(buff) == ERROR_RESPONSE_LENGTH:
                                command, status, identifier = unpack(ERROR_RESPONSE_FORMAT, buff)
                                if 8 == command: # there is error response from APNS
                                    error_response = (status, identifier)
                                    if self._apns_connection._response_listener:
                                        self._apns_connection._response_listener(convert_error_response_to_dict(*error_response))
                                    provider_log.info("got error-response from APNS:" + str(error_response))
                                    self._apns_connection._disconnect()
                                    self._resend_notifications_by_id(identifier)
                            if len(buff) == 0:
                                provider_log.warning("read socket got 0 bytes data") #DEBUG
                                self._apns_connection._disconnect()

                except socket_error as e: # APNS close connection arbitrarily
                    provider_log.exception("exception occur when reading APNS error-response: " + str(type(e)) + ": " + str(e)) #DEBUG
                    self._apns_connection._disconnect()
                    continue

                time.sleep(0.1) #avoid crazy loop if something bad happened. e.g. using invalid certificate

            self._apns_connection._disconnect()
            provider_log.debug("error-response handler worker closed") #DEBUG

        def _resend_notifications_by_id(self, failed_identifier):
            fail_idx = getListIndexFromID(self._apns_connection._sent_notifications, failed_identifier)
            #pop-out success notifications till failed one
            self._resend_notification_by_range(fail_idx+1, len(self._apns_connection._sent_notifications))
            return

        def _resend_notification_by_range(self, start_idx, end_idx):
            self._apns_connection._sent_notifications = collections.deque(itertools.islice(self._apns_connection._sent_notifications, start_idx, end_idx))
            provider_log.info("resending %s notifications to APNS" % len(self._apns_connection._sent_notifications)) #DEBUG
            for sent_notification in self._apns_connection._sent_notifications:
                provider_log.debug("resending notification with id:" + str(sent_notification['id']) + " to APNS") #DEBUG
                try:
                    self._apns_connection.write(sent_notification['message'])
                except socket_error as e:
                    provider_log.exception("resending notification with id:" + str(sent_notification['id']) + " failed: " + str(type(e)) + ": " + str(e)) #DEBUG
                    break
                time.sleep(DELAY_RESEND_SEC) #DEBUG

