# -*- coding: utf-8 -*-
import json
import logging
from binascii import a2b_hex

from cuckoo.model.utils import *

MAX_PAYLOAD_LENGTH = 4096


class Payload(object):
    """A class representing an APNs message payload"""
    def __init__(self, alert=None, badge=None, sound=None, category=None, custom=None, content_available=False):
        super(Payload, self).__init__()
        self.alert = alert
        self.badge = badge
        self.sound = sound
        self.category = category
        if not custom:
            self.custom = {}
        else:
            self.custom = custom
        self.content_available = content_available
        self._check_size()

    def dict(self):
        """Returns the payload as a regular Python dictionary"""
        d = {}
        if self.alert:
            # Alert can be either a string or a PayloadAlert
            # object
            if isinstance(self.alert, PayloadAlert):
                d['alert'] = self.alert.dict()
            else:
                d['alert'] = self.alert
        if self.sound:
            d['sound'] = self.sound
        if self.badge is not None:
            d['badge'] = int(self.badge)
        if self.category:
            d['category'] = self.category

        if self.content_available:
            d.update({'content-available': 1})

        d = {'aps': d}
        d.update(self.custom)
        return d

    def json(self):
        return json.dumps(self.dict(), separators=(',', ':'), ensure_ascii=False).encode('utf-8')

    def _check_size(self):
        payload_length = len(self.json())
        if payload_length > MAX_PAYLOAD_LENGTH:
            raise PayloadTooLargeError(payload_length)

    def __repr__(self):
        attrs = ("alert", "badge", "sound", "category", "custom")
        args = ", ".join(["%s=%r" % (n, getattr(self, n)) for n in attrs])
        return "%s(%s)" % (self.__class__.__name__, args)


class PayloadAlert(object):
    def __init__(self, title=None, body=None, title_loc_key=None, title_loc_args=None, action_loc_key=None,
                 loc_key=None, loc_args=None, launch_image=None):
        super(PayloadAlert, self).__init__()
        self.title = title
        self.body = body
        self.title_loc_key = title_loc_key
        self.title_loc_args = title_loc_args
        self.action_loc_key = action_loc_key
        self.loc_key = loc_key
        self.loc_args = loc_args
        self.launch_image = launch_image

    def dict(self):
        d = {}
        if self.title:
            d['title'] = self.title
        if self.body:
            d['body'] = self.body
        if self.title_loc_key:
            d['title-loc-key'] = self.title_loc_key
        if self.title_loc_args:
            d['title-loc-args'] = self.title_loc_args
        if self.action_loc_key:
            d['action-loc-key'] = self.action_loc_key
        if self.loc_key:
            d['loc-key'] = self.loc_key
        if self.loc_args:
            d['loc-args'] = self.loc_args
        if self.launch_image:
            d['launch-image'] = self.launch_image
        return d


class PayloadTooLargeError(Exception):
    def __init__(self, payload_size):
        super(PayloadTooLargeError, self).__init__()
        self.payload_size = payload_size


class Frame(object):
    """A class representing an APNs message frame for multiple sending"""
    def __init__(self):
        self.frame_data = bytearray()
        self.notification_data = list()

    def get_frame(self):
        return self.frame_data

    def add_item(self, token_hex, payload, identifier, expiry, priority):
        """Add a notification message to the frame"""
        item_len = 0
        self.frame_data.extend(b'\2' + packed_uint_big_endian(item_len))

        token_bin = a2b_hex(token_hex)
        token_length_bin = packed_ushort_big_endian(len(token_bin))
        token_item = b'\1' + token_length_bin + token_bin
        self.frame_data.extend(token_item)
        item_len += len(token_item)

        payload_json = payload.json()
        payload_length_bin = packed_ushort_big_endian(len(payload_json))
        payload_item = b'\2' + payload_length_bin + payload_json
        self.frame_data.extend(payload_item)
        item_len += len(payload_item)

        identifier_bin = packed_uint_big_endian(identifier)
        identifier_length_bin = packed_ushort_big_endian(len(identifier_bin))
        identifier_item = b'\3' + identifier_length_bin + identifier_bin
        self.frame_data.extend(identifier_item)
        item_len += len(identifier_item)

        expiry_bin = packed_uint_big_endian(expiry)
        expiry_length_bin = packed_ushort_big_endian(len(expiry_bin))
        expiry_item = b'\4' + expiry_length_bin + expiry_bin
        self.frame_data.extend(expiry_item)
        item_len += len(expiry_item)

        priority_bin = packed_uchar(priority)
        priority_length_bin = packed_ushort_big_endian(len(priority_bin))
        priority_item = b'\5' + priority_length_bin + priority_bin
        self.frame_data.extend(priority_item)
        item_len += len(priority_item)

        self.frame_data[-item_len-4:-item_len] = packed_uint_big_endian(item_len)

        self.notification_data.append({'token':token_hex, 'payload':payload, 'identifier':identifier, 'expiry':expiry, "priority":priority})

    def get_notifications(self, gateway_connection):
        notifications = list({'id': x['identifier'],
                              'message':gateway_connection._get_enhanced_notification(x['token'],
                                                                                      x['payload'],
                                                                                      x['identifier'],
                                                                                      x['expiry'])}
                                                                    for x in self.notification_data)
        return notifications

    def __str__(self):
        """Get the frame buffer"""
        return str(self.frame_data)

