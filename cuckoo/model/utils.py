# -*- coding: utf-8 -*-
from struct import pack, unpack

ER_STATUS = 'status'
ER_IDENTIFER = 'identifier'

def packed_uchar(num):
    """
    Returns an unsigned char in packed form
    """
    return pack('>B', num)


def packed_ushort_big_endian(num):
    """
    Returns an unsigned short in packed big-endian (network) form
    """
    return pack('>H', num)

def unpacked_ushort_big_endian(bytes):
    """
    Returns an unsigned short from a packed big-endian (network) byte
    array
    """
    return unpack('>H', bytes)[0]


def packed_uint_big_endian(num):
    """
    Returns an unsigned int in packed big-endian (network) form
    """
    return pack('>I', num)

def unpacked_uint_big_endian(bytes):
    """
    Returns an unsigned int from a packed big-endian (network) byte array
    """
    return unpack('>I', bytes)[0]

def unpacked_char_big_endian(bytes):
    """
    Returns an unsigned char from a packed big-endian (network) byte array
    """
    return unpack('c', bytes)[0]

def getListIndexFromID(this_class, the_list, identifier):
    return next(index for (index, d) in enumerate(the_list)
                    if d['id'] == identifier)

def convert_error_response_to_dict(this_class, error_response_tuple):
    return {ER_STATUS: error_response_tuple[0], ER_IDENTIFER: error_response_tuple[1]}
