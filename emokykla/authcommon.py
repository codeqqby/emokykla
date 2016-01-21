"""
Common authentication code.
"""

import binascii
import os

import logging
log = logging.getLogger(__name__)


from .ldapcommon import CONNECTIONS


def create_token():
    return binascii.b2a_hex(os.urandom(20))


def valid_token(request):

    log.debug("CONNECTIONS -> %r", CONNECTIONS)

    header = 'X-Messaging-Token'
    token = request.headers.get(header, '').encode()

    log.debug("Request token: %r", token)

    if not token:
        request.errors.add('valid_token', 'EAUTH', 'token not provided', status=401)
        return

    if token not in CONNECTIONS:
        request.errors.add('valid_token', 'EAUTH', 'missing token', status=401)
        return

    request.validated['token'] = token