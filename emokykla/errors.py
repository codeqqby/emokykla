"""
Common error handling related code.
"""

import json
import logging
log = logging.getLogger(__name__)

from webob import Response, exc

from .ldapcommon import DEBUG


class JSONError(exc.HTTPError):
    def __init__(self, msgs, status=400):

        # XXX: status code is pulled from the first error message
        # (probably not the most intuitive way)

        msg = next((msg for msg in msgs if 'status' in msg), None)
        log.debug("JSONError.__init__: errors -> %r", msgs)

        if msg:
            status = msg.pop('status')

        # leave only debugging info
        if not DEBUG:
            body = [{"description": "", "name": m['name'], "location": ""} for \
                    m in msgs]
        else:
            body = msgs

        Response.__init__(self, json.dumps(body))

        self.status = status
        self.content_type = 'application/json'


def json_error_handler(msgs):
    """Returns an HTTPError with given messages.

    The HTTP error content type is "application/json"
    """
    return JSONError(msgs)
