"""
Authentication and authorization subsystem services.
"""

import re
import logging
log = logging.getLogger(__name__)

from ldap3 import SEARCH_SCOPE_WHOLE_SUBTREE, MODIFY_REPLACE, Connection,\
    STRATEGY_SYNC, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPOperationResult

# Helper filters
from ldap.filter import filter_format as ldap_format

from cornice import Service

from .validators import v_required
from .ldapcommon import ldap_server, ldap_usersdn, ldap_orgsdn, CONNECTIONS,\
    ldap_orgid, ldap_users_attributes_filter, ldap_user_search_filter,\
    ldap_active_user_search_filter, ldap_org_search_template, ManagerConnection
from .authcommon import create_token, valid_token
from .errors import json_error_handler
from .user import get_virtual_attributes, serialize_custom_attributes,\
    VIRTUAL_ATTRIBUTES

from .misc import list_partition

# Services

srv_login = Service(name='login', path='/login', cors_origins=('*',))

srv_logout = Service(name='logout', path='/logout', cors_origins=('*',))

srv_register = Service(name='register', path='/register', cors_origins=('*',))


@srv_login.post(error_handler=json_error_handler,
                validators=v_required('password', 'uid'))
def login(request):
    """
    Finds user DN using Manager account connection, checks if user is active
    and tries to bind to the new User session with given credentials.

    Returns authentication token, roles and requested attributes for initiated
    user-bound LDAP connection.

    **Request body:**

    ``{ uid, password, attributes }``

    **Response body:**

    ``{ 'token': token, 'roles': roles_obj, 'attributes': [ attributes ] }``
    or :ref:`errors`

    *roles_obj:*

    list of JSON objects:
    ``[ { 'id': id, 'o': organization_name,
    'role': role }, .. ]``

    **Errors:**
    ``ESEARCH, ENOTFOUND, EBIND, EPARAMS``
    """

    passw = request.json_body['password']
    uid = request.json_body['uid']
    attrs = []

    if 'attributes' in request.json_body and\
            type(request.json_body['attributes']) is list:
        attrs = request.json_body['attributes']

    # Connect, try to search for the user id, retrieve authentication code
    try:

        manager_connection = ManagerConnection()
        manager_connection.tls_bind()
        res = manager_connection.search(ldap_usersdn, ldap_format(
            ldap_active_user_search_filter,
                                        [uid]),
                                        SEARCH_SCOPE_WHOLE_SUBTREE,
                                        attributes=['lmPersonAuthCode',
                                                    'eduPersonEntitlement',
                                                    'lmPersonActive'])

    except LDAPOperationResult as e:
        request.errors.add('login:dnsearch', 'ESEARCH', e.description,
                           status=500)
        return {}
    if not res:
        request.errors.add('login:dnsearch', 'ENOTFOUND',
                           '(uid, lmPersonActive=TRUE) not found', status=403)
        return {}

    resp_attrs = manager_connection.response[0]['attributes']  # uid is unique

    log.debug("User search response -> %r", manager_connection.response)

    userdn = manager_connection.response[0]['dn']

    # Return list of roles dicts [{ 'id': orgid, 'o': 'Name', role: 'role' }]

    roles = []
    roles_d, admin_roles_d = {}, {}

    # XXX: roles (prefer 'admin' role over others)
    # FIXME: hardcoded LDAP attributes
    if 'eduPersonEntitlement' in resp_attrs:
        for entitlement in resp_attrs['eduPersonEntitlement']:
            try:
                oid, role = entitlement.split(":role:", 1)[1].split(":", 1)
            except ValueError:
                continue  # XXX: we just skip to next iteration
            if role == "admin":
                admin_roles_d.update([(oid, role)])
            else:
                roles_d.update([(oid, role)])

        roles_d.update(admin_roles_d)

        # fetch additional info about organizations for given roles
        if roles_d:
            org_search_filter = ldap_org_search_template
            org_search_filter += ("(" + ldap_orgid + "=%s)") \
                * len(roles_d) + "))"
            log.debug("org_search_filter -> %r", org_search_filter)

            try:
                res = manager_connection.search(ldap_orgsdn, ldap_format(
                    org_search_filter, roles_d.keys()),
                                                SEARCH_SCOPE_WHOLE_SUBTREE,
                                                attributes=ALL_ATTRIBUTES)
            except LDAPOperationResult as e:
                request.errors.add('login:orgssearch', 'ESEARCH', e.description,
                                   status=500)
                return {}
            if not res:
                request.errors.add('login:orgssearch', 'ENOTFOUND',
                                   'organization in entitlement not found',
                                   status=500)
                return {}

            log.debug("Org search response -> %r", manager_connection.response)

            for resp in manager_connection.response:
                oid = resp['attributes'][ldap_orgid][0]
                roles.append({'id': oid, 'o': resp['attributes']['o'][0],
                              'role': roles_d[oid]})

    # Try to bind as a specified user
    user_connection = Connection(ldap_server, user=userdn, password=passw,
                                 auto_bind=False, client_strategy=STRATEGY_SYNC,
                                 raise_exceptions=True, lazy=False)
    user_connection.open()
    user_connection.start_tls()

    try:
        user_connection.bind()
    except LDAPOperationResult as e:
        request.errors.add('login:bind', 'EBIND', e.description, status=403)
        return {}

    # Create a token for user session
    # log.debug("CONNECTIONS: %r", CONNECTIONS)
    while True:
        token = uid.encode() + b'-' + create_token()
        if token not in CONNECTIONS:
            CONNECTIONS[token] = {'uid': uid, 'connection': user_connection,
                                  'userdn': userdn}
            break

    # Return additional attributes if requested
    attr_values = {}

    if attrs:
        l_attrs, v_attrs = list_partition(attrs, lambda attr: attr in \
                                          VIRTUAL_ATTRIBUTES and 'get' in \
                                          VIRTUAL_ATTRIBUTES[attr])
        ldap_attrs = list(l_attrs)
        log.debug("ldap_attrs -> %r, v_attrs -> %r", list(ldap_attrs),
                  list(v_attrs))
        attr_values.update(get_virtual_attributes(user_connection, request,
                                                  userdn, v_attrs))

        try:
            res = user_connection.search(ldap_usersdn, ldap_format(
                ldap_users_attributes_filter, [uid]),
                                            SEARCH_SCOPE_WHOLE_SUBTREE,
                                         attributes=ldap_attrs)
        except LDAPOperationResult as e:
            request.errors.add('login:attrsearch', 'ESEARCH', e.description,
                               status=500)
            return {}

        if not res:
            request.errors.add('login:attrsearch', 'ENOTFOUND',
                               'user not found', status=400)
            return {}

        log.debug("result -> %r, response -> %r", res, user_connection.response)

        attr_values.update(
            user_connection.response[0]['attributes'] if 'attributes' in \
            user_connection.response[0] else {}
        )

        # load custom attributes
        serialize_custom_attributes(attr_values)

    return {'token': token, 'attributes': attr_values, 'roles': roles}


@srv_register.post(error_handler=json_error_handler,
                   validators=v_required('password', 'uid', 'authcode'))
def register(request):
    """
    Registers user by setting password, email (OPTIONAL), lmPersonActive and
    reseting initial authentication code to zero.

    User must not be active and `authcode` should match one in the directory
    otherwise errors are returned.

    .. note::
        Email is validated only by a naive regex.

    **Request body:**

    ``{ uid, authcode, password, email }``

    **Response body:**

    ``{}`` or :ref:`errors`

    **Errors:**
    ``ESEARCH, ENOTFOUND, EMODIFY, EPARAMS, EMAILSYNTAX, EALREADYACTIVE``
    """

    uid = request.json_body['uid']
    authcode = request.json_body['authcode']
    passw = request.json_body['password']

    # Connect, search for matching user id
    try:
        manager_connection = ManagerConnection()
        manager_connection.tls_bind()

        res = manager_connection.search(ldap_usersdn, ldap_format(
            ldap_user_search_filter,
                                        [uid]),
                                        SEARCH_SCOPE_WHOLE_SUBTREE,
                                        attributes=['lmPersonActive',
                                                    'lmPersonAuthCode'])

    except LDAPOperationResult as e:
        request.errors.add('register:dnsearch', 'ESEARCH', e.description,
                           status=500)
        return {}

    if not res:
        request.errors.add('register:dnsearch', 'ENOTFOUND', 'user not found',
                           status=403)
        return {}

    resp_attrs = manager_connection.response[0]['attributes']  # uid is unique
    log.debug("response attributes -> %r", resp_attrs)

    # FIXME: hardcoded fields
    if 'lmPersonActive' in resp_attrs and \
            resp_attrs['lmPersonActive'][0] == 'TRUE':
        request.errors.add('register:dnsearch',
                           'EALREADYACTIVE', 'user is already active or \
                           lmPersonActive attribute not present', status=403)
        return {}

    # FIXME: hardcoded fields
    if 'lmPersonAuthCode' not in resp_attrs or \
            resp_attrs['lmPersonAuthCode'][0] != authcode:
        request.errors.add('register:dnsearch',
                           'ENOTFOUND', 'wrong authcode or lmPersonAuthCode \
                           attribute not present', status=403)
        return {}

    userdn = manager_connection.response[0]['dn']

    modify_attrs = {'lmPersonAuthCode': [MODIFY_REPLACE, ['0']],
                    'lmPersonActive': [MODIFY_REPLACE, ['TRUE']],
                    'radiusTunnelPassword': [MODIFY_REPLACE, [passw]]}

    # FIXME: very basic validation
    if 'email' in request.json_body:
        email = request.json_body['email']
        if re.match(r"[^@]+@[^@]+\.[^@]+", email):
            modify_attrs['mail'] = [MODIFY_REPLACE, [email]]
        else:
            request.errors.add('register:emailcheck',
                               'EMAILSYNTAX', 'invalid email syntax',
                               status=403)
            return {}

    # Set password, email and reset authentication code
    try:
        manager_connection.passmod(userdn, passw)
        manager_connection.modify(userdn, modify_attrs)

    except LDAPOperationResult as e:
        request.errors.add('register:modify', 'EMODIFY', e.description,
                           status=403)
        return {}

    return {}


@srv_logout.post(error_handler=json_error_handler, validators=valid_token)
def logout(request):
    """
    Disconnects user session

    **Request body:**

    Only expects valid token in *X-Messaging-Token* request header.

    **Response body:**

    ``{}`` or :ref:`errors`

    **Errors:**
    ``EAUTH``
    """

    tok = request.validated['token']
    CONNECTIONS[tok]['connection'].unbind()  # Close LDAP connection
    CONNECTIONS.pop(tok)

    return {}
