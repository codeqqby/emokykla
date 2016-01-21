"""
User management subsystem resources (/users/...).
"""

import sys
import re
import binascii
import logging
log = logging.getLogger(__name__)

from cornice.resource import resource, view

from ldap3 import SEARCH_SCOPE_WHOLE_SUBTREE, ALL_ATTRIBUTES, MODIFY_REPLACE,\
    MODIFY_DELETE, MODIFY_ADD
from ldap3.core.exceptions import LDAPOperationResult

from ldap.filter import filter_format as ldap_format, escape_filter_chars
from ldap.passmod import passmod

from .ldapcommon import CONNECTIONS, ldap_usersdn, ldap_users_attributes_filter,\
    ldap_user_obj_filter, ManagerConnection, USE_MANAGER, ldap_commonname,\
    ldap_userclass, ldap_org_search_template, ldap_orgid, ldap_orgsdn,\
    get_unique_uid, ldap_user_obj_del_filter, ldap_user_dn_template,\
    ldap_orgadminsdn, groupify, ldap_usergrpsdn_template
from .authcommon import valid_token
from .errors import json_error_handler

from .misc import list_partition


def attr_passmod(conn, request, userdn, value):
    """Set password using LDAP PASSMOD extended operation."""
    log.debug("userdn -> %r, password -> %r", userdn, value)
    try:
        passmod(conn, userdn, value)
    except LDAPOperationResult as e:
        log.error("exception -> %e, request -> %r", e, request)
        return

    # XXX: set radiusTunnelPassword
    try:
        log.debug("setting radiusTunnelPassword..")
        conn.modify(userdn, {'radiusTunnelPassword': [MODIFY_REPLACE, [value]]})
    except LDAPOperationResult as e:
        log.error("exception -> %e, request -> %r", e, request)

def adm_group(conn, request, userdn, value):
    """Add user to the admin group."""
    log.debug("userdn -> %r, admingroup -> %r", userdn, value)
    ldap_attrs = {'member': [MODIFY_ADD, [userdn]]}
    try:
        log.debug("setting admin group")
        conn.modify(ldap_format(ldap_orgadminsdn, [value]), ldap_attrs)
    except LDAPOperationResult as e:
        log.error("exception -> %e, request -> %r", e, request)

VIRTUAL_ATTRIBUTES = {
    'customField': {'get': (lambda *args: ['english', 'param2']),
                    'set': (lambda *args: True)},
    'password':    {'set': attr_passmod},
    'radiusTunnelPassword': {'get': (lambda *args: ['NULL']),
                             'set': (lambda *args: True)},
    'admingroup':  {'set': adm_group},
}

ATTRIBUTE_SERIALIZERS = {
    'customField': {'load': (lambda v: v + ['serialized']),
                    'store': (lambda v: [e for e in v if e != 'serialized'])
                   }
}

user_desc = """
Provides RESTful resources for managing user attributes.
"""

collection_user_desc = """
Allows to search/filter through the collection of users.
"""


def get_virtual_attributes(connection, request, dn, attrs):
    """
    Calls virtual attributes getters and returns dict with their respective
    results (values of virtual attributes).
    """
    values = {}
    for attr in attrs:
        try:
            values[attr] = VIRTUAL_ATTRIBUTES[attr]['get'](connection, request,
                                                           dn)
        except:
            log.error("exception -> %r", sys.exc_info[0])  # TODO: handle errors
    return values


def set_virtual_attributes(connection, request, dn, attrs):
    """
    Similar to above only for setting virtual attributes. `attrs` is
    a dictionary of key,value pairs.
    """
    for k, v in attrs.items():
        try:
            VIRTUAL_ATTRIBUTES[k]['set'](connection, request, dn, v)
        except:
            log.error("exception -> %r", sys.exc_info[0])  # TODO: handle errors


def serialize_custom_attributes(values, method='load'):
    """
    Modifies custom attribute values using corresponding serializer method
    ('load' or 'store').
    `values` dict is modified
    """
    for k in values:
        if k in ATTRIBUTE_SERIALIZERS:
            try:
                values[k] = ATTRIBUTE_SERIALIZERS[k][method](values[k])
            except:
                log.error("exception -> %r", sys.exc_info[0])  # TODO: errors


@resource(collection_path='/users', path='/users/{uid}*attr',
          cors_origins=('*',), description=user_desc,
          collection_description=collection_user_desc)
class User(object):

    def __init__(self, request):
        self.request = request

    @view(error_handler=json_error_handler, validators=valid_token)
    def get(self):
        """
        Returns requested attributes for given `uid`.

        Attributes are specified in the **request URL** such as
        `/users/<uid>/attribute1/attribute2`. If none specified all attributes
        are returned (*).

        `roles` is a special attribute and when requested it returns 'role'
        object described below.

        **Request body:**

        ``{ }``

        **Response body:**

        ``{ attributes, [ 'role': roles_obj ] }`` or :ref:`errors`

        *roles_obj:*

        list of JSON objects:

        ``[ { 'id': id, 'o': organization_name, 'role': role }, .. ]``

        **Errors:**
        ``ESEARCH, ENOTFOUND, EAUTH``
        """

        log.debug("self.request.matchdict -> %r, params -> %r",
                  self.request.matchdict, self.request.params)

        uid = self.request.matchdict['uid']
        tok = self.request.validated['token']

        if not USE_MANAGER:
            conn = CONNECTIONS[tok]['connection']
        else:
            conn = ManagerConnection()
            conn.tls_bind()

        log.debug("connection -> %r", conn)
        values = {}
        l_attrs, v_attrs = list_partition(self.request.matchdict['attr'],
                                          lambda attr: attr in \
                                                  VIRTUAL_ATTRIBUTES and 'get' \
                                                  in VIRTUAL_ATTRIBUTES[attr])
        ldap_attrs = list(l_attrs)

        ldap_attrs = ldap_attrs or ALL_ATTRIBUTES

        ldap_attrs = set(ldap_attrs)  # unique

        # XXX: hardcoded attributes
        need_roles = False

        if 'roles' in ldap_attrs:
            need_roles = True
            # get entitlement if we need roles
            ldap_attrs = list(ldap_attrs | set(['eduPersonEntitlement']))
            ldap_attrs.remove('roles')
        else:
            ldap_attrs = list(ldap_attrs)

        try:
            res = conn.search(ldap_usersdn,
                              ldap_format(ldap_users_attributes_filter, [uid]),
                              SEARCH_SCOPE_WHOLE_SUBTREE, attributes=ldap_attrs)
        except LDAPOperationResult as e:
            self.request.errors.add('User.get:search', 'ESEARCH', e.description,
                                    status=500)
            return {}

        if not res:
            self.request.errors.add('User.get:search', 'ENOTFOUND',
                                    'user not found', status=400)
            return {}

        dn = conn.response[0]['dn']
        values = dict(conn.response[0].pop('attributes', {}))

        values.update(get_virtual_attributes(conn, self.request, dn, v_attrs))
        serialize_custom_attributes(values)
        log.debug("connection.response -> %r", conn.response)

        roles = []
        roles_d, admin_roles_d = {}, {}

        # XXX: roles (prefer 'admin' role over others)
        # XXX: hardcoded LDAP attributes
        if need_roles and 'eduPersonEntitlement' in values:
            for entitlement in values['eduPersonEntitlement']:
                try:
                    oid, role = entitlement.split(":role:", 1)[1].split(":", 1)
                except ValueError:
                    # we just skip to next iteration
                    # (urn:mace:terena.org:role:manager)
                    continue
                if role == "admin":
                    admin_roles_d.update([(oid, role)])
                else:
                    roles_d.update([(oid, role)])

            roles_d.update(admin_roles_d)

            # fetch additional info about organizations for given roles
            if roles_d:
                org_search_filter = ldap_org_search_template
                org_search_filter += ("(" + ldap_orgid + "=%s)") * len(roles_d)\
                    + "))"
                log.debug("org_search_filter -> %r",
                          org_search_filter)

                try:
                    res = conn.search(ldap_orgsdn,
                                      ldap_format(org_search_filter, roles_d.keys()),
                                      SEARCH_SCOPE_WHOLE_SUBTREE,
                                      attributes=ALL_ATTRIBUTES)
                except LDAPOperationResult as e:
                    self.request.errors.add('User.get:orgssearch', 'ESEARCH',
                                            e.description, status=500)
                    return {}
                if not res:
                    self.request.errors.add('User.get:orgssearch', 'ENOTFOUND',
                                            'organization in entitlement not found', status=500)
                    return {}

                log.debug("Org search response -> %r", conn.response)

                for resp in conn.response:
                    oid = resp['attributes'][ldap_orgid][0]
                    roles.append({'id': oid, 'o': resp['attributes']['o'][0], 'role': roles_d[oid]})

                values['roles'] = roles

        return values

    @view(error_handler=json_error_handler, validators=valid_token)
    def put(self):
        """
        Updates selected user attributes.

        Attributes and their values are specified in request body.

        Controller makes sure that any attributes requiring special treatment
        (such as `password` which may require special LDAP extended password
        modification operation -
        `RFC3062 <http://www.ietf.org/rfc/rfc3062.txt>`_) are handled correctly.
        This is implemented either by using VIRTUAL_ATTRIBUTES and/or
        ATTRIBUTE_SERIALIZERS
        (see `user.py` source code).

        Special attribute `op` specifies the operation for updating attributes,
        supported values are:

        **"add"**, **"delete"**, **"replace"** (the default).

        **Request body:**

        ``{ 'attribute1' : ['value1', .. ], 'attribute2' : ['value2', .. ], ..
        }``

        **Response body:**

        ``{}`` or :ref:`errors`

        **Errors:**
        ``EPARAMS, ESEARCH, ENOTFOUND, EMODIFY, EAUTH``
        """

        uid = self.request.matchdict['uid']
        tok = self.request.validated['token']

        if not USE_MANAGER:
            conn = CONNECTIONS[tok]['connection']
        else:
            conn = ManagerConnection()
            conn.tls_bind()

        try:
            jb = self.request.json_body
        except ValueError:
            self.request.errors.add('User.put', 'EPARAMS',
                                    'ValueError while parsing JSON body')
            return {}

        # Check if we are acting on our own DN to save for additional search

        contest = conn.user if USE_MANAGER else CONNECTIONS[tok]['uid']

        if uid == contest:
            dn = conn.user
        else:
            try:
                res = conn.search(ldap_usersdn,
                                  ldap_format(ldap_users_attributes_filter, [uid]),
                                  SEARCH_SCOPE_WHOLE_SUBTREE)
            except LDAPOperationResult as e:
                self.request.errors.add('User.put:searchdn', 'ESEARCH',
                                        e.description, status=500)
                return {}

            if not res:
                self.request.errors.add('User.put:searchdn', 'ENOTFOUND',
                                        'user not found', status=400)
                return {}

            dn = conn.response[0]['dn']

        op = MODIFY_REPLACE
        if 'op' in jb:
            if jb['op'] == "add":
                op = MODIFY_ADD
            elif jb['op'] == "delete":
                op = MODIFY_DELETE
            del jb['op']

        # Partition attribute dictionary
        ldap_mod, v_attrs = {}, {}
        for attr, val in jb.items():
            if attr in VIRTUAL_ATTRIBUTES and 'set' in VIRTUAL_ATTRIBUTES[attr]:
                v_attrs[attr] = val
            else:
                ldap_mod[attr] = [op, val]

        log.debug("ldap_mod -> %r", ldap_mod)
        # Set virtual attributes first
        set_virtual_attributes(conn, self.request, dn, v_attrs)

        # Set remaining
        if ldap_mod:
            serialize_custom_attributes(ldap_mod)
            try:
                conn.modify(dn, ldap_mod)
            except LDAPOperationResult as e:
                self.request.errors.add('User.put:modify', 'EMODIFY',
                                        e.description, status=403)
                return {}

        return {'output': 'OK'}

    @view(error_handler=json_error_handler, validators=valid_token)
    def delete(self):
        """
        Deletes given uids.

        Multiple uids can be deleted like this:
        `/users/<uid>/<uid2>/<uid3>`

        **Request body:**

        ``{}``

        **Response body:**

        ``{}`` or :ref:`errors`

        **Errors:**
        ``EDELETE, EAUTH``
        """

        log.debug("self.request.matchdict -> %r, params -> %r",
                  self.request.matchdict, self.request.params)

        uids = [self.request.matchdict['uid']] + \
            list(self.request.matchdict['attr'])
        tok = self.request.validated['token']

        if not USE_MANAGER:
            conn = CONNECTIONS[tok]['connection']
        else:
            conn = ManagerConnection()
            conn.tls_bind()

        log.debug("connection -> %r", conn)
        log.debug("uids -> %r", uids)

        try:
            for uid in uids:
                conn.delete(ldap_format(ldap_user_dn_template, [uid]))
        except LDAPOperationResult as e:
            self.request.errors.add('User.delete', 'EDELETE', e.description,
                                    status=403)

        return {'output': 'OK'}

    @view(error_handler=json_error_handler, validators=valid_token)
    def collection_get(self):
        """
        Searches for users matching filters attributes.

        Filters are specified in the **request URL** such as:
        ``/users/attribute1=value1&attribute2=value2``.

        Paging (limiting results) is supported through OPTIONAL `page_size` and
        `page_cookie` URL parameters.

        By default a list of JSON objects containing only `uid` attributes is
        returned, additional attributes can be returned by passing `attributes`
        URL parameter, example:
        ``/users/attribute1=value1&attributes=displayName,givenName,lmPersonAuthCode``.

        More examples:

        1) Users belonging to organization (school) id *1234*:
            ``/users?lmPersonOrgDN=lmOrgJAK=1234,ou=Orgs,dc=lm,dc=lt``
        2) Users with last name 'Petraitis':
            ``/users?sn=Petraitis``
        3) Retrieve some attributes of users with first name 'Petras':
            ``/users?attributes=o,uid,lmPersonAuthCode,displayName&displayName=Petras*``
        4) Get all teachers of school id *1234*:
            ``/users?lmPersonOrgDN=lmOrgJAK=1234,ou=Orgs,dc=lm,dc=lt&eduPersonAffiliation=employee``

        **Request body:**

        ``{ }``

        **Response body:**

        ``{ 'results': [ { 'uid': uid, attributes .. }, .. ],
        'page_cookie': page_cookie  }`` or :ref:`errors`

        **Errors:**
        ``ESEARCH, ENOTFOUND, EAUTH``
        """

        ldap_filt = ldap_user_obj_filter

        reqpar = dict(self.request.params)
        log.debug("params -> %r", reqpar)

        tok = self.request.validated['token']

        if not USE_MANAGER:
            conn = CONNECTIONS[tok]['connection']
        else:
            conn = ManagerConnection()
            conn.tls_bind()

        log.debug("connection -> %r", conn)

        page_size = int(reqpar.pop('page_size', 0))
        try:
            page_cookie = binascii.unhexlify(reqpar.pop('page_cookie'))
        except (binascii.Error, KeyError):
            page_cookie = ''

        ret_attributes = reqpar.pop('attributes', '').split(',') \
            if 'attributes' in reqpar else []

        l_attrs, v_attrs = list_partition(ret_attributes,
                                          lambda attr: attr in
                                          VIRTUAL_ATTRIBUTES and 'get' in
                                          VIRTUAL_ATTRIBUTES[attr])
        ldap_attrs = list(l_attrs) or ['uid']
        log.debug("ldap_attrs -> %r", ldap_attrs)

        # build a filter from the rest of URL
        for k, v in reqpar.items():
            val = escape_filter_chars(v)
            val = val.replace(r'\2a', r'*')
            ldap_filt += '({}={})'.format(escape_filter_chars(k), val)
        ldap_filt += ')'

        try:
            log.debug("ldap_filt -> %r, page_size -> %r, \
                    page_cookie -> %r",
                      ldap_filt, page_size, page_cookie)
            res = conn.search(ldap_usersdn, ldap_filt,
                              SEARCH_SCOPE_WHOLE_SUBTREE,
                              attributes=ldap_attrs, paged_size=page_size or
                              None, paged_cookie=page_cookie or None)
        except LDAPOperationResult as e:
            self.request.errors.add('User.collection_get:search', 'ESEARCH',
                                    e.description, status=500)
            return {}

        if not res:
            return {}

        ret_values = []
        for resp in conn.response:
            d = dict(resp.pop('attributes', {}))
            # log.debug("d -> %r", d)
            d.update(get_virtual_attributes(conn, self.request, resp['dn'],
                                            v_attrs))
            serialize_custom_attributes(d)
            ret_values.append(d)

        log.debug("conn.result -> %r", conn.result)

        ret_pagecookie = b''

        # Not working if nonpersistent manager connection is used
        # (USE_MANAGER=True)

        try:
            ret_pagecookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        except KeyError:
            pass

        ret = {'results': ret_values,
               'page_cookie': binascii.hexlify(ret_pagecookie)}

        log.debug("conn.result -> %r", conn.result)

        return ret


    # TODO: validators and token
    @view(error_handler=json_error_handler, validators=(valid_token))
    def collection_post(self):
        """
        Create a new user in specified `path` with objectClass defined in
        `ldap_userclass` (**ldapcommon.py**).

        Unique DN is created from initials given in `cn` attribute in an
        auto-increment fashion, **path** is
        concatenated to the DN, i.e, when `cn` is ``Jonas Jonaitis`` and
        ``jonjon`` is unique initials and `path`
        is ``ou=Users,ou=People`` then resulting DN is
        ``uid=jonjon1,ou=Users,ou=People``.

        Generated `uid` is also returned with the response.

        Attributes and their values are specified in request body.

        Controller makes sure that any attributes requiring special treatment
        (such as `password` which may require special LDAP extended password
        modification operation -
        `RFC3062 <http://www.ietf.org/rfc/rfc3062.txt>`_)
        are handled correctly.  This is implemented either by using
        VIRTUAL_ATTRIBUTES and/or ATTRIBUTE_SERIALIZERS
        (see `user.py` source code).

        **Request body:**

        ``{ 'path' : 'path_to_user',
        'attributes': {
        'attribute1' : ['value1', .. ], 'attribute2' : ['value2', .. ], }
        }``

        **Response body:**

        ``{ 'uid': uid }`` or :ref:`errors`

        **Errors:**
            ``EPARAMS, ESEARCH, EADD, EAUTH``
        """

        tok = self.request.validated['token']

        if not USE_MANAGER:
            conn = CONNECTIONS[tok]['connection']
        else:
            conn = ManagerConnection()
            conn.tls_bind()

        try:
            jb = self.request.json_body
        except ValueError:
            self.request.errors.add('User.collection_post', 'EPARAMS',
                                    'ValueError while parsing JSON body')
            return {}

        if 'attributes' in jb and type(jb['attributes']) is dict:
            attrs = jb['attributes']
        else:
            self.request.errors.add('User.collection_post', 'EPARAMS',
                                    'error parsing attributes')
            return {}

        # Partition attribute dictionary
        ldap_add, v_attrs = {}, {}
        for attr, val in attrs.items():
            if attr in VIRTUAL_ATTRIBUTES and 'set' in VIRTUAL_ATTRIBUTES[attr]:
                v_attrs[attr] = val
            else:
                ldap_add[attr] = val

        try:
            uid = get_unique_uid(conn, attrs[ldap_commonname][0])
        except (KeyError, IndexError) as e:
            self.request.errors.add('user.collection_post', 'EPARAMS',
                                    '{} while parsing common name parameter'.
                                    format(type(e).__name__))
            return {}
        except LDAPOperationResult as e:
            self.request.errors.add('User.collection_post:search', 'ESEARCH',
                                    e.description, status=500)
            return {}
        except Exception as e:
            self.request.errors.add('User.collection_post:genuid', 'EPARAMS',
                                    str(e), status=500)
            return {}

        dn = ldap_format('uid=%s,%s', [uid, ldap_usersdn])

        ldap_add['uid'] = [uid]

        # Set virtual attributes first

        # Create DN, set attributes
        if ldap_add:
            serialize_custom_attributes(ldap_add)
            try:
                log.debug("ldap_add -> %r dn -> %r", ldap_add, dn)
                conn.add(dn, ldap_userclass, ldap_add)
            except LDAPOperationResult as e:
                self.request.errors.add('User.collection_post:modify', 'EADD',
                                        e.description, status=403)
                return {}

            # Set virtual attributes
            set_virtual_attributes(conn, self.request, dn, v_attrs)

        groupid = None

        # XXX: required
        orgjak = re.search("lmOrgJAK=(.*),ou=Orgs",
                           ldap_add['lmPersonOrgDN'][0]).group(1)

        if ldap_add['affiliation'][0] == 'employee':
            groupid = 'bazinis_{}'.format(orgjak)
        elif 'ou' in ldap_add:
            groupid = '{}_{}'.format(groupify(ou), orgjak)

        if groupid:
            try:
                conn.modify(ldap_format(ldap_usergrpsdn_template, [groupid]),
                            {'memberUid': [MODIFY_ADD, uid]})
            except LDAPOperationResult as e:
                log.error("exception -> %e", e)

        return {'uid': uid}
