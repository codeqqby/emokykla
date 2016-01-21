"""
Organization management subsystem resources (/orgs/...).
"""

import binascii
import logging
log = logging.getLogger(__name__)

import string
import random

from dateutil.parser import parse as dateparse
from datetime import date

import xml.etree.ElementTree as ET

from cornice.resource import resource, view

from ldap3 import SEARCH_SCOPE_WHOLE_SUBTREE, MODIFY_REPLACE, MODIFY_ADD,\
    MODIFY_DELETE
from ldap3.core.exceptions import LDAPOperationResult

from ldap.filter import filter_format as ldap_format, escape_filter_chars

from .ldapcommon import CONNECTIONS, ldap_orgdn, ldap_all_filter, ldap_orgsdn,\
    ldap_orgid, ldap_dummyadmin_dn, ldap_org_obj_filter, ldap_orgadminsdn,\
    ldap_usersdn, ldap_users_import_filter, ManagerConnection,\
    get_unique_uid, ldap_userclass, ldap_orgsub_search_filter,\
    ldap_orgsub_labeleduri, ldap_orgsubclass, ldap_usergrpsdn_template,\
    USE_MANAGER, groupify
from .authcommon import valid_token
from .errors import json_error_handler

org_desc = """
Provides RESTful resources for managing organization attributes.
"""

collection_org_desc = """
Allows to search/filter through the collection of organizations.
"""


@resource(collection_path='/orgs', path='/orgs/{org}*attr', cors_origins=('*',),
          description=org_desc, collection_description=collection_org_desc)
class Organization(object):

    def __init__(self, request):
        self.request = request

    @view(error_handler=json_error_handler, validators=valid_token)
    def get(self):
        """
        Returns requested attributes for given `orgid` (lmOrgJAK) together with
        its subgroups.

        Attributes are specified in the **request URL** such as
        `/orgs/<orgid>/attribute1/attribute2/attribute3`.

        By default all DNs and `lmOrgJAK` attribute is returned.

        **Request body:**

        ``{}``

        **Response body:**

        ``{ 'orgid': lmOrgJAK, 'dn': dn, attributes .. 'groups':
        [ { 'dn': dn, attributes .. }, .. ] }``
        or :ref:`errors`

        **Errors:**
        ``ESEARCH, ENOTFOUND, EAUTH``
        """

        log.debug("matchdict -> %r, params -> %r",
                  self.request.matchdict, self.request.params)

        tok = self.request.validated['token']

        if not USE_MANAGER:
            conn = CONNECTIONS[tok]['connection']
        else:
            conn = ManagerConnection()
            conn.tls_bind()

        orgid = self.request.matchdict['org']

        ldap_attrs = list(self.request.matchdict['attr']) + [ldap_orgid]

        try:
            res = conn.search(ldap_format(ldap_orgdn, [orgid]), ldap_all_filter,
                              SEARCH_SCOPE_WHOLE_SUBTREE, attributes=ldap_attrs)
        except LDAPOperationResult as e:
            self.request.errors.add('Organization.get:search', 'ESEARCH',
                                    e.description, status=500)
            return {}

        if not res:
            self.request.errors.add('Organization.get:search', 'ENOTFOUND',
                                    'organization not found', status=400)
            return {}

        log.debug("connection.response -> %r", conn.response)

        ret = {'groups': []}
        for resp in conn.response:
            if ldap_orgid in resp['attributes']:  # organization
                ret['dn'] = resp['dn']
                ret.update(resp['attributes'])
            else:
                group = {'dn': resp['dn']}
                group.update(resp['attributes'])
                try:  # remove dummy admin
                    group["member"].remove(ldap_dummyadmin_dn)
                except (KeyError, ValueError):
                    pass
                ret['groups'].append(group)

        return ret

    @view(error_handler=json_error_handler, validators=valid_token)
    def collection_get(self):
        """
        Searches for organizations matching filters attributes.

        Filters are specified in the **request URL** such as
        ``/orgs/attribute1=value1&attribute2=value2``.

        Paging (limiting results) is supported through OPTIONAL `page_size` and
        `page_cookie` URL parameters.

        By default a list of JSON objects containing only `lmOrgJAK` and `dn`
        attributes is returned, additional attributes can be returned by passing
        `attributes` URL parameter, example:
        ``/orgs/attribute1=value1&attributes=lmOrgSync,lmOrgJAK``.

        More examples:

        1) Attributes of organizations not synchronized with the registry:
            ``/orgs?attributes=o,lmOrgSync&lmOrgSync=FALSE``
        2) Organizations starting with "Kauno":
            ``/orgs?o=Kauno*&attributes=o``

        **Request body:**

        ``{}``

        **Response body:**

        ``{ 'results': [ { 'orgid': lmOrgJAK, attributes .. }, .. ],
        'page_cookie': page_cookie }`` or :ref:`errors`

        **Errors:**
        ``ESEARCH, ENOTFOUND, EAUTH``
        """

        ldap_filt = ldap_org_obj_filter
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

        ldap_attrs = reqpar.pop('attributes', '').split(',') if 'attributes' \
            in reqpar else []
        ldap_attrs.append(ldap_orgid)

        log.debug("ldap_attrs -> %r", ldap_attrs)

        # build a filter from the rest of URL
        for k, v in reqpar.items():
            val = escape_filter_chars(v)
            val = val.replace(r'\2a', r'*')
            ldap_filt += '({}={})'.format(escape_filter_chars(k), val)
        ldap_filt += ')'

        try:
            log.debug("ldap_filt -> %r,\
                      page_size -> %r, page_cookie -> %r",
                      ldap_filt, page_size, page_cookie)
            res = conn.search(ldap_orgsdn, ldap_filt,
                              SEARCH_SCOPE_WHOLE_SUBTREE,
                              attributes=ldap_attrs, paged_size=page_size \
                              or None, paged_cookie=page_cookie or None)
        except LDAPOperationResult as e:
            self.request.errors.add('Organization.collection_get:search',
                                    'ESEARCH', e.description, status=500)
            return {}

        if not res:
            return {}

        ret_values = []
        for resp in conn.response:
            d = dict(resp.pop('attributes', {}))
            d['dn'] = resp['dn']
            ret_values.append(d)

        log.debug("connection.result -> %r", conn.result)

        ret_pagecookie = b''

        # Not working if nonpersistent manager connection is used
        # (USE_MANAGER=True)

        try:
            ret_pagecookie = conn.result['controls']['1.2.840.113556.1.4.319']\
                ['value']['cookie']
        except KeyError:
            pass

        ret = {'results': ret_values, 'page_cookie': \
               binascii.hexlify(ret_pagecookie)}

        log.debug("conn.result -> %r", conn.result)

        return ret

    @view(error_handler=json_error_handler, validators=valid_token)
    def put(self):
        """
        Updates selected organization attributes.

        Attributes and their values are specified in request body.

        Special attribute `subtree` specifies the subtree for updating
        attributes.
        If it's not provided or empty the attributes of root organization entry
        are updated.

        Special attribute `op` specifies the operation for updating attributes,
        supported values are:

        **"add"**, **"delete"**, **"replace"** (the default).

        **Request body:**

        ``{ 'attribute1' : ['value1', .. ], 'attribute2' : [ 'value2', .. ],
        .. }``

        **Response body:**

        ``{}`` or :ref:`errors`

        **Errors:**
        ``EPARAMS, EMODIFY, EAUTH``
        """

        orgid = self.request.matchdict['org']
        tok = self.request.validated['token']

        if not USE_MANAGER:
            conn = CONNECTIONS[tok]['connection']
        else:
            conn = ManagerConnection()
            conn.tls_bind()

        try:
            jb = self.request.json_body
        except ValueError:
            self.request.errors.add('Organization.put', 'EPARAMS',
                                    'ValueError while parsing JSON body')
            return {}

        subtr = ""
        if 'subtree' in jb and jb['subtree']:
            subtr = escape_filter_chars(jb['subtree']) + ","
            del jb['subtree']

        op = MODIFY_REPLACE
        if 'op' in jb:
            if jb['op'] == "add":
                op = MODIFY_ADD
            elif jb['op'] == "delete":
                op = MODIFY_DELETE
            del jb['op']

        # Partition attribute dictionary
        ldap_mod = {attr: [op, val] for attr, val in jb.items()}
        mdn = subtr+ldap_format(ldap_orgdn, [orgid])
        log.debug("ldap_mod -> %r mdn -> %r", ldap_mod, mdn)

        if ldap_mod:
            try:
                conn.modify(mdn, ldap_mod)
            except LDAPOperationResult as e:
                self.request.errors.add('Organization.put:modify', 'EMODIFY',
                                        e.description, status=403)
                return {}

        return {'output': 'OK'}

    @view(error_handler=json_error_handler, renderer="text",
          validators=valid_token)
    def post(self):
        """
        Imports user data from uploaded XML file.

        **Request body:**

        ``{ 'employee' : 'false' }``

        **Response body:**

        ``{}`` or :ref:`errors`

        Expects file upload of name="file" and Content-Type: text/xml.

        **Errors:**
        ``ECOMPARE, ESEARCH, EACCESS, EAUTH, EPARAMS, XPARSEXML, EXMLFMT``
        """

        tok = self.request.validated['token']
        orgid = self.request.matchdict['org']

        conn = CONNECTIONS[tok]['connection']

        # Check if user belongs to particular organization's admins group
        try:
            res = conn.compare(ldap_format(ldap_orgadminsdn, [orgid]),
                               "member", CONNECTIONS[tok]['userdn'])
            log.debug("LDAP compare res -> %r", res)
        except LDAPOperationResult as e:
            self.request.errors.add('Organization.post:attrsearch', 'ECOMPARE',
                                    e.description, status=500)
            return {}

        if not res:
            self.request.errors.add('Organization.post:search',
                                    'EACCESS',
                                    "uid is not a member of organization's \
                                    cn=admins subgroup", status=500)
            return {}

        if "sync" not in self.request.matchdict['attr']:
            self.request.errors.add('Organization.post', 'EPARAMS',
                                    "missing sync param")
            return {}


        if 'file' not in self.request.POST:
            self.request.errors.add('Organization.post', 'EPARAMS',
                                    "missing file param")
            return {}

        # Employee or student ?
        if 'employee' not in self.request.POST:
            self.request.errors.add('Organization.post', 'EPARAMS',
                                    "missing employee param")
            return {}

        input_file = self.request.POST['file'].file

        imp_func = self.import_employees if self.request.POST['employee'] \
            == "employee" else self.import_students

        try:
            ret = imp_func(conn, orgid, input_file)
        except ET.ParseError as pe:
            self.request.errors.add('Organization.post:XML', 'EPARSEXML',
                                    "{}, pos: {}".format(repr(pe),
                                                         pe.position))
            return {}

        return ret

    def import_students(self, conn, orgid, input_file):

        root = ET.parse(input_file).getroot()

        # APRASYMAS, INSTITUCIJA ...
        for org in root:

            log.debug("org.tag -> %s", org.tag)

            if org.tag != "INSTITUCIJA":
                log.debug("org.tag != INSTITUCIJA")
                continue # skip metadata tags (APRASYMAS etc.)

            if "INSTITUCIJOS_KODAS" not in org.attrib:
                self.request.errors.add('Organization.import_students:XML',
                        'EXMLFMT', 'missing attribute: INSTITUCIJOS_KODAS')
                return {}

            if "PAVADINIMAS" not in org.attrib:
                self.request.errors.add('Organization.import_students:XML',
                        'EXMLFMT', 'missing attribute: PAVADINIMAS')
                return {}

            orgname = ldap_format("%s", [org.attrib['PAVADINIMAS']])

            if org.attrib["INSTITUCIJOS_KODAS"] != orgid:
                self.request.errors.add('Organization.import_students:XML',
                                        'EACCESS',
                                        "INSTITUCIJOS_KODAS != orgid")
                return {} # fail if user is not admin of this org

            # KLASE ...
            for cls in org:

                if cls.tag != "KLASE":
                    log.error("cls.tag != KLASE")
                    continue

                if "PAVADINIMAS" not in cls.attrib:
                    self.request.errors.add('Organization.\
                                            import_students:XML',
                                            'EXMLFMT',
                                            "missing attribute: PAVADINIMAS")
                    return {}

                log.debug("cls -> %r", cls.attrib)

                # Create dynamic group for class if doesn't exist
                ldap_filt = ldap_format(ldap_orgsub_search_filter,
                                        [cls.attrib['PAVADINIMAS']])
                ldap_suborgdn = ldap_format("cn=%s,",
                                            [cls.attrib['PAVADINIMAS']])
                ldap_suborgdn += ldap_format(ldap_orgdn, [orgid])

                log.debug("orgsub_search_filt -> %r", ldap_filt)
                try:
                    res = conn.search(ldap_format(ldap_orgdn, [orgid]),
                                      ldap_filt,
                                      SEARCH_SCOPE_WHOLE_SUBTREE)
                except LDAPOperationResult as e:
                    self.request.errors.add('Organization.\
                                            import_students:orgsearch',
                                            'ESEARCH',
                                            e.description, status=500)
                    return {}

                if not res:
                    try:
                        lbluri = ldap_format(ldap_orgsub_labeleduri,
                                             [orgid, cls.attrib['PAVADINIMAS']])
                        log.debug("ldap_orgdn -> %s, lbluri -> %s",
                                  ldap_orgdn, lbluri)
                        conn.add(ldap_suborgdn, ldap_orgsubclass,
                                 {'labeledURI': lbluri})
                    except LDAPOperationResult as e:
                        self.request.errors.add('Organization.\
                                                import_students:orgadd',
                                                'EADD', e.description,
                                                status=403)
                        return {}

                for usr in cls:

                    if usr.tag != "MOKINYS":
                        log.error("cls.tag != KLASE")
                        continue

                    req_attrs = ("ASM_ID", "VARDAS", "PAVARDE",
                                 "GIMIMO_DATA")
                    for rattr in req_attrs:
                        if rattr not in usr.attrib:
                            self.request.error.add('Organization.\
                                                   import_students:XML',
                                                   'EXMLFMT',
                                                   'missing attribute: {}'\
                                                   .format(rattr))
                            return {}

                    # XXX: format of personId:
                    # 10<ASM_ID> - students
                    # 20<ASM_ID> - employees
                    personid = ldap_format("10%s", [usr.attrib["ASM_ID"]])

                    # Search for the user by personId
                    try:
                        res = conn.search(ldap_usersdn,
                                          ldap_format(
                                              ldap_users_import_filter,
                                              [personid]),
                                          SEARCH_SCOPE_WHOLE_SUBTREE,
                                          attributes=['uid'])
                    except LDAPOperationResult as e:
                        self.request.errors.add('Organization.import_students:\
                                                search', 'ESEARCH',
                                                e.description,
                                                status=500)
                        return {}

                    bday = dateparse(usr.attrib['GIMIMO_DATA'])
                    sn = usr.attrib["PAVARDE"]
                    ou = cls.attrib['PAVADINIMAS']
                    displayname = cn = "{} {}".format(
                        usr.attrib["VARDAS"], usr.attrib["PAVARDE"])
                    givenname = usr.attrib["VARDAS"]
                    birthdate = bday.strftime("%Y-%m-%d")

                    groupid = groupify(ou)

                    lmpersonauthcode = ''.join(random.choice(
                        string.ascii_uppercase+string.digits) for _ in \
                                               range(10))
                    uid = ''

                    # User not found
                    if not res:
                        # cn, sn, displayName, givenName, personId,
                        # birthDate, eduPersonAffiliation,
                        # eduPersonEntitlement, lmPersonActive
                        # lmPersonAuthCode, ou, o

                        ldap_add = {}
                        ldap_add['personId'] = [personid]
                        ldap_add['eduPersonAffiliation'] = ['student']
                        ldap_add['sn'] = [sn]
                        ldap_add['ou'] = [ou]
                        ldap_add['o'] = orgname
                        ldap_add['displayName'] = [displayname]
                        ldap_add['givenName'] = [givenname]
                        ldap_add['cn'] = [cn]
                        ldap_add['birthDate'] = [birthdate]
                        ldap_add['lmPersonActive'] = ['FALSE']
                        ldap_add['lmPersonAuthCode'] = [lmpersonauthcode]
                        #ldap_add['lmOrgJAK'] = [orgid]
                        ldap_add['lmPersonOrgDN'] = [ldap_orgdn % orgid]
                        ldap_add['eduPersonEntitlement'] = \
                            ["urn:mace:terena:org:role:{}:user"\
                             .format(orgid)]

                        try:
                            uid = get_unique_uid(conn, ldap_add['cn'][0])
                        except (KeyError, IndexError) as e:
                            self.request.errors.add('Organization.\
                                                    import_students:\
                                                    get_unique_id',
                                                    'EPARAMS',
                                                    '{} while parsing \
                                                    common name parameter'.
                                                    format(type(e).__name__))
                            return {}
                        except LDAPOperationResult as e:
                            self.request.errors.add('Organization.\
                                                    import_students:\
                                                    get_unique_id',
                                                    'ESEARCH',
                                                    e.description, status=500)
                            return {}
                        except Exception as e: # XXX: type ?
                            self.request.errors.add('Organization.\
                                                    import_students:\
                                                    get_unique_id',
                                                    'EPARAMS',
                                                    e.message, status=500)
                            return {}

                        dn = ldap_format('uid=%s,%s', [uid, ldap_usersdn])

                        try:
                            log.debug("ldap_add -> %r dn -> %r", ldap_add, dn)
                            conn.add(dn, ldap_userclass, ldap_add)
                        except LDAPOperationResult as e:
                            self.request.errors.add('Organization.\
                                                    import_students:add',
                                                    'EADD', e.description,
                                                    status=403)
                            return {}

                    # User found
                    else:
                        dn = conn.response[0]['dn']
                        uid = conn.response[0]['attributes']['uid']
                        log.debug("modifying existing DN -> %s", dn)

                        ldap_attrs = {}
                        ldap_attrs['ou'] = [MODIFY_REPLACE, [ou]]
                        ldap_attrs['o'] = [MODIFY_REPLACE, [orgname]]
                        ldap_attrs['displayName'] = [MODIFY_REPLACE,
                                                     [displayname]]
                        ldap_attrs['givenName'] = [MODIFY_REPLACE,
                                                   [givenname]]
                        ldap_attrs['cn'] = [MODIFY_REPLACE, [cn]]
                        #ldap_attrs['lmOrgJAK'] = [MODIFY_REPLACE, [orgid]]
                        ldap_attrs['lmPersonOrgDN'] = [MODIFY_REPLACE,
                                                     [ldap_orgdn % orgid]]
                        ldap_attrs['eduPersonEntitlement'] = [MODIFY_REPLACE,
                                                            ["urn:mace:terena:org:role:{}:user"\
                                                      .format(orgid)]]
                        # Modify existing DN
                        try:
                            conn.modify(dn, ldap_attrs)
                        except LDAPOperationResult as e:
                            log.error("exception -> %e", e)

                    # XXX: add to the filtering group
                    try:
                        conn.modify(ldap_format(ldap_usergrpsdn_template,
                                                ['{}_{}'.format(groupid, orgid)]),
                                    {'memberUid': [MODIFY_ADD, uid]})
                    except LDAPOperationResult as e:
                        log.error("exception -> %e", e)


        return {'output': 'OK'}

    def import_employees(self, conn, orgid, input_file):

        root = ET.parse(input_file).getroot()

        # PEDAGOGAS
        for usr in root:

            log.debug("usr.tag -> %s", usr.tag)

            if usr.tag != "Pedagogas":
                log.error("usr.tag != Pedagogas")
                continue

            # ASMUO
            for idnt in usr:

                if idnt.tag != "Asmuo":
                    log.error("idnt.tag != KLASE")
                    continue

                req_attrs = ("ASM_ID", "VARDAS", "PAVARDE")
                if not all(k in idnt.attrib for k in req_attrs):
                    log.error("missing attributes: %r", req_attrs)
                    continue

                for org in idnt:

                    if org.tag != "Institucija":
                        log.error("org.tag != Institucija")
                        continue

                    req_attrs = ("INST_NUMER", "INSTITUCIJA_PAVADINIMAS")
                    if not all(k in org.attrib for k in req_attrs):
                        log.error("missing attributes: %r", req_attrs)
                        continue

                    orgname = ldap_format("%s", [org.attrib\
                                                 ['INSTITUCIJA_PAVADINIMAS']])

                    # XXX: format of personId:
                    # 10<ASM_ID> - students
                    # 20<ASM_ID> - employees
                    personid = ldap_format("20%s", [idnt.attrib["ASM_ID"]])

                    # Search for the user by personId
                    try:
                        res = conn.search(ldap_usersdn,
                                          ldap_format(
                                              ldap_users_import_filter,
                                              [personid]),
                                          SEARCH_SCOPE_WHOLE_SUBTREE)
                    except LDAPOperationResult as e:
                        self.request.errors.add('Organization.import_employees:\
                                                search', 'ESEARCH',
                                                e.description, status=500)
                        return {}

                    sn = idnt.attrib["PAVARDE"]
                    displayname = cn = "{} {}".format(
                        idnt.attrib["VARDAS"], idnt.attrib["PAVARDE"])
                    givenname = idnt.attrib["VARDAS"]
                    lmpersonauthcode = ''.join(random.choice(
                        string.ascii_uppercase+string.digits) for _ in \
                                               range(10))

                    # User not found
                    if not res:
                        # cn, sn, displayName, givenName, personId,
                        # birthDate, eduPersonAffiliation,
                        # eduPersonEntitlement, lmPersonActive
                        # lmPersonAuthCode, ou

                        ldap_add = {}
                        ldap_add['personId'] = [personid]
                        ldap_add['eduPersonAffiliation'] = ['employee']
                        ldap_add['sn'] = [sn]
                        ldap_add['displayName'] = [displayname]
                        ldap_add['givenName'] = [givenname]
                        ldap_add['cn'] = [cn]
                        ldap_add['o'] = [orgname]
                        ldap_add['lmPersonActive'] = ['FALSE']
                        ldap_add['lmPersonAuthCode'] = [lmpersonauthcode]
                        ldap_add['lmPersonOrgDN'] = [ldap_orgdn % orgid]
                        ldap_add['eduPersonEntitlement'] = \
                            ["urn:mace:terena:org:role:{}:user"\
                             .format(orgid)]

                        try:
                            uid = get_unique_uid(conn, ldap_add['cn'][0])
                        except (KeyError, IndexError) as e:
                            self.request.errors.add('Organization.\
                                                    import_employees:\
                                                    get_unique_id', 'EPARAMS',
                                                    '{} while parsing \
                                                    common name parameter'.
                                                    format(type(e).__name__))
                            return {}
                        except LDAPOperationResult as e:
                            self.request.errors.add('Organization.:\
                                                    import_employees:\
                                                    get_unique_id', 'ESEARCH',
                                                    e.description, status=500)
                            return {}
                        except Exception as e: # XXX: type ?
                            self.request.errors.add('Organization.\
                                                    import_employees:\
                                                    get_unique_id', 'EPARAMS',
                                                    e.message, status=500)
                            return {}

                        dn = ldap_format('uid=%s,%s', [uid, ldap_usersdn])

                        try:
                            log.debug("ldap_add -> %r dn -> %r", ldap_add, dn)
                            conn.add(dn, ldap_userclass, ldap_add)
                        except LDAPOperationResult as e:
                            self.request.errors.add('Organization.\
                                                    import_employees:add',
                                                    'EADD', e.description,
                                                    status=403)
                            return {}

                    # User found
                    else:
                        dn = conn.response[0]['dn']
                        log.debug("modifying existing DN -> %s", dn)

                        ldap_attrs = {}
                        ldap_attrs['displayName'] = [MODIFY_REPLACE,
                                                     [displayname]]
                        ldap_attrs['givenName'] = [MODIFY_REPLACE,
                                                   [givenname]]
                        ldap_attrs['cn'] = [MODIFY_REPLACE, [cn]]
                        ldap_attrs['o'] = [MODIFY_REPLACE, [orgname]]
                        ldap_attrs['lmPersonOrgDN'] = [MODIFY_REPLACE,
                                                     [ldap_orgdn % orgid]]
                        ldap_attrs['eduPersonEntitlement'] = [MODIFY_REPLACE,
                                                            ["urn:mace:terena:org:role:{}:user"\
                                                      .format(orgid)]]

                        # Modify existing DN
                        try:
                            conn.modify(dn, ldap_attrs)
                        except LDAPOperationResult as e:
                            log.error("attr_passmod: exception -> %e", e)

                    # XXX: add employees to the group as well
                    try:
                        conn.modify(ldap_format(ldap_usergrpsdn_template,
                                                ['bazinis_{}'.format(orgid)]),
                                    {'memberUid': [MODIFY_ADD, uid]})
                    except LDAPOperationResult as e:
                        log.error("exception -> %e", e)


        return {'output': 'OK'}
