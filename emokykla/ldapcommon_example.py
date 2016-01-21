"""
LDAP Manager connection and other common parameters.
"""

import ssl
import re

from ldap3 import Server, Connection, Tls, STRATEGY_SYNC,\
    SEARCH_SCOPE_WHOLE_SUBTREE
from ldap.filter import filter_format as ldap_format

from ldap.passmod import passmod
import logging
log = logging.getLogger(__name__)

# Show error descriptions and locations (in code)
DEBUG = True

ldap_tls = Tls(validate=ssl.CERT_NONE)
ldap_server = Server('ldap.lm.lt', port=389, use_ssl=False, tls=ldap_tls)

# Manager
ldap_manager_user = 'cn=lm,ou=Apps,dc=lm,dc=lt'
ldap_manager_password = ''

# Schema parameters

# DNs
ldap_dn = 'dc=lm,dc=lt'
ldap_usersdn = 'ou=Users,ou=People,dc=lm,dc=lt'
ldap_orgsdn = 'ou=Orgs,dc=lm,dc=lt'
ldap_orgdn = """lmOrgJAK=%s,ou=Orgs,dc=lm,dc=lt"""
ldap_orgadminsdn = """cn=admins,lmOrgJAK=%s,ou=Orgs,dc=lm,dc=lt"""
ldap_usergrpsdn = "ou=groups," + ldap_usersdn

# Dummy admin user to ignore in cn=admins groups (empty groups can't exist)
ldap_dummyadmin_dn = 'cn=dummy,dc=lm,dc=lt'

# Attributes
ldap_orgid = 'lmOrgJAK'
ldap_commonname = 'cn'

# classes
ldap_userclass = ['radiusprofile', 'lmPerson', 'eduPerson', 'organizationalPerson',
                  'inetOrgPerson', 'uidObject', 'person', 'top', 'schacContactLocation']
ldap_orgsubclass = ['groupOfURLs', 'labeledURIObject', 'top']

ldap_orgsub_labeleduri = """ldap:///ou=Users,ou=People,dc=lm,dc=lt??one?(&(eduPersonEntitlement=urn:mace:terena:org:role:%s:user)(eduPersonAffiliation=student)(ou=%s))"""

# Filters
ldap_users_attributes_filter = """(&(objectClass=*)(uid=%s))"""
ldap_users_import_filter = """(&(objectClass=*)(personid=%s))"""
ldap_all_filter = """(objectClass=*)"""
ldap_active_user_search_filter = """(&(objectClass=lmPerson)\
    (lmPersonActive=TRUE)(uid=%s))"""
ldap_user_search_filter = """(&(uid=%s)(objectClass=lmPerson))"""
ldap_user_obj_filter = """(&(objectClass=lmPerson)"""
ldap_user_obj_del_filter = """(&(objectClass=lmPerson)(|"""
ldap_org_obj_filter = """(&(objectClass=lmOrg)"""
ldap_orgsub_search_filter = """(&(cn=%s)(objectClass=groupOfURLs))"""
ldap_org_search_template = "(&(objectClass=lmOrg)(|"
ldap_usergrpsdn_template = "cn=%s,ou=groups,ou=Users,ou=People," + ldap_dn
ldap_admin_dn_template = "uid=%s,ou=Admins,ou=People," + ldap_dn
ldap_user_dn_template = "uid=%s,ou=Users,ou=People," + ldap_dn

# Development parameters

USE_MANAGER = False  # use Manager user for all operations

CONNECTIONS = {}

class ManagerConnection(Connection):
    """Wraps manager_connection for error handling and safer cleanup"""

    def __init__(self, auto_bind=False, raise_exceptions=True):
        Connection.__init__(self, ldap_server, user=ldap_manager_user,
                            password=ldap_manager_password,
                            auto_bind=auto_bind, client_strategy=STRATEGY_SYNC,
                            raise_exceptions=raise_exceptions)

    def __del__(self):
        log.debug("bound -> %r", self.bound)
        if self.bound:
            self.unbind()

    def tls_bind(self):
        self.open()
        #self.start_tls()
        self.bind()

    passmod = passmod


def get_unique_uid(conn, cn):
    """Finds unique uid to generate."""

    # XXX: hardcoded logic (three first letters of first name and last name
    # as initials)

    # Translation table (no Lithuanian letters)
    intab = "ąčęėįšųūž"
    outtab = "aceeisuuz"
    trantab = dict(zip([ord(char) for char in intab], outtab))

    # FIXME: KeyError, IndexError
    cname = cn.split()
    sn = cname[-1]
    ini = (cname[0][:3] + sn[:3]).lower()

    ini = ini.translate(trantab)

    # FIXME: LDAPOperationResult
    ldap_filt = ldap_format(ldap_user_search_filter, [ini+"*"])
    ldap_filt = ldap_filt.replace(r'\2a', r'*')
    log.debug("ldap_filt -> %r", ldap_filt)
    res = conn.search(ldap_usersdn, ldap_filt,
                      SEARCH_SCOPE_WHOLE_SUBTREE, attributes=['uid'])

    if not res:
        uid = ini + '1' # start with appended '1'
    else:
        maxnum = max(resp.pop('attributes')['uid'][0][6:] \
                     for resp in conn.response)
        uid = ini + str(int(maxnum) + 1)

    return uid

def groupify(ou):
    """Classify student to filtering group by organization unit"""
    classmatch = re.compile(r"^(\d{1,2})[^\W\d_]*$", re.IGNORECASE)
    classmatchgym = re.compile(r".*gimn.*", re.IGNORECASE)
    classmatchrom = re.compile(r"^(I|II|III|IV).*$")

    groupid = 'pradinis'

    if classmatchgym.match(ou) or classmatchrom.match(ou):
        groupid = 'bazinis'
    else:
        m = classmatch.match(ou)
        if m and int(m.group(1)) >= 5:
            groupid = 'bazinis'

    return groupid

