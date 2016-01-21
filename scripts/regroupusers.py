import re
import sys

from emokykla.ldapcommon import ManagerConnection, ldap_usersdn,\
    ldap_all_filter, ldap_usergrpsdn_template, groupify

from ldap.filter import filter_format as ldap_format, escape_filter_chars

from ldap3 import SEARCH_SCOPE_WHOLE_SUBTREE, MODIFY_ADD
from ldap3.core.exceptions import LDAPNoSuchObjectResult, LDAPAttributeOrValueExistsResult

all_students_filt = "(objectClass=lmPerson)"

def main():

    # Retrieve all users
    manager_connection = ManagerConnection()
    manager_connection.tls_bind()
    manager_connection.search(ldap_usersdn, all_students_filt,
                              SEARCH_SCOPE_WHOLE_SUBTREE,
                              attributes=['ou', 'uid', 'eduPersonAffiliation',
                                          'eduPersonEntitlement',
                                          'lmPersonOrgDN'])

    for entry in manager_connection.response:
        uid = entry['attributes']['uid'][0]

        # XXX: skip 'dummy'
        if uid == 'dummy':
            continue

        if 'lmPersonOrgDN' not in entry['attributes']:
            continue

        orgjak = re.search("lmOrgJAK=(.*),ou=Orgs",
                           entry['attributes']['lmPersonOrgDN'][0]).group(1)
        
        affiliation = entry['attributes']['eduPersonAffiliation'][0] \
            if 'eduPersonAffiliation' in entry['attributes'] else 'NONE'

        ou = entry['attributes']['ou'][0] if 'ou' in entry['attributes'] \
            else 'NONE'

        entitlement = entry['attributes']['eduPersonEntitlement'][0] \
            if 'eduPersonEntitlement' in entry['attributes'] else 'NONE'

        if affiliation == 'student':
            groupid = '{}_{}'.format(groupify(ou), orgjak)
        elif affiliation == 'employee':
            #if re.match(r"^urn:mace:terena.org:role:\d.*:admin$", entitlement):
            groupid = 'bazinis_{}'.format(orgjak)
            

        print("uid={}, ou={}, affiliation={}, group={}"\
              .format(uid, ou, affiliation, groupid))

        try:
            manager_connection.modify(ldap_format(ldap_usergrpsdn_template,
                                                  [groupid]),
                        {'memberUid': [MODIFY_ADD, uid]})
        except LDAPNoSuchObjectResult:
            print("LDAPNoSuchObjectResult: (uid={}, ou={}, affiliation={}, group={})"\
                  .format(uid, ou, affiliation, groupid), file=sys.stderr)
            break

        except LDAPAttributeOrValueExistsResult:
            continue


if __name__ == "__main__":
        main()
