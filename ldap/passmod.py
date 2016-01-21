"""
Password extended modify operation implementation
for python3-ldap, see RFC-3062.
"""


from ldap3 import RESULT_SUCCESS
from ldap3.protocol.rfc4511 import RequestName, Simple
from pyasn1.type.univ import Sequence
from pyasn1.type.namedtype import NamedType, OptionalNamedType, NamedTypes
from pyasn1.codec.ber import encoder
from pyasn1.type import tag


# Redefine request types with correct tagId values
class PasswdModifyRequestValue(Sequence):
    """
    PasswdModifyRequestValue ::= SEQUENCE {
        userIdentity [0] OCTET STRING OPTIONAL
        oldPasswd [1] OCTET STRING OPTIONAL
        newPasswd [2] OCTET STRING OPTIONAL }
    """
    componentType = NamedTypes(OptionalNamedType('userIdentity', Simple()),
                               OptionalNamedType('oldPasswd', Simple(tagSet=tag.initTagSet(tag.Tag(tagClass=128, tagFormat=0, tagId=1)))),
                               OptionalNamedType('newPasswd', Simple(tagSet=tag.initTagSet(tag.Tag(tagClass=128, tagFormat=0, tagId=2)))))


class ExtendedPasswdRequest(Sequence):
    """
    ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
        requestName      [0] LDAPOID,
        requestValue     [1] OCTET STRING OPTIONAL }
    """
    tagSet = Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 23))
    componentType = NamedTypes(NamedType('requestName', RequestName()),
                               OptionalNamedType('requestValue', Simple(tagSet=tag.initTagSet(tag.Tag(tagClass=128, tagFormat=0, tagId=1)))))


def passmod(conn, uid=None, newpassw=None, oldpassw=None, controls=None):
    """
    Performs password modify extended operation (RFC3062).
    """
    conn._fire_deferred()
    request = ExtendedPasswdRequest()
    request.setComponentByName('requestName', '1.3.6.1.4.1.4203.1.11.1')
    reqvalue = PasswdModifyRequestValue()
    reqvalue.setComponentByName('userIdentity', uid)
    reqvalue.setComponentByName('newPasswd', newpassw)
    if oldpassw:
        reqvalue.setComponentByName('oldPasswd', oldpassw)
    request.setComponentByName('requestValue', encoder.encode(reqvalue))
    response = conn.post_send_single_response(conn.send('extendedReq', request, controls))
    if isinstance(response, int):
            return response
    return True if conn.result['type'] == 'extendedResp' and conn.result['result'] == RESULT_SUCCESS else False

# resp = passwordmodifyrequest(ldap_connection, 'uid=jj00001,ou=Users,dc=lm,dc=lt', 'labas', 'labaz')
