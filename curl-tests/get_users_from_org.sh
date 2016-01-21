#!/bin/bash

curl -H "X-Messaging-Token: $1" "http://127.0.0.1:6544/users?lmPersonOrgDN=lmOrgJAK=$2,ou=Orgs,dc=lm,dc=lt"

echo
