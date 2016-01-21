.. E-mokykla documentation master file, created by
   sphinx-quickstart on Sun Jun  8 21:03:23 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

=====================================
Welcome to E-mokykla's documentation!
=====================================

E-mokykla service provides authenticated REST methods (resources) for managing lm LDAP directory data (educational institutions and their respective users). Resources are extendable, customizable and easily adaptable to schema changes. 

For configuration options see files ``ldapcommon.py`` and ``settings.py`` in the main directory.

.. note::
        All of this is in early development stage.

Installation
==============

From virtualenv::

        python setup.py develop

.. cornice-autodoc::
   :modules: emokykla.auth, emokykla.user, emokykla.organization
   :services: login, logout, register, user, collection_user, organization, collection_organization

.. _errors:

Error Messages
==============

List of JSON error objects is returned, eg::

        [
            {
                "description": "invalidCredentials: ...",
                "name": "EBIND",
                "location": "SomeModule.function:codeblock"
            }
        ]

**ENOTFOUND**

   Specified ``uid`` and ``password`` or ``authcode`` not found.

**EPARAMS**

   Error parsing parameters.

**EBIND**

   LDAP bind error (authentication failure).
 
**ESEARCH**

   LDAP search operation error.

**ECOMPARE**

   LDAP compare operation error.

**EMODIFY**

   LDAP MODIFY operation failure (TODO: return ``description`` regarding password policy).

**EDELETE**

   LDAP DELETE operation error.

**EAUTH**

   Unauthenticated.

**EMAILSYNTAX**

   Email syntax invalid.

**EALREADYACTIVE**

   Registration of active user.

**EACCESS**

   Permission denied.

**EPARSEXML**

   XML parser error.

**EXMLFMT**

   XML format error (missing required attributes).

Other
==================

* :ref:`search`

