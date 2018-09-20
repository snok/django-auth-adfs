.. _configuration:

Settings
========

.. _audience_setting:

AUDIENCE
--------
**Required**

Default: ``None``

Set this to the value of the ``aud`` claim your ADFS server sends back in the JWT token.
If you leave this set to ``None`` this claim will not be verified.

You can lookup this value by executing the powershell command ``Get-AdfsRelyingPartyTrust`` on the ADFS server
and taking the ``Identifier`` value. But beware, it doesn't match exactly if it's not a URL.

Examples

+--------------------------------------------------+------------------------------------------------------------+
| Relying Party Trust identifier                   | ``aud`` claim value                                        |
+==================================================+============================================================+
| your-RelyingPartyTrust-identifier                | microsoft:identityserver:your-RelyingPartyTrust-identifier |
+--------------------------------------------------+------------------------------------------------------------+
| https://adfs.yourcompany.com/adfs/services/trust | https://adfs.yourcompany.com/adfs/services/trust           |
+--------------------------------------------------+------------------------------------------------------------+

CA_BUNDLE
---------
Default: ``True``

The value of this setting is passed to the call to the ``Requests`` package when fetching the access token from ADFS.
It allows you to control the webserver certificate verification of the ADFS server.

``True`` to use the default CA bundle of the ``requests`` package.

``/path/to/ca-bundle.pem`` allows you to specify a path to a CA bundle file. If your ADFS server uses a certificate
signed by an enterprise root CA, you will need to specify the path to it's certificate here.

``False`` disables the certificate check.

Have a look at the `Requests documentation
<http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification>`_ for more details.

.. warning::
    Do not set this value to ``False`` in a production setup. Because we load certain settings from the ADFS server,
    this might lead to a security issue. DNS hijacking for example might cause an attacker to inject his own
    access token signing certificate.

.. _boolean_claim_mapping_setting:

BOOLEAN_CLAIM_MAPPING
---------------------
Default: ``None``

A dictionary of claim/field mappings that is used to set boolean fields on the user account in Django.

The **key** represents user model field (e.g. ``first_name``)
and the **value** represents the claim short name (e.g. ``given_name``).

If the value is any of ``y, yes, t, true, on, 1``, the field will be set to ``True``. All other values, or the absence of
the claim, will result in a value of ``False``

example

.. code-block:: python

    AUTH_ADFS = {
        "BOOLEAN_CLAIM_MAPPING": {"is_staff": "user_is_staff",
                                  "is_superuser": "user_is_superuser"},
    }

.. NOTE::
   You can find the short name for the claims you configure in the ADFS management console underneath
   **ADFS** ➜ **Service** ➜ **Claim Descriptions**

.. _claim_mapping_setting:

CLAIM_MAPPING
-------------
Default: ``None``

A dictionary of claim/field mappings that will be used to populate the user account in Django.
The user's details will be set according to this setting upon each login.

The **key** represents the user model field (e.g. ``first_name``)
and the **value** represents the claim short name (e.g. ``given_name``).

example

.. code-block:: python

    AUTH_ADFS = {
        "CLAIM_MAPPING": {"first_name": "given_name",
                          "last_name": "family_name",
                          "email": "email"},
    }

.. NOTE::
   You can find the short name for the claims you configure in the ADFS management console underneath
   **ADFS** ➜ **Service** ➜ **Claim Descriptions**

.. _client_id_setting:

CLIENT_ID
---------
**Required**

Set this to the value you configured on your ADFS server as ``ClientId`` when executing the ``Add-AdfsClient`` command.

You can lookup this value by executing the powershell command ``Get-AdfsClient`` on the ADFS server
and taking the ``ClientId`` value.

CONFIG_RELOAD_INTERVAL
----------------------
Default: ``24``

When starting Django, some settings are retrieved from the ADFS metadata file or the OpenID Connect configuration on the
ADFS server. Based on this information, certain configuration for this module is calculated.

This setting determines the interval after which the configuration is reloaded. This allows to automatically follow the
token signing certificate rollover on ADFS.

GROUP_CLAIM
-----------
Alias of ``GROUPS_CLAIM``

.. _groups_claim_setting:

GROUPS_CLAIM
------------
Default ``group`` for ADFS or ``groups`` for Azure AD.

Name of the claim in the JWT access token from ADFS that contains the groups the user is member of.
If an entry in this claim matches a group configured in Django, the user will join it automatically.

Set this setting to ``None`` to disable automatic group handling. The group memberships of the user
will not be touched.

.. IMPORTANT::
   If not set to ``None``, a user's group membership in Django will be reset to math this claim's value.
   If there's no value in the access token, the user will be removed from all groups.

.. NOTE::
   You can find the short name for the claims you configure in the ADFS management console underneath
   **ADFS** ➜ **Service** ➜ **Claim Descriptions**

GROUP_TO_FLAG_MAPPING
---------------------
This settings allows you to set flags on a user based on his group membership in Active Directory.

For example, if a user is a member of the group ``Django Staff``, you can automatically set the ``is_staff``
field of the user to ``True``.

The **key** represents the boolean user model field (e.g. ``is_staff``)
and the **value** represents the group name (e.g. ``Django Staff``).

example

.. code-block:: python

    AUTH_ADFS = {
        "GROUP_TO_FLAG_MAPPING": {"is_staff": "Django Staff",
                                  "is_superuser": "Django Admins"},
    }

.. NOTE::
   The group doesn't need to exist in Django for this to work. This will work as long as it's in the groups claim
   in the access token.

LOGIN_EXEMPT_URLS
-----------------
Default: ``None``

When you activate the ``LoginRequiredMiddleware`` middleware, by default every page will redirect
an unauthenticated user to the page configured in the Django setting ``LOGIN_URL``.

If you have pages that should not trigger this redirect, add them to this setting as a list value.

Every item it the list is interpreted as a regular expression.

.. _mirror_group_setting:

MIRROR_GROUPS
-------------
Default ``False``

This parameter will create groups from ADFS in the Django database if they do not exist already.

``True`` will create groups.

``False`` will not create any extra groups.

.. IMPORTANT::
    This parameter only has effect if GROUP_CLAIM is set to something other then ``None``.

.. _relying_party_id_setting:

RELYING_PARTY_ID
----------------
**Required**

Set this to the ``Relying party trust identifier`` value of the ``Relying Party Trust`` (2012) or ``Web application``
(2016) you configured in ADFS.

You can lookup this value by executing the powershell command ``Get-AdfsRelyingPartyTrust`` (2012) or
``Get-AdfsWebApiApplication`` (2016) on the ADFS server and taking the ``Identifier`` value.

RESOURCE
--------
Alias for ``RELYING_PARTY_ID``

.. _retries_setting:

RETRIES
-------
Default ``3``

The number of time a request to the ADFS server is retried. It allows, in combination with :ref:`timeout_setting`
to fine tune the behaviour of the connection to ADFS.

SERVER
------
**Required** when your identity provider is an on premises ADFS server.

Only one of ``SERVER`` or ``TENANT_ID`` can be set.

The FQDN of the ADFS server you want users to authenticate against.

.. _tenant_id_setting:

TENANT_ID
---------
**Required** when your identity provider is an Azure AD instance.

Only one of ``TENANT_ID`` or ``SERVER`` can be set.

The FQDN of the ADFS server you want users to authenticate against.

.. _timeout_setting:

TIMEOUT
-------
Default ``5``

The timeout in seconds for every request made to the ADFS server. It's passed on as the ``timeout`` parameter
to the underlying calls to the `requests <http://docs.python-requests.org/en/master/user/quickstart/#timeouts>`__
library.

It allows, in combination with :ref:`retries_setting` to fine tune the behaviour of the connection to ADFS.

.. _username_claim_setting:

USERNAME_CLAIM
--------------
Default: ``winaccountname`` for ADFS or ``upn`` for Azure AD.

Name of the claim sent in the JWT token from ADFS that contains the username.
If the user doesn't exist yet, this field will be used as it's username.

.. warning::
   You shouldn't need to set this value for ADFS or Azure AD. Because ``winaccountname`` maps to the ``sAMAccountName``
   on Active Directory, which is guaranteed to be unique. The same for Azure AD where ``upn`` maps to the
   ``UserPrincipleName``, which is unique on Azure AD.

.. NOTE::
   You can find the short name for the claims you configure in the ADFS management console underneath
   **ADFS** ➜ **Service** ➜ **Claim Descriptions**

