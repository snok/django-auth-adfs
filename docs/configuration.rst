.. _configuration:

Settings
========

.. _audience_setting:

AUDIENCE
--------
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

``/path/to/ca-bundle.pem`` allows you to specify a path to a CA bundle file.

``False`` disables the certificate check.

Have a look at the `Requests documentation
<http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification>`_ for more details.

.. _boolean_claim_mapping_setting:

BOOLEAN_CLAIM_MAPPING
---------------------
Default: ``None``

A dictionary of claim/field mappings that is used to set boolean fields of the user account in Django.

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

.. _group_claim_setting:

GROUP_CLAIM
-----------
Default ``group`` for windows server or ``groups`` for Azure AD.

Name of the claim in the JWT access token from ADFS that contains the groups the user is member of.
If an entry in this claim matches a group configured in Django, the user will join it automatically.

Set this setting to ``None`` to disable automatic group handling. The group memberships of the user
will not be touched.

.. IMPORTANT::
   A user's group membership in Django will be reset to math this claim's value.
   If there's no value in the access token, the user will end up being a member of no group at all.

.. NOTE::
   You can find the short name for the claims you configure in the ADFS management console underneath
   **ADFS** ➜ **Service** ➜ **Claim Descriptions**

GROUP_FLAG_MAPPING
------------------
This settings allows you to set flags on a user based on his group membership in Active Directory.

For example, if a user is a member of the group ``Django Staff``, you can automatically set the ``is_staff``
field of the user to ``True``.

The **key** represents the boolean user model field (e.g. ``is_staff``)
and the **value** represents the group name (e.g. ``Django Staff``).

example

.. code-block:: python

    AUTH_ADFS = {
        "GROUP_FLAG_MAPPING": {"is_staff": "Django Staff",
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

.. _resource_setting:

RESOURCE
--------
**Required**

Set this to the ``Relying party trust identifier`` value of the ``Relying Party Trust`` you configured in ADFS.

You can lookup this value by executing the powershell command ``Get-AdfsRelyingPartyTrust`` on the ADFS server
and taking the ``Identifier`` value.

SERVER
------
**Required** when your ADFS server is an on premises ADFS server.

Only one of ``SERVER`` or ``TENANT_ID`` can be set.

The FQDN of the ADFS server you want users to authenticate against.

TENANT_ID
---------
**Required** when your ADFS server is an Azure AD instance.

Only one of ``TENANT_ID`` or ``SERVER`` can be set.

The FQDN of the ADFS server you want users to authenticate against.

.. _username_claim_setting:

USERNAME_CLAIM
--------------
Default: ``winaccountname`` on Windows Server or ``upn`` on Azure AD.

Name of the claim sent in the JWT token from ADFS that contains the username.
If the user doesn't exist yet, this field will be used as it's username.

.. NOTE::
   You can find the short name for the claims you configure in the ADFS management console underneath
   **ADFS** ➜ **Service** ➜ **Claim Descriptions**
