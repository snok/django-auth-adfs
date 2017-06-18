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

AUTHORIZE_PATH
--------------
Default: ``/adfs/oauth2/authorize``

The path to the authorize page off your ADFS server.
Users have to visit this page to receive an *authorization code*.
This value is appended to the server FQDN and used to build the full authorization URL.
This URL is available as the variable ``ADFS_AUTH_URL`` inside templates when using the
django-auth-adfs context processor ``adfs_url``.

The default value matches the default for ADFS 3.0.

CA_BUNDLE
---------
Default: ``True``

The value of this setting is passed to the call to the ``Requests`` package when fetching the access token from ADFS.
It allows you to control the webserver certificate verification of the ADFS server.

``True`` makes it use the default CA bundle of your system.

``False`` disables the certificate check.

``/path/to/ca-bundle.pem`` allows you to specify a path to a CA bundle file.

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

The **key** represents user model field (e.g. ``first_name``)
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

CERT_MAX_AGE
------------
Default: ``24``

The number of hours the ADFS token signing certificate is cached.
This timer gets started the first time someone logs in using a ADFS JWT token
because only then the backend class is loaded for the first time.

.. NOTE::
   This setting is related with the ``SIGNING_CERT`` setting.

.. _group_claim_setting:

GROUP_CLAIM
-----------
Default ``group``

Name of the claim sent in the JWT token from ADFS that contains the groups the user is member of.
If an entry in this claim matches a group configured in Django, the user will join it automatically.

If the returned claim is empty, or the setting is set to ``None``, users are not joined to any group.

.. IMPORTANT::
   User's group membership in Django will be reset to math this claim's value.
   If there's no value, the user will end up being member of no groups.

.. NOTE::
   You can find the short name for the claims you configure in the ADFS management console underneath
   **ADFS** ➜ **Service** ➜ **Claim Descriptions**

LOGIN_EXEMPT_URLS
-----------------
Default: ``None``

When you activate the ``LoginRequiredMiddleware`` middleware, by default every page will redirect
an unauthenticated user to the page configured in the Django setting ``LOGIN_URL``.

If you have pages that should not trigger this redirect, add them to this setting as a list value.

Every item it the list is interpreted as a regular expression.

LOGIN_REDIRECT_URL
------------------
Default: ``None``

The URL users are redirected to when their authentication is successful.

Because we redirect users to and from the ADFS server, we can't pass along
a parameters telling us what page the user tried accessing before he got redirected.
Thet's why we redirect to a fixed page.

If you leave this set to ``None``, the Django setting named ``LOGIN_REDIRECT_URL`` will be used instead.

ISSUER
------
Default: ``None``

Set this to the value of the ``iss`` claim your ADFS server sends back in the JWT token.
Usually this is something like ``http://adfs.yourcompany.com/adfs/services/trust``.

If you leave this set to ``None`` this claim will not be verified.

You can lookup this value by executing the powershell command ``Get-AdfsProperties`` on the ADFS server
and taking the ``Identifier`` value.

.. IMPORTANT::
    The issuer isn't necessarily the same as the URL of your ADFS server.
    It usually starts with ``HTTP`` instead of ``HTTPS``

.. _redir_uri_setting:

REDIR_URI
---------
**Required**

Sets the **redirect uri** configured for your client id in ADFS.

Because we need this value in a context without access to a Django ``request`` object,
it needs to be explicitly configured.

You can lookup this value by executing the powershell command ``Get-AdfsClient`` on the ADFS server
and taking the ``RedirectUri`` value (without the ``{}`` brackets).

.. IMPORTANT::
   Make sure both this setting and the setting on your ADFS server
   matches with the url pattern configured in your ``urls.py`` file.

   See the :ref:`install documentation <install>` for more details.

.. _resource_setting:

RESOURCE
--------
**Required**

Set this to the ``Relying party trust identifier`` value of the ``Relying Party Trust`` you configured in ADFS.

You can lookup this value by executing the powershell command ``Get-AdfsRelyingPartyTrust`` on the ADFS server
and taking the ``Identifier`` value.

SIGNING_CERT
------------
Default: ``True``

Can be one of the following values:

* ``True`` for autoloading the certificate from the ``FederationMetadata.xml`` file on the ADFS server.
* The base64 PEM representation of the ``Token Signing Certificate`` configured in your ADFS server.
* The path to a certificate file in base64 PEM format.

The default value allows you to automatically load new certificates when they get changed on the ADFS server.
For more details see the ``AutoCertificateRollover`` setting of your ADFS server.

.. NOTE::
   This setting is related with the ``CERT_MAX_AGE`` setting.

SERVER
------
**Required**

Default: ``None``

The FQDN of the ADFS server you want users to authenticate against.

TOKEN_PATH
----------
Default: ``/adfs/oauth2/token``

This is the path to the token page of your ADFS server. The authentication backend
will try to fetch the access token by submitting the authorization code to this page.

.. _username_claim_setting:

USERNAME_CLAIM
--------------
Default: ``winaccountname``

Name of the claim sent in the JWT token from ADFS that contains the username.
If the user doesn't exist yet, this field will be used as it's username.

.. NOTE::
   You can find the short name for the claims you configure in the ADFS management console underneath
   **ADFS** ➜ **Service** ➜ **Claim Descriptions**
