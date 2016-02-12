.. _configuration:

Settings
========

ADFS_SERVER
-----------
**Required**

Default: ``None``

The FQDN of the ADFS server you want users to authenticate against.

ADFS_AUTHORIZE_PATH
-------------------

Default: ``/adfs/oauth2/authorize``

The path to the authorize page off your ADFS server.
Users have to visit this page to receive a *authorization code*.
This value is appended to the server FQDN and used to build the full authorization URL.
This URL is available as the variable ``ADFS_AUTH_URL`` inside templates when using the
django-auth-adfs context processor ``adfs_url``.

The default value matches the default for ADFS 3.0.

ADFS_TOKEN_PATH
---------------

Default: ``/adfs/oauth2/token``

This is the path to the token page off your ADFS server. The authentication backand
will try to fetch the access token by submitting the authorization code to this page.

ADFS_CLIENT_ID
--------------

**Required**

Default: ``None``

Set this to the value you configured on your ADFS server as ``ClientId``

ADFS_RESOURCE
-------------

**Required**

Default: ``None``

Set this to the name of the ``Relying Party Trust`` you configured in ADFS.

ADFS_SIGNING_CERT
-----------------

**Required**

Default: ``None``

This can either be the base64 PEM representation of the ``Token Signing Certificate``
you configured on ADFS. Or it can be the path to a certificate file in base64 PEM format.

ADFS_AUDIENCE
-------------

Default: ``None``

Set this to the value of the ``aud claim`` your ADFS server sends back in the JWT token.
Usually this is something like ``microsoft:identityserver:your-RelyingPartyTrust-name``

If you leave this set to ``None`` this claim will not be verified.

ADFS_ISSUER
-----------

Default: ``None``

Set this to the value of the ``iss claim`` your ADFS server sends back in the JWT token.
Usually this is something like ``http://adfs.yourcompany.com/adfs/services/trust``.

If you leave this set to ``None`` this claim will not be verified.

ADFS_CA_BUNDLE
--------------

Default: ``True``

The value of this setting is passed to the call to the ``Requests`` package when fetching the access token from ADFS.
It allows you to control the webserver certificate verification of the ADFS server.

``True`` makes it use the default CA bundle of your system.

``False`` disables the certificate check.

``/path/to/ca-bundle.pem`` allows you to specify a path to a CA bundle file.

Have a look at the `Requests documentation
<http://docs.python-requests.org/en/master/user/advanced/#ssl-cert-verification>`_ for more details.

ADFS_REDIR_URI
--------------

Default: ``None``

Allows you to specify a specific **redirirect uri** configured for your client id in ADFS.

If you leave this set to ``None``, the URI will be calculated based on these values.

* ``request.scheme``
* ``request.META['HTTP_HOST']``
* ``reverse("auth_adfs:login")``

If for some reason this resolution fails (ex. your behind a SSL offloading reverse proxy), you can set this
value manually

ADFS_LOGIN_REDIRECT_URL
-----------------------

Default: ``None``

The URL users are redirected to when their authentication is successful.

Because we redirect users to and from the ADFS server, we can't pass along
a parameters telling us what page the user tried accessing before he got redirected.
Thet's why we redirect to a fixed page.

If you leave this set to ``None``, the Django setting named ``LOGIN_REDIRECT_URL`` will be used instead.


ADFS_USERNAME_CLAIM
-------------------

Default: ``winaccountname``

Name of the claim sent in the JWT token from ADFS that contains the username.
If the user doesn't exist yet, this field will be used as it's username.

ADFS_GROUP_CLAIM
----------------

Default ``group``

Name of the claim sent in the JWT token from ADFS that contains the groups the user is member of.
If a entry in this claim matches a group configured in Django, the user will join it automatically.

If there's no value in the configured claim, or the claim doesn't exist, users are not joined to any group.

.. IMPORTANT::
   User's group membership in Django will be reset to math this claim's value.
   If there's no value, the user will end up being member of no groups.


ADFS_CLAIM_MAPPING
------------------

Default: ``None``

A dictionary of claim/field mappings that will be used to populate the user account in Django.
The user's details will be set according to this setting upon each login.


REQUIRE_LOGIN_EXEMPT_URLS
-------------------------

Default: ``None``

When you activate the ``LoginRequiredMiddleware`` middleware, by default every page will redirect
an unauthenticated used to the page configured in the Django setting ``LOGIN_URL``.

If you have pages that should not trigger this redirect, add them to this setting as a list value.

Every item it the list is interpreted as a regular expression.
