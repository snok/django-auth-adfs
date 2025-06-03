.. _settings:

Settings Reference
==================

.. _audience_setting:

AUDIENCE
--------
* **Default**:
* **Type**: ``string`` or ``list``

**Required**

Set this to the value of the ``aud`` claim your ADFS server sends back in the JWT token.

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


.. _block_guest_users_setting:

BLOCK_GUEST_USERS
-----------------
* **Default**: ``False``
* **Type**: ``boolean``

Whether guest users of your Azure AD is allowed to log into the site. This is validated by matching
the ``http://schemas.microsoft.com/identity/claims/tenantid``-key in the claims towards the configured tenant.


.. _boolean_claim_mapping_setting:

BOOLEAN_CLAIM_MAPPING
---------------------
* **Default**: ``None``
* **Type**: ``dictionary``

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

CA_BUNDLE
---------
* **Default**: ``True``
* **Type**: ``boolean`` or ``string``

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

.. _claim_mapping_setting:

CLAIM_MAPPING
-------------
* **Default**: ``None``
* **Type**: ``dictionary``

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

The dictionary can also map extra details to the Django user account using an
`Extension of the User model <https://docs.djangoproject.com/en/stable/topics/auth/customizing/#extending-the-existing-user-model>`_
Set a dictionary as value in the CLAIM_MAPPING setting with as key the name User model.
You will need to make sure the related field exists before the user authenticates.
This can be done by creating a receiver on the
`post_save <https://docs.djangoproject.com/en/4.0/ref/signals/#post-save>`_ signal that
creates the related instance when the ``User`` instance is created.

example

.. code-block:: python

    'CLAIM_MAPPING': {'first_name': 'given_name',
                      'last_name': 'family_name',
                      'email': 'upn',
                      'userprofile': {
                          'employee_id': 'employeeid'
                      }}

.. NOTE::
   You can find the short name for the claims you configure in the ADFS management console underneath
   **ADFS** ➜ **Service** ➜ **Claim Descriptions**

.. _client_id_setting:

CLIENT_ID
---------
* **Default**:
* **Type**: ``dictionary``

**Required**

Set this to the value you configured on your ADFS server as ``ClientId`` when executing the ``Add-AdfsClient`` command.

You can lookup this value by executing the powershell command ``Get-AdfsClient`` on the ADFS server
and taking the ``ClientId`` value.

CLIENT_SECRET
-------------
* **Default**: ``None``
* **Type**: ``string``

A Client secret is generated by ADFS server when executing the ``Add-AdfsClient`` command with the
``-GenerateClientSecret`` parameter.

You can lookup this value by executing the powershell command ``Get-AdfsClient`` on the ADFS server
and taking the ``ClientSecret`` value.

CONFIG_RELOAD_INTERVAL
----------------------
* **Default**: ``24``
* **Unit**: hours
* **Type**: ``integer``

When starting Django, some settings are retrieved from the ADFS metadata file or the OpenID Connect configuration on the
ADFS server. Based on this information, certain configuration for this module is calculated.

This setting determines the interval after which the configuration is reloaded. This allows to automatically follow the
token signing certificate rollover on ADFS.

.. _create_new_users_setting:

CREATE_NEW_USERS
----------------
* **Default**: ``True``
* **Type**: ``boolean``

Determines whether users are created automatically if they do not exist.

If set to ``False``, then you need to create your users before they can log in.

DISABLE_SSO
-----------
* **Default**: ``False``
* **Type**: ``boolean``


Setting this to ``True`` will globally disable the seamless single sign-on capability of ADFS.
Forcing ADFS to prompt users for a username and password, instead of automatically logging them in
with their current user. This allows users to use a different account then the one they are logged
in with on their workstation.

You can also selectively enable this setting by using ``<a href="{% url 'django_auth_adfs:login-no-sso' %}">...</a>``
in a template instead of the regular ``<a href="{% url 'django_auth_adfs:login' %}">...</a>``

.. attention::

    This does not work with ADFS 3.0 on windows 2012 because this setting requires OpenID Connect
    which is not supported on ADFS 3.0


JWT_LEEWAY
-----------
* **Default**: ``0``
* **Type**: ``str``

Allows you to set a leeway of the JWT token. See the official
`PyJWT <https://pyjwt.readthedocs.io/en/stable/usage.html>`__ docs for more information.


CUSTOM_FAILED_RESPONSE_VIEW
--------------------------------
* **Default**: ``lambda``
* **Type**: ``str`` or ``callable``

Allows you to set a custom django function view to handle login failures. Can be a dot path to your
Django function based view function or a callable.

Callable must have the following method signature accepting ``error_message`` and ``status`` arguments:

.. code-block:: python

    def failed_response(request, error_message, status):
        # Return an error message
        return render(request, 'myapp/login_failed.html', {
            'error_message': error_message,
        }, status=status)


GROUP_CLAIM
-----------
Alias of ``GROUPS_CLAIM``

.. _groups_claim_setting:

GROUPS_CLAIM
------------
* **Default**: ``group`` for ADFS or ``groups`` for Azure AD
* **Type**: ``string``

Name of the claim in the JWT access token from ADFS that contains the groups the user is member of.
If an entry in this claim matches a group configured in Django, the user will join it automatically.

If using Azure AD and there are too many groups to fit in the JWT access token, the application will
make a request to the Microsoft GraphQL API to find the groups. If you have many groups but only
need a specific few, you can customize the request by overriding
``AdfsBaseBackend.get_group_memberships_from_ms_graph_params`` and specifying the
`OData query parameters <https://learn.microsoft.com/en-us/graph/api/group-list-transitivememberof?view=graph-rest-1.0&tabs=python#http-request>`_.

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
* **Default**: ``None``
* **Type**: ``dictionary``

This settings allows you to set flags on a user based on his group membership in Active Directory.

For example, if a user is a member of the group ``Django Staff``, you can automatically set the ``is_staff``
field of the user to ``True``.

The **key** represents the boolean user model field (e.g. ``is_staff``)
and the **value**, which can either be a single String or an array of Strings, represents the group(s) name (e.g. ``Django Staff``).

example

.. code-block:: python

    AUTH_ADFS = {
        "GROUP_TO_FLAG_MAPPING": {"is_staff": ["Django Staff", "Other Django Staff"],
                                  "is_superuser": "Django Admins"},
    }

.. NOTE::
   The group doesn't need to exist in Django for this to work. This will work as long as it's in the groups claim
   in the access token.

GUEST_USERNAME_CLAIM
--------------------
* **Default**: ``None``
* **Type**: ``string``

When these criteria are met:

1. A ``guest_username_claim`` is configured
2. Token claims do not have the configured ``settings.USERNAME_CLAIM`` in it
3. The ``settings.BLOCK_GUEST_USERS`` is set to ``False``
4. The claims ``tid`` does not match ``settings.TENANT_ID`` or claims ``idp`` does not match ``iss``.

Then, the ``GUEST_USERNAME_CLAIM`` can be used to populate a username, when the ``USERNAME_CLAIM`` cannot be found in
the claims.

This can be useful when you want to use ``upn`` as a username claim for your own users,
but some guest users (such as normal outlook users) don't have that claim.


LOGIN_EXEMPT_URLS
-----------------
* **Default**: ``None``
* **Type**: ``list``

When you activate the ``LoginRequiredMiddleware`` middleware, by default every page will redirect
an unauthenticated user to the page configured in the Django setting ``LOGIN_URL``.

If you have pages that should not trigger this redirect, add them to this setting as a list value.

Every item it the list is interpreted as a regular expression.

example

.. code-block:: python

    AUTH_ADFS = {
        'LOGIN_EXEMPT_URLS': [
            '^$',
            '^api'
        ],
    }

.. _mirror_group_setting:

MIRROR_GROUPS
-------------
* **Default**: ``False``
* **Type**: ``boolean``


This parameter will create groups from ADFS in the Django database if they do not exist already.

``True`` will create groups.

``False`` will not create any extra groups.

.. IMPORTANT::
    This parameter only has effect if GROUP_CLAIM is set to something other then ``None``.

.. _relying_party_id_setting:

RELYING_PARTY_ID
----------------
* **Default**:
* **Type**: ``string``

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
* **Default**: ``3``
* **Type**: ``integer``

The number of time a request to the ADFS server is retried. It allows, in combination with :ref:`timeout_setting`
to fine tune the behaviour of the connection to ADFS.


SCOPES
------
* **Default**: ``[]``
* **Type**: ``list``

**Only used when you have v2 AzureAD config**



SERVER
------
* **Default**:
* **Type**: ``string``

**Required** when your identity provider is an on premises ADFS server.

Only one of ``SERVER`` or ``TENANT_ID`` can be set.

The FQDN of the ADFS server you want users to authenticate against.

SETTINGS_CLASS
--------------
* **Default**: ``django_auth_adfs.config.Settings``
* **Type**: ``string``

By default, django-auth-adfs reads the configuration from the Django setting
``AUTH_ADFS``. You can provide the configuration in a custom implementation
and point to it by using the ``SETTINGS_CLASS`` setting:

.. code-block:: python

    # in myapp.adfs.config

    class CustomSettings:

        SERVER = 'bar'
        AUDIENCE = 'foo'
        ...


    # in settings.py

    AUTH_ADFS = {
        'SETTINGS_CLASS': 'myapp.adfs.config.CustomSettings',
        # other settings are not needed
    }

The value must be an importable dotted Python path, and the imported object
must be callable with no arguments to initialize.

Use cases are storing configuration in database so an administrator can edit
the configuration in an admin interface.

.. _tenant_id_setting:

TENANT_ID
---------
* **Default**:
* **Type**: ``string``

**Required** when your identity provider is an Azure AD instance.

Only one of ``TENANT_ID`` or ``SERVER`` can be set.

The FQDN of the ADFS server you want users to authenticate against.

.. _timeout_setting:

TIMEOUT
-------
* **Default**: ``5``
* **Unit**: seconds
* **Type**: ``integer``

The timeout in seconds for every request made to the ADFS server. It's passed on as the ``timeout`` parameter
to the underlying calls to the `requests <http://docs.python-requests.org/en/master/user/quickstart/#timeouts>`__
library.

It allows, in combination with :ref:`retries_setting` to fine tune the behaviour of the connection to ADFS.

.. _username_claim_setting:

USERNAME_CLAIM
--------------
* **Default**: ``winaccountname`` for ADFS or ``upn`` for Azure AD.
* **Type**: ``string``

Name of the claim sent in the JWT token from ADFS that contains the username.
If the user doesn't exist yet, this field will be used as it's username.

The value of the claim must be a unique value. No 2 users should ever have the same value.

.. warning::
   You shouldn't need to set this value for ADFS or Azure AD unless you use custom user models.
   Because ``winaccountname`` maps to the ``sAMAccountName`` on Active Directory, which is guaranteed
   to be unique. The same for Azure AD where ``upn`` maps to the ``UserPrincipleName``, which is unique
   on Azure AD.

.. NOTE::
   You can find the short name for the claims you configure in the ADFS management console underneath
   **ADFS** ➜ **Service** ➜ **Claim Descriptions**


.. _version_setting:

VERSION
--------------
* **Default**: ``v1.0``
* **Type**: ``string``

Version of the Azure Active Directory endpoint version. By default it is set to ``v1.0``. At the time of writing this documentation, it can also be set to ``v2.0``. For new projects, ``v2.0`` is recommended. ``v1.0`` is kept as a default for backwards compatibility.

PROXIES
-------
* **Default**: ``None``
* **Type**: ``dict``

An optional proxy for all communication with the server. Example: ``{'http': '10.0.0.1', 'https': '10.0.0.2'}``
See the `requests documentation <https://requests.readthedocs.io/en/v3.0.0/api/#requests.Session.proxies>`__ for more information.
