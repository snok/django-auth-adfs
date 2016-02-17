Installation
============

Requirements
------------

This package has been tested on the following Python versions:

* 3.4

You will also need the following:

* A properly configured Microsoft Windows server with the **ADFS 3.0** role installed.
* A copy of the **Token Signing Certificate** as configured on your ADFS server in base64 PEM format.

Package installation
--------------------

Python package::

    pip install django-auth-adfs


Setting up django
-----------------

In your project's ``settings.py``

.. code-block:: python

    AUTHENTICATION_BACKENDS = (
        ...
        'django_auth_adfs.backend.AdfsBackend',
        ...
    )

    INSTALLED_APPS = (
        ...
        # Needed for the ADFS redirect URI to function
        'django_auth_adfs',
        ...

    # checkout config.py for more settings
    AUTH_ADFS = {
        "ADFS_SERVER": "adfs.yourcompany.com",
        "ADFS_CLIENT_ID": "your-configured-client-id",
        "ADFS_RESOURCE": "your-adfs-RPT-name",
        "ADFS_SIGNING_CERT": "/path/to/adfs-signing-certificate.pem",
        # Make sure to read the documentation about the ADFS_AUDIENCE setting
        # when you configured the identifier as a URL!
        "ADFS_AUDIENCE": "microsoft:identityserver:your-RelyingPartyTrust-identifier",
        "ADFS_ISSUER": "http://adfs.yourcompany.com/adfs/services/trust",
        "ADFS_CA_BUNDLE": "/path/to/ca-bundle.pem",
        "ADFS_CLAIM_MAPPING": {"first_name": "given_name",
                               "last_name": "family_name",
                               "email": "email"},
    }

    ########################
    # OPTIONAL SETTINGS
    ########################
    TEMPLATES = [
        {
            ...
            'OPTIONS': {
                'context_processors': [
                    # Only needed if you want to use the variable ADFS_AUTH_URL in your templates
                    'django_auth_adfs.context_processors.adfs_url',
                    ...
                ],
            },
        },
    ]


    MIDDLEWARE_CLASSES = (
        ...
        # With this you can force a user to login without using
        # the @login_required decorator for every view function
        #
        # You can specify URLs for which login is not forced by
        # specifying them in LOGIN_EXEMPT_URLS in setting.py.
        # The values in LOGIN_EXEMPT_URLS are interpreted as regular expressions.
        #
        # The user will get redirected to the url set in the Django setting ``LOGIN_URL``
        'django_auth_adfs.middleware.LoginRequiredMiddleware',
    )

    # There's a view available for automatically redirecting users to the ADFS authorization URL.
    # If you set the value of LOGIN_URL like this, along with enabling the middleware,
    # users have to take no action themselves for logging on
    LOGIN_URL = reverse_lazy('auth_adfs:adfs')

In your project's ``urls.py``

.. code-block:: python

    urlpatterns = [
        ...
        # Needed for the redirect URL to function
        # The namespace is important and shouldn't be changed
        url(r'^oauth2/', include('django_auth_adfs.urls', namespace='auth_adfs')),
        ...
    ]

The URL you have to configure as the redirect URL in ADFS depends on the url pattern you configure.
In the example above you have to make the redirect url in ADFS point to ``https://yoursite.com/oauth2/login``
