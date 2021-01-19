ADFS Authentication for Django
==============================

.. image:: https://readthedocs.org/projects/django-auth-adfs/badge/?version=latest
    :target: http://django-auth-adfs.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status
.. image:: https://img.shields.io/pypi/v/django-auth-adfs.svg
    :target: https://pypi.python.org/pypi/django-auth-adfs
.. image:: https://img.shields.io/pypi/pyversions/django-auth-adfs.svg
    :target: https://pypi.python.org/pypi/django-auth-adfs#downloads
.. image:: https://img.shields.io/pypi/djversions/django-auth-adfs.svg
    :target: https://pypi.python.org/pypi/django-auth-adfs
.. image:: https://codecov.io/github/snok/django-auth-adfs/coverage.svg?branch=master
    :target: https://codecov.io/github/snok/django-auth-adfs?branch=master

A Django authentication backend for Microsoft ADFS and Azure AD

* Free software: BSD License
* Homepage: https://github.com/snok/django-auth-adfs
* Documentation: http://django-auth-adfs.readthedocs.io/

Features
--------

* Integrates Django with Active Directory on Windows 2012 R2, 2016 or Azure AD in the cloud.
* Provides seamless single sign on (SSO) for your Django project on intranet environments.
* Auto creates users and adds them to Django groups based on info received from ADFS.
* Django Rest Framework (DRF) integration: Authenticate against your API with an ADFS access token.

Installation
------------

Python package::

    pip install django-auth-adfs

In your project's ``settings.py`` add these settings.

.. code-block:: python

    AUTHENTICATION_BACKENDS = (
        ...
        'django_auth_adfs.backend.AdfsAuthCodeBackend',
        ...
    )

    INSTALLED_APPS = (
        ...
        # Needed for the ADFS redirect URI to function
        'django_auth_adfs',
        ...

    # checkout the documentation for more settings
    AUTH_ADFS = {
        "SERVER": "adfs.yourcompany.com",
        "CLIENT_ID": "your-configured-client-id",
        "RELYING_PARTY_ID": "your-adfs-RPT-name",
        # Make sure to read the documentation about the AUDIENCE setting
        # when you configured the identifier as a URL!
        "AUDIENCE": "microsoft:identityserver:your-RelyingPartyTrust-identifier",
        "CA_BUNDLE": "/path/to/ca-bundle.pem",
        "CLAIM_MAPPING": {"first_name": "given_name",
                          "last_name": "family_name",
                          "email": "email"},
    }

    # Configure django to redirect users to the right URL for login
    LOGIN_URL = "django_auth_adfs:login"
    LOGIN_REDIRECT_URL = "/"

    ########################
    # OPTIONAL SETTINGS
    ########################

    MIDDLEWARE = (
        ...
        # With this you can force a user to login without using
        # the LoginRequiredMixin on every view class
        #
        # You can specify URLs for which login is not enforced by
        # specifying them in the LOGIN_EXEMPT_URLS setting.
        'django_auth_adfs.middleware.LoginRequiredMiddleware',
    )

In your project's ``urls.py`` add these paths:

.. code-block:: python

    urlpatterns = [
        ...
        path('oauth2/', include('django_auth_adfs.urls')),
    ]

This will add these paths to Django:

* ``/oauth2/login`` where users are redirected to, to initiate the login with ADFS.
* ``/oauth2/login_no_sso`` where users are redirected to, to initiate the login with ADFS but forcing a login screen.
* ``/oauth2/callback`` where ADFS redirects back to after login. So make sure you set the redirect URI on ADFS to this.
* ``/oauth2/logout`` which logs out the user from both Django and ADFS.

You can use them like this in your django templates:

.. code-block:: html

    <a href="{% url 'django_auth_adfs:logout' %}">Logout</a>
    <a href="{% url 'django_auth_adfs:login' %}">Login</a>
    <a href="{% url 'django_auth_adfs:login-no-sso' %}">Login (no SSO)</a>

Contributing
------------
Contributions to the code are more then welcome.
For more details have a look at the ``CONTRIBUTING.rst`` file.
