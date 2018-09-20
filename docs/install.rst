.. _install:

Installation
============

Requirements
------------

* Python 2.7 or 3.4 and above
* Django 1.8 and above

You will also need the following:

* A properly configured Microsoft Windows server 2012 R2 or 2016 with the **AD FS** role installed
  or an Azure Active Directory setup.
* A root CA bundle containing the root CA that signed the webserver certificate of your ADFS server if signed by an
  enterprise CA.

.. note::
    When using Azure AD, beware of the following limitations:

    * Users have no email address unless you assigned an Office 365 license to that user.
    * Groups are listed with their GUID in the groups claim. Meaning you have to create your groups in Django using
      these GUIDs, instead of their name.
    * Usernames are in the form of an email address, hence users created in Django follow this format.
    * You cannot send any custom claims, only those predefined by Azure AD.

Package installation
--------------------

Python package::

    pip install django-auth-adfs

Setting up django
-----------------

In your project's ``settings.py`` add these settings.

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
        # specifying them in LOGIN_EXEMPT_URLS in setting.
        'django_auth_adfs.middleware.LoginRequiredMiddleware',
    )

In your project's ``urls.py`` add these paths:

.. code-block:: python

    urlpatterns = [
        ...
        path('oauth2/', include('django_auth_adfs.urls')),
    ]

This will add 3 paths to Django:

* ``/oauth2/login`` where users are redirected to, to initiate the login with ADFS.
* ``/oauth2/callback`` where ADFS redirects back to after login. So make sure you set the redirect URI on ADFS to this.
* ``/oauth2/logout`` which logs out the user from both Django and ADFS.
