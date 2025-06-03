.. _install:

Installation
============

Requirements
------------

* Python 3.9 and above
* Django 4.2 and above

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

    # You can point login failures to a custom Django function based view for customization of the UI
    CUSTOM_FAILED_RESPONSE_VIEW = 'dot.path.to.custom.views.login_failed'

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

Below is sample Django template code to use these paths depending if
you'd like to use GET or POST requests. Logging out was deprecated in
`Django 4.1 <https://docs.djangoproject.com/en/5.1/releases/4.1/#features-deprecated-in-4-1>`_.

- Using GET requests:

    .. code-block:: html

        <a href="{% url 'django_auth_adfs:logout' %}">Logout</a>
        <a href="{% url 'django_auth_adfs:login' %}">Login</a>
        <a href="{% url 'django_auth_adfs:login-no-sso' %}">Login (no SSO)</a>

- Using POST requests:

    .. code-block:: html+django

        <form method="post" action="{% url 'django_auth_adfs:logout' %}">
            {% csrf_token %}
            <button type="submit">Logout</button>
        </form>
        <form method="post" action="{% url 'django_auth_adfs:login' %}">
            {% csrf_token %}
            <input type="hidden" name="next" value="{{ next }}">
            <button type="submit">Login</button>
        </form>
        <form method="post" action="{% url 'django_auth_adfs:login-no-sso' %}">
            {% csrf_token %}
            <input type="hidden" name="next" value="{{ next }}">
            <button type="submit">Login (no SSO)</button>
        </form>
