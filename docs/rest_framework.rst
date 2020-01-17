Rest Framework integration
==========================

Setup
-----

When using Django Rest Framework, you can also use this package to authenticate
your REST API clients. For this you need to do some extra configuration.

You also need to install ``djangorestframework`` (or add it to your
project dependencies)::

    pip install djangorestframework

The default ``AdfsBackend`` backend expects an ``authorization_code``. The backend
will take care of obtaining an ``access_code`` from the Adfs server.

With the Django Rest Framework integration the client application needs to acquire
the access token by itself. See for an example: :ref:`request-access-token`. To
authenticate against the API you need to enable the ``AdfsAccessTokenBackend``.

Steps to enable the Django Rest Framework integration are as following:

Add an extra authentication class to Django Rest Framework in ``settings.py``:

.. code-block:: python

    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': (
            'django_auth_adfs.rest_framework.AdfsAccessTokenAuthentication',
            'rest_framework.authentication.SessionAuthentication',
        )
    }

Enable the ``AdfsAccessTokenBackend`` authentication backend in ``settings.py``:

.. code-block:: python

    AUTHENTICATION_BACKENDS = (
        ...
        'django_auth_adfs.backend.AdfsAccessTokenBackend',
        ...
    )

Prevent your API from triggering a login redirect:

.. code-block:: python

    AUTH_ADFS = {
        'LOGIN_EXEMPT_URLS': [
            '^api',  # Assuming you API is available at /api
        ],
    }

(Optional) Override the standard Django Rest Framework login pages in your main ``urls.py``:

.. code-block:: python

    urlpatterns = [
        ...
        # The default rest framework urls shouldn't be included
        # If we include them, we'll end up with the DRF login page,
        # instead of being redirected to the ADFS login page.
        #
        # path('api-auth/', include('rest_framework.urls')),
        #
        # This overrides the DRF login page
        path('oauth2/', include('django_auth_adfs.drf_urls')),
        ...
    ]

.. _request-access-token:

Requesting an access token
--------------------------

When everything is configured, you can request an access token in your client (script) and
access the api like this:

.. note::

    This example is written for ADFS on windows server 2016 but with some changes in the
    URLs should also work for Azure AD.

.. code-block:: python

    import getpass
    import requests
    from pprint import pprint

    # Ask for password
    user = getpass.getuser()
    password = getpass.getpass("Password for "+user+": ")
    user = user + "@example.com"

    # Get an access token
    payload = {
        "grant_type": "password",
        "resource": "your-relying-party-id",
        "client_id": "your-configured-client-id",
        "username": user,
        "password": password,
    }
    response = requests.post(
        "https://adfs.example.com/adfs/oauth2/token",
        data=payload,
        verify=False
    )
    response.raise_for_status()
    response_data = response.json()
    access_token = response_data['access_token']

    # Make a request towards this API
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + access_token,
    }
    response = requests.get(
        'https://web.example.com/api/questions',
        headers=headers,
        verify=False
    )
    pprint(response.json())


.. note::

    The following example is written for ADFS on windows server 2012 R2 and needs
    the ``requests-ntlm`` module.

    This example is here only for legacy reasons. If possible it's advised to
    upgrade to 2016. Support for 2012 R2 is about to end.

.. code-block:: python

    import getpass
    import re
    import requests
    from requests_ntlm import HttpNtlmAuth
    from pprint import pprint

    # Ask for password
    user = getpass.getuser()
    password = getpass.getpass("Password for "+user+": ")
    user = "EXAMPLE\\" + user

    # Get a authorization code
    headers = {"User-Agent": "Mozilla/5.0"}
    params = {
        "response_type": "code",
        "resource": "your-relying-party-id",
        "client_id": "your-configured-client-id",
        "redirect_uri": "https://djangoapp.example.com/oauth2/callback"
    }
    response = requests.get(
        "https://adfs.example.com/adfs/oauth2/authorize/wia",
        auth=HttpNtlmAuth(user, password),
        headers=headers,
        allow_redirects=False,
        params=params,
    )
    response.raise_for_status()
    code = re.search('code=(.*)', response.headers['location']).group(1)

    # Get an access token
    data = {
        'grant_type': 'authorization_code',
        'client_id': 'your-configured-client-id',
        'redirect_uri': 'https://djangoapp.example.com/oauth2/callback',
        'code': code,
    }
    response = requests.post(
        "https://adfs.example.com/adfs/oauth2/token",
        data,
    )
    response.raise_for_status()
    response_data = response.json()
    access_token = response_data['access_token']

    # Make a request towards this API
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Bearer %s' % access_token,
    }
    response = requests.get(
        'https://djangoapp.example.com/v1/pets?name=rudolf',
        headers=headers
    )
    pprint(response.json())
