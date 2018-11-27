Django Rest Framework integration
=================================

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
        path('oauth2/', include('django_auth_adfs.drf-urls')),
        ...
    ]

.. _request-access-token:

Requesting an access token
--------------------------

When everything is configured, you can request an access token in your client (script) and
access the api like this:

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
