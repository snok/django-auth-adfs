Login Middleware
================

**django-auth-adfs** ships with a middleware class named ``LoginRequiredMiddleware``.
You can use it to force an unauthenticated user to login and be redirected to the URL specified in in Django's
``LOGIN_URL`` setting without having to add code to every view.

By default it's disabled for the page defined in the ``LOGIN_URL`` setting and the redirect page for ADFS.
But by setting the ``LOGIN_EXEMPT_URLS`` setting, you can exclude other pages from authentication.
Have a look at the :ref:`settings` for more information.

To enable the middleware, add it to ``MIDLEWARE`` in ``settings.py`` (or ``MIDDLEWARE_CLASSES`` if using Django <1.10.
make sure to add it after any other session or authentication middleware to be sure all other methods of identifying
the user are tried first.

In your ``settings.py`` file, add the following:

.. code-block:: python

    MIDDLEWARE = (
        ...
        'django_auth_adfs.middleware.LoginRequiredMiddleware',
    )

    AUTH_ADFS = {
        ...
        "LOGIN_EXEMPT_URLS": ["api/", "public/"],
        ...
    }
