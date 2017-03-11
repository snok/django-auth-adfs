Extras
======

Middleware
----------

**django-auth-adfs** ships with a middleware class named ``LoginRequiredMiddleware``.
You can use it to force an unauthenticated user to be redirected to the page defined in the
``LOGIN_PAGE`` setting in ``settings.py`` without having to add code to every view.

By default it's disabled for the page defined in the ``LOGIN_URL`` setting and the redirect page for ADFS.
But by setting the ``LOGIN_EXEMPT_URLS`` setting, you can exclude other pages from authentication.
Have a look at the :ref:`configuration documentation <configuration>` for more information.

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

Context processor
-----------------

This context processor allows you to use the login URL of your ADFS server
as a variable inside your templates. This can be used for example to provide a login link.

First, in your ``settings.py`` file, add the following:

.. code-block:: python

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

Then, inside a template you can point to this variable like so:


.. code-block:: html

    ...
    <a href="{{ ADFS_AUTH_URL }}">Click here to log in</a>
    ...

