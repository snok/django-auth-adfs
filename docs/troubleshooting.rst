Troubleshooting
===============

Turn on Django debug logging
----------------------------
If you run into any problems, set the logging level in Django to DEBUG.
You can do this by adding the configuration below to your ``settings.py``

You can see this logging in your console, or in you web server log if you're using something
like Apache with mod_wsgi.

More details about logging in Django can be found in
`the official Django documentation <https://docs.djangoproject.com/en/latest/topics/logging/>`_

.. code-block:: python

    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'verbose': {
                'format': '%(levelname)s %(asctime)s %(name)s %(message)s'
            },
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'formatter': 'verbose'
            },
        },
        'loggers': {
            'django_auth_adfs': {
                'handlers': ['console'],
                'level': 'DEBUG',
            },
        },
    }

Run Django with warnings enabled
--------------------------------

Start the python interpreter that runs you Django with the ``-Wd`` parameter. This will show warnings that are otherwise
suppressed.

.. code-block::

    python -Wd manage.py runserver
