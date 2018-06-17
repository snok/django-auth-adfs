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

.. code-block:: bash

    python -Wd manage.py runserver

Have a look at the demo project
-------------------------------
There's an simple demo project available in the ``/demo`` folder and in the **demo** chapter of the documentation.

If you compare the files in the ``adfs`` folder with those in the ``formsbased`` folder, you'll see what needs to be
changed in a standard Django project to enable ADFS authentication.

Besides that, there are a couple of PowerShell scripts available that are used while provisioning the ADFS server for
the demo. you can find them in the ``/vagrant`` folder in this repository. They might be useful to figure out what is
wrong with the configuration of your ADFS server.

**Note that they are only meant for getting a demo running. By no means are they meant to configure your ADFS server.**
