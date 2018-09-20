Frequently Asked Questions
==========================

Why am I always redirected to ``/accounts/profile/`` after login?
-----------------------------------------------------------------
This is default Django behaviour. You can change it by setting the Django setting named
`LOGIN_REDIRECT_URL <https://docs.djangoproject.com/en/dev/ref/settings/#login-redirect-url>`_.

How do I store additional info about a user?
--------------------------------------------
``django_auth_adfs`` can only store information in existing fields of the user model.
If you want to store extra info, you'll have to extend the default user model with extra fields and adjust
the :ref:`claim_mapping_setting` setting accordingly.

`You can read about how to extend the user model here <https://simpleisbetterthancomplex.com/tutorial/2016/07/22/how-to-extend-django-user-model.html#abstractuser>`_

I'm receiving an ``SSLError: CERTIFICATE_VERIFY_FAILED`` error.
---------------------------------------------------------------
double check your ``CA_BUNDLE`` setting. Most likely your ADFS server is using a certificate signed by an
enterprise root CA. you'll need to put it's certificate in a file and set ``CA_BUNDLE`` to it's path.

I cannot get it working!
------------------------
Make sure you follow the instructions in the troubleshooting guide.
It will enable debugging and can quickly tell you what is wrong.

Also, walk through :ref:`all the possible settings <configuration>` once, you might find one
that needs to be adjusted to match your situation.
