Changelog
=========

`1.0.0`_ - Not yet released
---------------------------

**This version contains backwards incompatible changes. Make sure to read the entire release notes**

* Windows 2016 (a.k.a. ADFS 4.0) Support
* AzureAD support (check the setting ``TENANT_ID``)
* Django 2.1 support
* All settings that can be determined automatically are now set automatically
* Users are now redirected back to the page that triggered the login instead of the main page.
* Groups a user belongs to can now be automatically created in Django (check the ``MIRROR_GROUPS`` setting)
* When a claim mapped to a non-required field in the user model is missing,
  a warning is logged instead of an exception raised
* Add a ``RETRIES`` and ``TIMEOUT`` setting for requests towards the ADFS server.

**Incompatible changes**

* these settings are now loaded from ADFS metadata automatically and have been deprecated:

    * ``AUTHORIZE_PATH``
    * ``LOGIN_REDIRECT_URL``
    * ``ISSUER``
    * ``REDIR_URI``
    * ``SIGNING_CERT``
    * ``TOKEN_PATH``

* Because of the login and logout views that were added, the redirect URI back from ADFS should
  now point to ``/oauth2/callback``. Keeping it at ``/oauth2/login`` would have caused a potential redirect loop.

`0.2.1`_ - 2017-10-20
---------------------

* Django 2.0 support and tests.

`0.2.0`_ - 2017-09-14
---------------------

* Fixed a bug were authentication failed when the last ADFS signing key was not the one that signed the JWT token.
* Django 1.11 support and tests.
* Proper handling the absence of 'code' query parameter after ADFS redirect.
* Added ADFS configuration guide to docs.
* Allow boolean user model fields to be set based on claims.
* The ``namespace`` argument for ``include()`` is not needed anymore on Django >=1.9.
* Fixed some Django 2.0 deprecation warnings, improving future django support.

`0.1.2`_ - 2017-03-11
---------------------

* Support for django 1.10 new style middleware using the ``MIDDLEWARE`` setting.

`0.1.1`_ - 2016-12-13
---------------------

* Numerous typos fixed in code and documentation.
* Proper handling of class variables to allow inheriting from the class ``AdfsBackend``.

`0.1.0`_ - 2016-12-11
---------------------

* By default, the ADFS signing certificate is loaded from the ``FederationMetadata.xml`` file every 24 hours.
  Allowing to automatically follow certificate updates when the ADFS settings for ``AutoCertificateRollover``
  is set to ``True`` (the default).
* Group assignment optimisation. Users are not removed and added to all groups anymore. Instead only the
  groups that need to be removed or added are handled.

**Backwards incompatible changes**

* The redundant ``ADFS_`` prefix was removed from the configuration variables.
* The ``REQUIRE_LOGIN_EXEMPT_URLS`` variable was renamed to ``LOGIN_EXEMPT_URLS``

`0.0.5`_ - 2016-12-10
---------------------

* User update code in authentication backend split into separate functions.

`0.0.4`_ - 2016-03-14
---------------------

* Made the absence of the group claim non-fatal to allow users without a group.

`0.0.3`_ - 2016-02-21
---------------------

* ADFS_REDIR_URI is now a required setting
* Now supports Python 2.7, 3.4 and 3.5
* Now supports Django 1.7, 1.8 and 1.9
* Added debug logging to aid in troubleshooting
* Added unit tests
* Lot's of code cleanup

`0.0.2`_ - 2016-02-11
---------------------

* Fixed a possible issue with the cryptography package when used with apache + mod_wsgi.
* Added a optional context processor to make the ADFS authentication URL available as a template variable (ADFS_AUTH_URL).
* Added a optional middleware class to be able force an anonymous user to authenticate.

0.0.1 - 2016-02-09
------------------

* Initial release

.. _1.0.0: https://github.com/jobec/django-auth-adfs/compare/0.2.1...1.0.0
.. _0.2.1: https://github.com/jobec/django-auth-adfs/compare/0.2.0...0.2.1
.. _0.2.0: https://github.com/jobec/django-auth-adfs/compare/0.1.2...0.2.0
.. _0.1.2: https://github.com/jobec/django-auth-adfs/compare/0.1.1...0.1.2
.. _0.1.1: https://github.com/jobec/django-auth-adfs/compare/0.1.0...0.1.1
.. _0.1.0: https://github.com/jobec/django-auth-adfs/compare/0.0.5...0.1.0
.. _0.0.5: https://github.com/jobec/django-auth-adfs/compare/0.0.4...0.0.5
.. _0.0.4: https://github.com/jobec/django-auth-adfs/compare/0.0.3...0.0.4
.. _0.0.3: https://github.com/jobec/django-auth-adfs/compare/0.0.2...0.0.3
.. _0.0.2: https://github.com/jobec/django-auth-adfs/compare/0.0.1...0.0.2


