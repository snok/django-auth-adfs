Changelog
=========

`1.6.0`_ - 2021-01-25
---------------------

**Features**

* New parameter called `CUSTOM_FAILED_RESPONSE_VIEW`, allowing you to set a custom django function view to handle login
  failures. #136


`1.5.0`_ - 2021-01-18
---------------------

**Features**

* New parameter called `LEEWAY_JWT`, allowing you to set a leeway for validating the JWT token. #128


`1.4.1`_ - 2021-01-16
---------------------

**Fixed**

* AADSTS50076 error fixed. #101


`1.4.0`_ - 2021-01-16
---------------------

**Features**

* Added support for enterprice app SSO certificates. #87
* Added setting to disable user creation. #96

**Fixed**

* Dependency compatibility for PyJWT 2.0. #120
* Django 4.0 deprecation cleanup.
* Fixed a bug where IntegrityError could occur if a users groups changed, and multiple requests were done quickly. #95


`1.3.1`_ - 2019-11-06
---------------------

**Fixed**

* Fix retries towards ADFS in situations where ADFS didn't respond in time.

`1.3.0`_ - 2019-11-01
---------------------

.. note::

    From this release onwards, compatibility with python 2.7 and 3.4 is not guaranteed anymore.

**Removed**

* Python 2.7 and 3.4 tests
* Django Rest Framework 3.7 tests

**Changed**

* The URLs file to override the django rest framework login (``drf-urls.py``), was not a valid python module name.
  It was changed to ``drf_urls.py``. Th old name is still there but will be removed in a next release.

**Added**

* Added setting ``SETTINGS_CLASS``, defaulting to
  ``django_auth_adfs.config.Settings``. This provides a mechanism to load the
  ``AUTH_ADFS`` config from sources other than Django settings.
* Python 3.8 tests
* Django Rest Framework 3.10 tests

`1.2.0`_ - 2019-03-01
---------------------

**Removed**

* Django 1.8, 1.9 and 1.10 support. They are end of extended support and keeping support for them was becoming too
  complex.

**Fixed**

* The django templates were missing in the wheel

`1.1.2`_ - 2018-12-11
---------------------

**Added**

* Added views to selectively disable SSO for login links

**Fixed**

* Existing users with an empty password raised an exception

`1.1.1`_ - 2018-12-07
---------------------

**Added**

* Add a setting to force a login screen and disable SSO on ADFS.
* Documentation about how to enable SSO for other browsers than IE & Edge.

**Fixed**

* Prevent username field from being overwritten by a claim mapping.
* Prevent traceback upon logout when ADFS config is not yet loaded.
* Fix fields in log messages being swapped.

**Security**

* Don't allow the audience claim to be ignored. Preventing access token reuse.
* Set an unusable password on newly created user instead of leaving it empty.

`1.0.0`_ - 2018-12-05
---------------------

**This version contains backwards incompatible changes. Make sure to read the entire release notes**

**Added**

* Windows 2016 (a.k.a. ADFS 4.0) Support
* AzureAD support (check the setting ``TENANT_ID``)
* Django Rest Framework support.
* Add a ``RETRIES`` and ``TIMEOUT`` setting for requests towards the ADFS server.
* Add the ``CLIENT_SECRET`` setting to support client secrets in the OAuth2 Flow.
* Users are now redirected back to the page that triggered the login instead of the main page.
* Groups a user belongs to can now be automatically created in Django (check the ``MIRROR_GROUPS`` setting)

**Changed**

* Django 2.1 support
* All settings that can be determined automatically are now set automatically
* When a claim mapped to a non-required field in the user model is missing,
  a warning is logged instead of an exception raised

**Incompatible changes**

* Because of the login and logout views that were added, the redirect URI back from ADFS should
  now point to ``/oauth2/callback``. Keeping it at ``/oauth2/login`` would have caused a potential redirect loop.

**Deprecated**

* these settings are now loaded from ADFS metadata automatically and have been deprecated:

    * ``AUTHORIZE_PATH``
    * ``LOGIN_REDIRECT_URL``
    * ``ISSUER``
    * ``REDIR_URI``
    * ``SIGNING_CERT``
    * ``TOKEN_PATH``


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

.. _1.6.0: https://github.com/snok/django-auth-adfs/compare/1.5.0...1.6.0
.. _1.5.0: https://github.com/jobec/django-auth-adfs/compare/1.4.1...1.5.0
.. _1.4.1: https://github.com/jobec/django-auth-adfs/compare/1.4.0...1.4.1
.. _1.4.0: https://github.com/jobec/django-auth-adfs/compare/1.3.1...1.4.0
.. _1.3.1: https://github.com/jobec/django-auth-adfs/compare/1.3.0...1.3.1
.. _1.3.0: https://github.com/jobec/django-auth-adfs/compare/1.2.0...1.3.0
.. _1.2.0: https://github.com/jobec/django-auth-adfs/compare/1.1.2...1.2.0
.. _1.1.2: https://github.com/jobec/django-auth-adfs/compare/1.1.1...1.1.2
.. _1.1.1: https://github.com/jobec/django-auth-adfs/compare/1.0.0...1.1.1
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
