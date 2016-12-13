Changelog
---------

0.1.1 (2016-12-13)
~~~~~~~~~~~~~~~~~~

* Numerous typos fixed in code and documentation.
* Proper handling of class variables to allow inheriting from the class `AdfsBackend`.

0.1.0 (2016-12-11)
~~~~~~~~~~~~~~~~~~

* By default, the ADFS signing certificate is loaded from the ``FederationMetadata.xml`` file every 24 hours.
  Allowing to automatically follow certificate updates when the ADFS settings for ``AutoCertificateRollover``
  is set to ``True`` (the default).
* Group assignment optimisation. Users are not removed and added to all groups anymore. Instead only the
  groups that need to be removed or added are handled.

**Backwards incompatible changes**

* The redundant ``ADFS_`` prefix was removed from the configuration variables.
* The ``REQUIRE_LOGIN_EXEMPT_URLS`` variable was renamed to ``LOGIN_EXEMPT_URLS``

0.0.5 (2016-12-10)
~~~~~~~~~~~~~~~~~~

* User update code in authentication backend split into separate functions.

0.0.4 (2016-03-14)
~~~~~~~~~~~~~~~~~~

* Made the absence of the group claim non-fatal to allow users without a group.

0.0.3 (2016-02-21)
~~~~~~~~~~~~~~~~~~

* ADFS_REDIR_URI is now a required setting
* Now supports Python 2.7, 3.4 and 3.5
* Now supports Django 1.7, 1.8 and 1.9
* Added debug logging to aid in troubleshooting
* Added unit tests
* Lot's of code cleanup

0.0.2 (2016-02-11)
~~~~~~~~~~~~~~~~~~

* Fixed a possible issue with the cryptography package when used with apache + mod_wsgi.
* Added a optional context processor to make the ADFS authentication URL available as a template variable (ADFS_AUTH_URL).
* Added a optional middleware class to be able force an anonymous user to authenticate.

0.0.1 (2016-02-09)
~~~~~~~~~~~~~~~~~~

* Initial release
