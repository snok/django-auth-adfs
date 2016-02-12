Changelog
---------

0.0.2 (2016-02-11)
~~~~~~~~~~~~~~~~~~~

* Fixed a possible issue with the cryptography package when used with apache + mod_wsgi.
* Added a optional context processor to make the ADFS authentication URL available as a template variable (ADFS_AUTH_URL).
* Added a optional middleware class to be able force an anonymous user to authenticate.

0.0.1 (2016-02-09)
~~~~~~~~~~~~~~~~~~

* Initial release
