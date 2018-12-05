ADFS Authentication for Django
==============================

.. image:: https://readthedocs.org/projects/django-auth-adfs/badge/?version=latest
    :target: http://django-auth-adfs.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status
.. image:: https://img.shields.io/pypi/v/django-auth-adfs.svg
    :target: https://pypi.python.org/pypi/django-auth-adfs
.. image:: https://img.shields.io/pypi/pyversions/django-auth-adfs.svg
    :target: https://pypi.python.org/pypi/django-auth-adfs#downloads
.. image:: https://img.shields.io/pypi/djversions/django-auth-adfs.svg
    :target: https://pypi.python.org/pypi/django-auth-adfs
.. image:: https://travis-ci.org/jobec/django-auth-adfs.svg?branch=master
    :target: https://travis-ci.org/jobec/django-auth-adfs
.. image:: https://codecov.io/github/jobec/django-auth-adfs/coverage.svg?branch=master
    :target: https://codecov.io/github/jobec/django-auth-adfs?branch=master

A Django authentication backend for Microsoft ADFS and Azure AD

* Free software: BSD License
* Homepage: https://github.com/jobec/django-auth-adfs
* Documentation: http://django-auth-adfs.readthedocs.io/

Features
--------

* Integrates Django with Active Directory on Windows 2012 R2, 2016 or Azure AD in the cloud.
* Provides seamless single sign on (SSO) for your Django project on intranet environments.
* Auto creates users and adds them to Django groups based on info received from ADFS.
* Django Rest Framework (DRF) integration: Authenticate against your API with an ADFS access token.

Contents
--------

.. toctree::
    :maxdepth: 3

    install
    oauth2_explained
    settings_ref
    config_guides
    middleware
    rest_framework
    demo
    troubleshooting
    faq
    contributing
    changelog
