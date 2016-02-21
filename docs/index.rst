.. django-auth-adfs documentation master file, created by
   sphinx-quickstart on Fri Jan 29 11:23:45 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

ADFS Authentication for Django
==============================

.. image:: https://readthedocs.org/projects/django-auth-adfs/badge/?version=latest
    :target: http://django-auth-adfs.readthedocs.org/en/latest/?badge=latest
    :alt: Documentation Status
.. image:: https://img.shields.io/pypi/v/django-auth-adfs.svg
    :target: https://pypi.python.org/pypi/django-auth-adfs
.. image:: https://travis-ci.org/jobec/django-auth-adfs.svg?branch=master
    :target: https://travis-ci.org/jobec/django-auth-adfs
.. image:: https://codecov.io/github/jobec/django-auth-adfs/coverage.svg?branch=master
    :target: https://codecov.io/github/jobec/django-auth-adfs?branch=master

A Django authentication backend for Microsoft ADFS

* Free software: BSD License
* Homepage: https://github.com/jobec/django-auth-adfs
* Documentation: http://django-auth-adfs.readthedocs.org/

Features
--------

* Let's your django users login through Microsoft ADFS by using OAuth2.
* Provides seamless single sign-on on intranet environments.
* Automatically creates users upon receiving a valid access token from ADFS.
* Adds users to groups upon signin

Contents
--------

.. toctree::
   :maxdepth: 3

   install
   configuration
   extras
   troubleshooting
   adfs_oauth
   contributing
   changelog
