Django Signals
================

**django-auth-adfs** uses Django `Signals <https://docs.djangoproject.com/en/stable/topics/signals/>`
to allow the application to listen for and execute custom logic at certain points in the authentication
process. Currently, the following signals are supported:

* ``post_authenticate``: sent after a user has been authenticated through either the ``AdfsAuthCodeBackend``
  or the ``AdfsAccessTokenBackend`` (and created in Django, if ``CREATE_NEW_USERS`` is enabled) and
  after all claims and groups have been mapped. The signal is sent with the user object, the claims
  dictionary, and the ADFS response as arguments for the signal handler.

To use a signal in your application:

.. code-block:: python

    from django.dispatch import receiver
    from django_auth_adfs.signals import post_authenticate


    @receiver(post_authenticate)
    def handle_post_authenticate(sender, user, claims, adfs_response, **kwargs):
        user.do_post_auth_steps(claims, adfs_response)


