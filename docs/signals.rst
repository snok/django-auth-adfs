Django Signals
================

**django-auth-adfs** uses Django `Signals <https://docs.djangoproject.com/en/stable/topics/signals/>` to allow the
application to listen for and execute custom logic at certain points in the authentication process. Currently, the
following signals are supported:

* ``post_authenticate``: sent after a user has been authenticated through any subclass of ``AdfsBaseBackend``. The
  signal is sent after all other processing is done, e.g. mapping claims and groups and creating the user in Django (if
  :ref:`the CREATE_NEW_USERS setting <create_new_users_setting>` is enabled). In addition to the sender, the signal
  includes the user object, the claims dictionary, and the ADFS response as arguments for the signal handler:

  * ``sender`` (``AdfsBaseBackend``): the backend instance from which the signal was triggered.
  * ``user`` (Django user class): the user object that was authenticated.
  * ``claims`` (``dict``): the decoded access token JWT, which contains all claims sent from the identity provider.
  * ``adfs_response`` (``dict|None``): used in the ``AdfsAuthCodeBackend`` to provide the full response received from
    the server when exchanging an authorization code for an access token.

* ``adfs_claims_processed``: sent after a user has been authenticated through ``AdfsAuthCodeBackend``. The
  signal is sent after after access_token is received, e.g. extacting user email when it is not registered in Django App
  In addition to the sender, the signal includes the request object, and the claims dictionary as arguments for the signal handler:

  * ``sender`` (``AdfsAuthCodeBackend``): the backend instance from which the signal was triggered.
  * ``request`` (``WSGIRequest``): the request object.
  * ``claims`` (``dict``): the decoded access token JWT, which contains all claims sent from the identity provider.

To use a signal in your application:

.. code-block:: python

    from django.dispatch import receiver
    from django_auth_adfs.signals import post_authenticate


    @receiver(post_authenticate)
    def handle_post_authenticate(sender, user, claims, adfs_response=None, **kwargs):
        user.do_post_auth_steps(claims, adfs_response)

To get store Email id Request session:

.. code-block:: python

    from django.dispatch import receiver
    from django_auth_adfs.signals import adfs_claims_processed


    @receiver(adfs_claims_processed)
    def handle_adfs_claims(sender, request, claims, **kwargs):
        print("Signal is received")
        if request and hasattr(request, "session"):
            username_claim = settings.AUTH_ADFS['USERNAME_CLAIM']
            request.session["username_claim"] = claims[username_claim]