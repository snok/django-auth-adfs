import logging

import requests
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import PermissionDenied

from django_auth_adfs.adfs import exchange_auth_code, process_access_token
from django_auth_adfs.config import provider_config

logger = logging.getLogger("django_auth_adfs")


class AdfsAuthCodeBackend(ModelBackend):
    """
    Authentication backend to allow authenticating users against a
    Microsoft ADFS server with an authorization code.
    """

    def authenticate(self, request=None, authorization_code=None, **kwargs):
        # If loaded data is too old, reload it again
        provider_config.load_config()

        # If there's no token or code, we pass control to the next authentication backend
        if authorization_code is None or authorization_code == '':
            logger.debug("django_auth_adfs authentication backend was called but no authorization code was received")
            return
        try:
            adfs_response = exchange_auth_code(authorization_code, request)
            access_token = adfs_response["access_token"]
            user = process_access_token(self, access_token, adfs_response)
        except (requests.HTTPError, ValueError):
            raise PermissionDenied
        return user


class AdfsAccessTokenBackend(ModelBackend):
    """
    Authentication backend to allow authenticating users against a
    Microsoft ADFS server with an access token retrieved by the client.
    """

    def authenticate(self, request=None, access_token=None, **kwargs):
        # If loaded data is too old, reload it again
        provider_config.load_config()

        # If there's no token or code, we pass control to the next authentication backend
        if access_token is None or access_token == '':
            logger.debug("django_auth_adfs authentication backend was called but no authorization code was received")
            return

        access_token = access_token.decode()
        try:
            user = process_access_token(self, access_token)
        except ValueError:
            raise PermissionDenied
        return user


class AdfsBackend(AdfsAuthCodeBackend):
    """ Backwards compatible class name """
    pass
