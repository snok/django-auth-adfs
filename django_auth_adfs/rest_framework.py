from __future__ import absolute_import

from django.contrib.auth import authenticate
from rest_framework import exceptions
from rest_framework.authentication import (
    BaseAuthentication, get_authorization_header
)


class AdfsAccessTokenAuthentication(BaseAuthentication):
    """
    ADFS access Token authentication
    """
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        """
        Returns a `User` if a correct access token has been supplied
        in the Authorization header.  Otherwise returns `None`.
        """
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != b'bearer':
            return None

        if len(auth) == 1:
            msg = 'Invalid authorization header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Invalid authorization header. Access token should not contain spaces.'
            raise exceptions.AuthenticationFailed(msg)

        # Authenticate the user
        # The AdfsAuthCodeBackend authentication backend will notice the "access_token" parameter
        # and skip the request for an access token using the authorization code
        user = authenticate(access_token=auth[1])

        if user is None:
            raise exceptions.AuthenticationFailed('Invalid access token.')

        if not user.is_active:
            raise exceptions.AuthenticationFailed('User inactive or deleted.')

        return user, auth[1]

    def authenticate_header(self, request):
        return 'Bearer realm="%s" token_type="JWT"' % self.www_authenticate_realm
