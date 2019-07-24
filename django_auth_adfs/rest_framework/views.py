from __future__ import absolute_import

from rest_framework import exceptions, status
from rest_framework.views import APIView
from rest_framework.response import Response

from django_auth_adfs.adfs import exchange_auth_code, exchange_refresh_token
from django_auth_adfs.config import settings as adfs_settings, provider_config

from requests import HTTPError


class OAuth2CallbackAPIView(APIView):
    authentication_classes = []

    def get(self, request):
        """
        Handles the redirect from ADFS to our site.
        The passed authorization code and login is already handled by the authentication class.
        Args:
            request (rest_framework.request.Request): A DRF Request object
        """
        authorization_code = request.GET.get('code')
        if not authorization_code:
            raise exceptions.APIException(
                code=status.HTTP_400_BAD_REQUEST,
                detail='code must be supplied as a query parameter'
            )

        try:
            adfs_response = exchange_auth_code(authorization_code, request)
        except HTTPError:
            raise exceptions.APIException(
                detail='The authentication service is not available'
            )

        return Response(
            status=status.HTTP_200_OK,
            data={
                'token_type': adfs_response['token_type'],
                'refresh_token_expires_in': adfs_response['refresh_token_expires_in'],
                'refresh_token': adfs_response['refresh_token'],
                'expires_in': adfs_response['expires_in'],
                'id_token': adfs_response['id_token'],
                'access_token': adfs_response['access_token'],
            }
        )


class OAuth2RefreshTokenAPIView(APIView):
    authentication_classes = []

    def get(self, request):
        """
        Handles the token refresh for ADFS.
        The passed refresh token is used to acquire a new access token.
        Args:
            request (rest_framework.request.Request): A DRF Request object
        """
        # If loaded data is too old, reload it again
        provider_config.load_config()
        refresh_token = request.GET.get('token')

        data = {
            'grant_type': 'refresh_token',
            'client_id': adfs_settings.CLIENT_ID,
            'refresh_token': refresh_token,
        }

        try:
            adfs_response = exchange_refresh_token(refresh_token, request)
        except HTTPError:
            raise exceptions.APIException(
                detail='The authentication service is not available'
            )

        return Response(
            status=status.HTTP_200_OK,
            data={
                'token_type': adfs_response['token_type'],
                'refresh_token_expires_in': adfs_response['refresh_token_expires_in'],
                'refresh_token': adfs_response['refresh_token'],
                'expires_in': adfs_response['expires_in'],
                'access_token': adfs_response['access_token'],
            }
        )
