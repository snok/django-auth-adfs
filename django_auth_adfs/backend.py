from os.path import isfile

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured, PermissionDenied, ObjectDoesNotExist
from requests import post

from .config import settings


class AdfsBackend(ModelBackend):
    """
    This backend is based on the ``RemoteUserBackend`` from Django.
    """

    def __init__(self):
        if settings.ADFS_SIGNING_CERT:
            certificate = settings.ADFS_SIGNING_CERT
            if isfile(certificate):
                with open(certificate, 'r') as file:
                    certificate = file.read()
            if isinstance(certificate, str):
                certificate = certificate.encode()
            cert_obj = load_pem_x509_certificate(certificate, default_backend())
            self._public_key = cert_obj.public_key()
        else:
            raise ImproperlyConfigured("ADFS token signing certificate not set")

    def authenticate(self, access_token=None, authorization_code=None, redir_uri=None):
        # If there's no token or code, we pass controll to the next authentication backend
        if not access_token and not authorization_code:
            return

        if access_token and not (redir_uri or settings.ADFS_REDIR_URI):
            raise ValueError("Redirect URI not specified")

        # If we get passed an authorization code, we first have to fetch the access token from ADFS
        if authorization_code:
            token_url = "https://{0}{1}".format(settings.ADFS_SERVER, settings.ADFS_TOKEN_PATH)
            if not redir_uri:
                redir_uri = settings.ADFS_REDIR_URI
            data = {
                'grant_type': 'authorization_code',
                'client_id': settings.ADFS_CLIENT_ID,
                'redirect_uri': redir_uri,
                'code': authorization_code,
            }
            response = post(token_url, data, verify=settings.ADFS_CA_BUNDLE)

            # 200 = valid token received
            # 400 = 'something' is wrong in our request
            if response.status_code == 400:
                raise PermissionDenied(response.json()["error_description"])

            if response.status_code != 200:
                raise PermissionDenied("Unexpected response from ADFS")

            json_response = response.json()
            access_token = json_response["access_token"]

        try:
            # Explicitly define the verification option
            # The list below is the default the jwt module uses.
            # Explicit is better then implicit and it protects against
            # changes is the defaults the jwt module uses
            options = {
                'verify_signature': True,
                'verify_exp': True,
                'verify_nbf': True,
                'verify_iat': True,
                'verify_aud': True,
                'verify_iss': True,
                'require_exp': False,
                'require_iat': False,
                'require_nbf': False
            }

            # Validate token and extract payload
            payload = jwt.decode(
                access_token,
                key=self._public_key,
                verify=True,
                audience=settings.ADFS_AUDIENCE,
                issuer=settings.ADFS_ISSUER,
                options=options,
            )
        except jwt.ExpiredSignature:
            raise PermissionDenied('Signature has expired.')
        except jwt.DecodeError:
            raise PermissionDenied('Error decoding signature.')
        except jwt.InvalidTokenError:
            raise PermissionDenied("Invalid token.")

        username_claim = settings.ADFS_USERNAME_CLAIM

        # Create the user
        usermodel = get_user_model()
        user, created = usermodel.objects.get_or_create(**{
            usermodel.USERNAME_FIELD: payload[username_claim]
        })

        # Update the user's attributes
        for field, attr in settings.ADFS_CLAIM_MAPPING.items():
            try:
                setattr(user, field, payload[attr])
            except AttributeError:
                pass

        # Update the user's group memberships
        user.groups.clear()
        try:
            user_groups = payload[settings.ADFS_GROUP_CLAIM]
            if isinstance(user_groups, str):
                user_groups = [user_groups, ]
            for group_name in user_groups:
                try:
                    group = Group.objects.get(name=group_name)
                    user.groups.add(group)
                except ObjectDoesNotExist:
                    pass
        except KeyError:
            pass

        user.save()
        return user
