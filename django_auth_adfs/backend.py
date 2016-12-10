from os.path import isfile

import jwt
import logging
from pprint import pformat
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.x509 import load_pem_x509_certificate
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured, PermissionDenied, ObjectDoesNotExist
from requests import post

from .config import settings

logger = logging.getLogger(__name__)


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
            try:
                cert_obj = load_pem_x509_certificate(certificate, backend)
                backend.activate_builtin_random()
                self._public_key = cert_obj.public_key()
            except ValueError:
                raise ImproperlyConfigured("Invalid value for ADFS token signing certificate")
        else:
            raise ImproperlyConfigured("ADFS token signing certificate not set")

    def authenticate(self, authorization_code=None):
        # If there's no token or code, we pass controll to the next authentication backend
        if authorization_code is None or authorization_code == '':
            return

        if settings.ADFS_REDIR_URI is None:
            raise ImproperlyConfigured("ADFS Redirect URI is not configured")

        token_url = "https://{0}{1}".format(settings.ADFS_SERVER, settings.ADFS_TOKEN_PATH)
        data = {
            'grant_type': 'authorization_code',
            'client_id': settings.ADFS_CLIENT_ID,
            'redirect_uri': settings.ADFS_REDIR_URI,
            'code': authorization_code,
        }
        logger.debug("Authorization code received. Fetching access token.")
        logger.debug(":: token URL: "+token_url)
        logger.debug(":: authorization code: "+authorization_code)
        response = post(token_url, data, verify=settings.ADFS_CA_BUNDLE)

        # 200 = valid token received
        # 400 = 'something' is wrong in our request
        if response.status_code == 400:
            logger.error("ADFS server returned an error: " + response.json()["error_description"])
            raise PermissionDenied

        if response.status_code != 200:
            logger.error("Unexpected ADFS response: " + response.content.decode())
            raise PermissionDenied

        json_response = response.json()
        access_token = json_response["access_token"]
        logger.debug("Received access token: "+access_token)

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
                'verify_aud': (True if settings.ADFS_AUDIENCE else False),
                'verify_iss': (True if settings.ADFS_ISSUER else False),
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
        except (jwt.ExpiredSignature, jwt.DecodeError, jwt.InvalidTokenError) as error:
            logger.info(str(error))
            raise PermissionDenied

        logger.debug("JWT payload:\n"+pformat(payload))
        username_claim = settings.ADFS_USERNAME_CLAIM

        # Create the user
        usermodel = get_user_model()
        user, created = usermodel.objects.get_or_create(**{
            usermodel.USERNAME_FIELD: payload[username_claim]
        })

        if created:
            logging.debug('User "{0}" has been created.'.format(username_claim))

        self.update_users_attributes(user, payload)
        self.update_users_groups(user, payload)

        user.save()
        return user

    def update_users_attributes(self, user, payload):
        """
        Updates users attributes based on ADFS_CLAIM_MAPPING set up in
        settings.

        Args:
            user (django.contrib.auth.models.User): User model instance
            payload (dictionary): decoded JSON web token
        """
        for field, claim in settings.ADFS_CLAIM_MAPPING.items():
            if hasattr(user, field):
                if claim in payload:
                    setattr(user, field, payload[claim])
                else:
                    msg = "Claim not found in payload: '{0}'. Check ADFS claims mapping."
                    raise ImproperlyConfigured(msg.format(claim))
            else:
                msg = "User model has no field named '{0}'. Check ADFS claims mapping."
                raise ImproperlyConfigured(msg.format(field))

    def update_users_groups(self, user, payload):
        """
        Updates users group memberships based on ADFS_GROUP_CLAIM set up in
        settings.

        Args:
            user (django.contrib.auth.models.User): User model instance
            payload (dictionary): decoded JSON web token
        """
        user.groups.clear()

        logging.debug('User "{0}" has been removed from all groups.'
                      .format(getattr(user, user.USERNAME_FIELD)))

        if settings.ADFS_GROUP_CLAIM is not None:
            if settings.ADFS_GROUP_CLAIM in payload:
                user_groups = payload[settings.ADFS_GROUP_CLAIM]
                if not isinstance(user_groups, list):
                    user_groups = [user_groups, ]
                for group_name in user_groups:
                    try:
                        group = Group.objects.get(name=group_name)
                        user.groups.add(group)
                        logger.debug('User added to group "{0}"'.format(group_name))
                    except ObjectDoesNotExist:
                        pass
            else:
                logger.debug("The configured group claim was not found in the payload")
