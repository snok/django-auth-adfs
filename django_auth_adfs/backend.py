import jwt
import logging
import requests
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.x509 import load_pem_x509_certificate
from datetime import datetime, timedelta
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured, PermissionDenied, ObjectDoesNotExist
from os.path import isfile
from pprint import pformat
from requests import post
from xml.etree import ElementTree

from django_auth_adfs.config import settings
from django_auth_adfs.util import get_redirect_uri

logger = logging.getLogger(__name__)


class AdfsBackend(ModelBackend):
    """
    Authentication backend to allow authenticating users against a
    Microsoft ADFS server.
    It's based on the ``RemoteUserBackend`` from Django.
    """
    # Globally cache keys because Django instantiates our class on every
    # authentication. Loading keys every time would waste resources.
    _public_keys = []
    _key_age = None

    def __init__(self):
        if not settings.SIGNING_CERT:
            raise ImproperlyConfigured("ADFS token signing certificate not set")

        cert_exp_time = datetime.now() - timedelta(hours=settings.CERT_MAX_AGE)

        if len(self.__class__._public_keys) < 1 or self.__class__._key_age < cert_exp_time:
            if settings.SIGNING_CERT is True:
                self._autoload()
            elif isfile(settings.SIGNING_CERT):
                self._load_from_file(settings.SIGNING_CERT)
            else:
                self._load_from_string(settings.SIGNING_CERT)

    @classmethod
    def _autoload(cls):
        """
        Autoloads certificates from the ADFS meta data file.
        """
        # Fetch metadata file from ADFS server
        metadata_url = "https://" + settings.SERVER + "/FederationMetadata/2007-06/FederationMetadata.xml"
        logger.info("Retrieving ADFS metadata file from {}".format(metadata_url))
        response = requests.get(metadata_url, verify=settings.CA_BUNDLE, timeout=10)
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            logger.error("Could not load ADFS signing certificates from federation meta data")
            if not isinstance(cls._public_keys, list) or len(cls._public_keys) == 0:
                raise

        # Extract token signing certificates
        xml_tree = ElementTree.fromstring(response.content)
        cert_nodes = xml_tree.findall(
            "./{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor"
            "[@{http://www.w3.org/2001/XMLSchema-instance}type='fed:SecurityTokenServiceType']"
            "/{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor[@use='signing']"
            "/{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
            "/{http://www.w3.org/2000/09/xmldsig#}X509Data"
            "/{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
        if len(cert_nodes) < 1:
            if isinstance(cls._public_keys, list) and len(cls._public_keys) > 0:
                logger.error("No singing certificates found in ADFS meta data file, keeping already cached keys.")
                return
            else:
                raise Exception("No singing certificates found in ADFS meta data file")

        cls._reset_keys()

        # Load all found certificates
        for node in cert_nodes:
            # Convert BASE64 encoded certificate into proper PEM format
            # Some OpenSSL versions seem to fail when the certificate is not
            # split in 64 character lines
            certificate = ["-----BEGIN CERTIFICATE-----"]
            no_of_slices = int(len(node.text) / 64)
            for i in range(0, no_of_slices + 1):
                certificate.append(node.text[i * 64:(i + 1) * 64])
            certificate.append("-----END CERTIFICATE-----")
            certificate = "\n".join(certificate)
            cls._load_from_string(certificate)

    @classmethod
    def _load_from_file(cls, file):
        """
        Load a certificate from a Base64 PEM encoded file.

        Args:
            file (str): Valid path to a certificate file
        """
        cls._reset_keys()
        with open(file, 'r') as file:
            certificate = file.read()
        cls._load_from_string(certificate)

    @classmethod
    def _load_from_string(cls, certificate):
        """
        Load a certificate from a string.

        Args:
            certificate (str): A base64 PEM encoded certificate
        """
        certificate = certificate.encode()
        try:
            cert_obj = load_pem_x509_certificate(certificate, backend)
            cls._public_keys.append(cert_obj.public_key())
            cls._key_age = datetime.now()
        except ValueError:
            raise ImproperlyConfigured("Invalid ADFS token signing certificate")

    @classmethod
    def _reset_keys(cls):
        """
        Remove all cached keys from the class.
        """
        cls._public_keys = []

    def authenticate(self, request=None, authorization_code=None):
        # If there's no token or code, we pass control to the next authentication backend
        if authorization_code is None or authorization_code == '':
            logger.debug("django_auth_adfs was called but no authorization code was received")
            return

        if settings.REDIR_URI is None:
            raise ImproperlyConfigured("ADFS Redirect URI is not configured")

        token_url = "https://{0}{1}".format(settings.SERVER, settings.TOKEN_PATH)
        data = {
            'grant_type': 'authorization_code',
            'client_id': settings.CLIENT_ID,
            'redirect_uri': get_redirect_uri(hostname=request.get_host() if request else None),
            'code': authorization_code,
        }
        logger.debug("Authorization code received. Fetching access token.")
        logger.debug(":: token URL: " + token_url)
        logger.debug(":: authorization code: " + authorization_code)
        response = post(token_url, data, verify=settings.CA_BUNDLE)

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
        logger.debug("Received access token: " + access_token)

        payload = None

        for idx, key in enumerate(self.__class__._public_keys):
            try:
                # Explicitly define the verification option.
                # The list below is the default the jwt module uses.
                # Explicit is better then implicit and it protects against
                # changes is the defaults the jwt module uses.
                options = {
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_nbf': True,
                    'verify_iat': True,
                    'verify_aud': (True if settings.AUDIENCE else False),
                    'verify_iss': (True if settings.ISSUER else False),
                    'require_exp': False,
                    'require_iat': False,
                    'require_nbf': False
                }
                # Validate token and extract payload
                payload = jwt.decode(
                    access_token,
                    key=key,
                    verify=True,
                    audience=settings.AUDIENCE,
                    issuer=settings.ISSUER,
                    options=options,
                )
                # Don't try next key if this one is valid
                break
            except jwt.ExpiredSignature as error:
                logger.info("Signature has expired: %s" % error)
                raise PermissionDenied
            except jwt.DecodeError as error:
                # If it's not the last certificate in the list, skip to the next one
                if idx < len(self.__class__._public_keys) - 1:
                    continue
                else:
                    logger.info('Error decoding signature: %s' % error)
                    raise PermissionDenied
            except jwt.InvalidTokenError as error:
                logger.info(str(error))
                raise PermissionDenied

        if not payload:
            logger.error("JWT payload empty, cannot authenticate the request")
            raise PermissionDenied

        logger.debug("JWT payload:\n"+pformat(payload))

        user = self.create_user(payload)
        self.update_user_attributes(user, payload)
        self.update_user_groups(user, payload)
        self.update_user_flags(user, payload)
        user.save()

        return user

    def create_user(self, payload):
        # Create the user
        username_claim = settings.USERNAME_CLAIM
        usermodel = get_user_model()
        user, created = usermodel.objects.get_or_create(**{
            usermodel.USERNAME_FIELD: payload[username_claim]
        })
        if created:
            logging.debug('User "{0}" has been created.'.format(username_claim))

        return user

    def update_user_attributes(self, user, payload):
        """
        Updates user attributes based on the CLAIM_MAPPING setting.

        Args:
            user (django.contrib.auth.models.User): User model instance
            payload (dict): decoded JSON web token
        """
        for field, claim in settings.CLAIM_MAPPING.items():
            if hasattr(user, field):
                if claim in payload:
                    setattr(user, field, payload[claim])
                else:
                    msg = "Claim not found in payload: '{0}'. Check ADFS claims mapping."
                    raise ImproperlyConfigured(msg.format(claim))
            else:
                msg = "User model has no field named '{0}'. Check ADFS claims mapping."
                raise ImproperlyConfigured(msg.format(field))

    def update_user_groups(self, user, payload):
        """
        Updates user group memberships based on the GROUP_CLAIM setting.

        Args:
            user (django.contrib.auth.models.User): User model instance
            payload (dict): decoded JSON web token
        """
        if settings.GROUP_CLAIM is not None:
            # Update the user's group memberships
            django_groups = [group.name for group in user.groups.all()]

            if settings.GROUP_CLAIM in payload:
                claim_groups = payload[settings.GROUP_CLAIM]
                if not isinstance(claim_groups, list):
                    claim_groups = [claim_groups, ]
            else:
                logger.debug("The configured group claim was not found in the payload")
                claim_groups = []

            # Make a diff of the user's groups.
            # Removing a user from all groups and then re-add them would cause
            # the autoincrement value for the database table storing the
            # user-to-group mappings to increment for no reason.
            groups_to_remove = [group for group in django_groups if group not in claim_groups]
            groups_to_add = [group for group in claim_groups if group not in django_groups]

            # Loop through the groups in the group claim and
            # add the user to these groups as needed.
            for group_name in groups_to_remove:
                group = Group.objects.get(name=group_name)
                user.groups.remove(group)
                logger.debug('User removed from group "{0}"'.format(group_name))

            for group_name in groups_to_add:
                try:
                    group = Group.objects.get(name=group_name)
                    user.groups.add(group)
                    logger.debug('User added to group "{0}"'.format(group_name))
                except ObjectDoesNotExist:
                    # Silently fail for non-existing groups.
                    pass

    def update_user_flags(self, user, payload):
        """
        Updates user boolean attributes based on the BOOLEAN_CLAIM_MAPPING setting.

        Args:
            user (django.contrib.auth.models.User): User model instance
            payload (dict): decoded JSON web token
        """
        for field, claim in settings.BOOLEAN_CLAIM_MAPPING.items():
            if hasattr(user, field):
                bool_val = False
                if claim in payload and str(payload[claim]).lower() in ['y', 'yes', 't', 'true', 'on', '1']:
                    bool_val = True
                setattr(user, field, bool_val)
            else:
                msg = "User model has no field named '{0}'. Check ADFS boolean claims mapping."
                raise ImproperlyConfigured(msg.format(field))
