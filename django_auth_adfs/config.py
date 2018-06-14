import base64
import logging
import warnings
from datetime import datetime, timedelta
from xml.etree import ElementTree

import requests
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.x509 import load_der_x509_certificate
from django.conf import settings as django_settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.exceptions import ImproperlyConfigured
from django.http import QueryDict

try:
    from django.urls import reverse
except ImportError:  # Django < 1.10
    from django.core.urlresolvers import reverse

logger = logging.getLogger("django_auth_adfs")

AZURE_AD_SERVER = "login.microsoftonline.com"


class Settings(object):
    def __init__(self):
        # Set defaults
        self.SERVER = None  # Required
        self.TENANT_ID = None  # Required
        self.CLIENT_ID = None  # Required
        self.AUDIENCE = None  # Required
        self.RESOURCE = None  # Required
        self.CONFIG_RELOAD_INTERVAL = 24  # hours
        self.CA_BUNDLE = True
        self.USERNAME_CLAIM = "winaccountname"
        self.GROUP_CLAIM = "group"
        self.CLAIM_MAPPING = {}
        self.GROUP_FLAG_MAPPING = {}
        self.BOOLEAN_CLAIM_MAPPING = {}
        self.LOGIN_EXEMPT_URLS = []
        self.MIRROR_GROUPS = False

        required_settings = [
            "CLIENT_ID",
            "AUDIENCE",
            "RESOURCE",
            "USERNAME_CLAIM",
        ]

        deprecated_settings = {
            "AUTHORIZE_PATH": "This setting is automatically loaded from ADFS.",
            "LOGIN_REDIRECT_URL": "Instead use the standard Django settings with the same name.",
            "ISSUER": "This setting is automatically loaded from ADFS.",
            "REDIR_URI": "This setting is automatically determined based on the URL configuration of Django.",
            "SIGNING_CERT": "The token signing certificates are automatically loaded from ADFS.",
            "TOKEN_PATH": "This setting is automatically loaded from ADFS.",
        }

        if not hasattr(django_settings, "AUTH_ADFS"):
            msg = "The configuration directive 'AUTH_ADFS' was not found in your Django settings"
            raise ImproperlyConfigured(msg)

        # Handle deprecated settings
        for setting, message in deprecated_settings.items():
            if setting in django_settings.AUTH_ADFS:
                warnings.warn('Setting {} is deprecated and has is ignored. {}'.format(setting, message),
                              DeprecationWarning)
                del django_settings.AUTH_ADFS[setting]
        if "CERT_MAX_AGE" in django_settings.AUTH_ADFS:
            django_settings.AUTH_ADFS["CONFIG_RELOAD_INTERVAL"] = django_settings.AUTH_ADFS["CERT_MAX_AGE"]
            warnings.warn('Setting CERT_MAX_AGE has been renamed to CONFIG_RELOAD_INTERVAL. The value was copied.',
                          DeprecationWarning)
            del django_settings.AUTH_ADFS["CERT_MAX_AGE"]

        # Overwrite defaults with user settings
        for setting, value in django_settings.AUTH_ADFS.items():
            if hasattr(self, setting):
                setattr(self, setting, value)
            else:
                msg = "'{0}' is not a valid configuration directive"
                raise ImproperlyConfigured(msg.format(setting))

        # Validate required settings
        for setting in required_settings:
            if not getattr(self, setting):
                msg = "django_auth_adfs setting '{0}' has not been set".format(setting)
                raise ImproperlyConfigured(msg)

        if (not self.TENANT_ID and not self.SERVER) or (self.TENANT_ID and self.SERVER):
            msg = "Exactly one of the settings TENANT_ID or SERVER must be set"
            raise ImproperlyConfigured(msg)

        if self.TENANT_ID is not None:
            # Is a tenant ID was set, switch to Azure AD mode
            self.SERVER = AZURE_AD_SERVER
            self.USERNAME_CLAIM = "upn"
            self.GROUP_CLAIM = "groups"
            self.CLAIM_MAPPING = {"first_name": "given_name",
                                  "last_name": "family_name",
                                  "email": "email"}
        else:
            # For local setups, the tenant ID is set to adfs
            # Allowing for easy URL building
            self.TENANT_ID = "adfs"


class ProviderConfig(object):
    def __init__(self):
        self._config_timestamp = None

        self.authorization_endpoint = None
        self.signing_keys = None
        self.token_endpoint = None
        self.end_session_endpoint = None
        self.issuer = None

    def load_config(self):
        # If loaded data is too old, reload it again
        refresh_time = datetime.now() - timedelta(hours=settings.CONFIG_RELOAD_INTERVAL)
        if self._config_timestamp is None or self._config_timestamp < refresh_time:
            logger.debug("Loading django_auth_adfs ID Provider configuration.")
            try:
                loaded = self._load_openid_config()
            except requests.HTTPError:
                loaded = self._load_federation_metadata()

            if not loaded:
                if self._config_timestamp is None:
                    msg = "Could not load any data from ADFS server. "\
                          "Authentication against ADFS not be possible. "\
                          "Verify your settings and the connection with the ADFS server."
                    logger.critical(msg)
                    raise RuntimeError(msg)
                else:
                    # We got data from the previous time. Log a message, but don't abort.
                    logger.warning("Could not load any data from ADFS server. Keeping previous configurations")
            self._config_timestamp = datetime.now()

            logger.info("django_auth_adfs loaded settings from ADFS server.")
            logger.info("authorization endpoint: " + self.authorization_endpoint)
            logger.info("token endpoint:         " + self.token_endpoint)
            logger.info("end session endpoint:   " + self.end_session_endpoint)
            logger.info("issuer:                 " + self.issuer)

    def _load_openid_config(self):
        config_url = "https://{}/{}/.well-known/openid-configuration".format(
            settings.SERVER, settings.TENANT_ID
        )

        logger.info("Trying to get OpenID Connect config from {}".format(config_url))
        response = requests.get(config_url, verify=settings.CA_BUNDLE, timeout=10)
        response.raise_for_status()
        openid_cfg = response.json()

        response = requests.get(openid_cfg["jwks_uri"], verify=settings.CA_BUNDLE, timeout=10)
        try:
            response.raise_for_status()
        except requests.HTTPError:
            return False
        signing_certificates = [x["x5c"][0] for x in response.json()["keys"] if x.get("use", "sig") == "sig"]
        #                       ^^^
        # https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41#section-4.7
        # The PKIX certificate containing the key value MUST be the first certificate

        self._load_keys(signing_certificates)
        self.authorization_endpoint = openid_cfg["authorization_endpoint"]
        self.token_endpoint = openid_cfg["token_endpoint"]
        self.end_session_endpoint = openid_cfg["end_session_endpoint"]
        if settings.TENANT_ID is not 'adfs':
            self.issuer = openid_cfg["issuer"]
        else:
            self.issuer = openid_cfg["access_token_issuer"]
        return True

    def _load_federation_metadata(self):
        server_url = "https://{}".format(settings.SERVER)
        base_url = "{}/{}".format(server_url, settings.TENANT_ID)
        if settings.TENANT_ID == "adfs":
            adfs_config_url = server_url + "/FederationMetadata/2007-06/FederationMetadata.xml"
        else:
            adfs_config_url = base_url + "/FederationMetadata/2007-06/FederationMetadata.xml"

        logger.info("Trying to get ADFS Metadata file {}".format(adfs_config_url))
        response = requests.get(adfs_config_url, verify=settings.CA_BUNDLE, timeout=10)
        response.raise_for_status()
        xml_tree = ElementTree.fromstring(response.content)

        # Extract token signing certificates
        cert_nodes = xml_tree.findall(
            "./{urn:oasis:names:tc:SAML:2.0:metadata}RoleDescriptor"
            "[@{http://www.w3.org/2001/XMLSchema-instance}type='fed:SecurityTokenServiceType']"
            "/{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor[@use='signing']"
            "/{http://www.w3.org/2000/09/xmldsig#}KeyInfo"
            "/{http://www.w3.org/2000/09/xmldsig#}X509Data"
            "/{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
        signing_certificates = [node.text for node in cert_nodes]

        self._load_keys(signing_certificates)
        self.issuer = xml_tree.get("entityID")
        self.authorization_endpoint = base_url + "/oauth2/authorize"
        self.token_endpoint = base_url + "/oauth2/token"
        self.end_session_endpoint = base_url + "/ls/?wa=wsignout1.0"
        return True

    def _load_keys(self, certificates):
        new_keys = []
        for cert in certificates:
            logger.debug("Loading public key from certificate: " + cert)
            cert_obj = load_der_x509_certificate(base64.b64decode(cert), backend)
            new_keys.append(cert_obj.public_key())
        self.signing_keys = new_keys

    def redirect_uri(self, request):
        self.load_config()
        return request.build_absolute_uri(reverse("django_auth_adfs:callback"))

    def build_authorization_endpoint(self, request):
        """
        This function returns the ADFS authorization URL.

        Args:
            request(django.http.request.HttpRequest): A django Request object

        Returns:
            str: The redirect URI

        """
        self.load_config()
        redirect_to = request.GET.get(REDIRECT_FIELD_NAME, None)
        if not redirect_to:
            redirect_to = django_settings.LOGIN_REDIRECT_URL
        redirect_to = base64.urlsafe_b64encode(redirect_to.encode()).decode()
        query = QueryDict(mutable=True)
        query.update({
            "response_type": "code",
            "client_id": settings.CLIENT_ID,
            "resource": settings.RESOURCE,
            "redirect_uri": self.redirect_uri(request),
            "state": redirect_to,
        })
        return "{0}?{1}".format(self.authorization_endpoint, query.urlencode())


settings = Settings()
provider_config = ProviderConfig()
