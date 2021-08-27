import logging

import jwt
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured, ObjectDoesNotExist, PermissionDenied

from django_auth_adfs import signals
from django_auth_adfs.config import provider_config, settings
from django_auth_adfs.exceptions import MFARequired

logger = logging.getLogger("django_auth_adfs")


class AdfsBaseBackend(ModelBackend):
    def exchange_auth_code(self, authorization_code, request):
        logger.debug("Received authorization code: %s", authorization_code)
        data = {
            'grant_type': 'authorization_code',
            'client_id': settings.CLIENT_ID,
            'redirect_uri': provider_config.redirect_uri(request),
            'code': authorization_code,
        }
        if settings.CLIENT_SECRET:
            data['client_secret'] = settings.CLIENT_SECRET

        logger.debug("Getting access token at: %s", provider_config.token_endpoint)
        response = provider_config.session.post(provider_config.token_endpoint, data, timeout=settings.TIMEOUT)
        # 200 = valid token received
        # 400 = 'something' is wrong in our request
        if response.status_code == 400:
            if response.json().get("error_description", "").startswith("AADSTS50076"):
                raise MFARequired
            logger.error("ADFS server returned an error: %s", response.json()["error_description"])
            raise PermissionDenied

        if response.status_code != 200:
            logger.error("Unexpected ADFS response: %s", response.content.decode())
            raise PermissionDenied

        adfs_response = response.json()
        return adfs_response

    def validate_access_token(self, access_token):
        for idx, key in enumerate(provider_config.signing_keys):
            try:
                # Explicitly define the verification option.
                # The list below is the default the jwt module uses.
                # Explicit is better then implicit and it protects against
                # changes in the defaults the jwt module uses.
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
                # Validate token and return claims
                return jwt.decode(
                    access_token,
                    key=key,
                    algorithms=['RS256', 'RS384', 'RS512'],
                    audience=settings.AUDIENCE,
                    issuer=provider_config.issuer,
                    options=options,
                    leeway=settings.JWT_LEEWAY
                )
            except jwt.ExpiredSignatureError as error:
                logger.info("Signature has expired: %s", error)
                raise PermissionDenied
            except jwt.DecodeError as error:
                # If it's not the last certificate in the list, skip to the next one
                if idx < len(provider_config.signing_keys) - 1:
                    continue
                else:
                    logger.info('Error decoding signature: %s', error)
                    raise PermissionDenied
            except jwt.InvalidTokenError as error:
                logger.info(str(error))
                raise PermissionDenied

    def process_access_token(self, access_token, adfs_response=None):
        if not access_token:
            raise PermissionDenied

        logger.debug("Received access token: %s", access_token)
        claims = self.validate_access_token(access_token)
        if (
            settings.BLOCK_GUEST_USERS
            and claims.get('tid')
            != settings.TENANT_ID
        ):
            logger.info('Guest user denied')
            raise PermissionDenied
        if not claims:
            raise PermissionDenied

        user = self.create_user(claims)
        self.update_user_attributes(user, claims)
        self.update_user_groups(user, claims)
        self.update_user_flags(user, claims)

        signals.post_authenticate.send(
            sender=self,
            user=user,
            claims=claims,
            adfs_response=adfs_response
        )

        user.full_clean()
        user.save()
        return user

    def create_user(self, claims):
        """
        Create the user if it doesn't exist yet

        Args:
            claims (dict): claims from the access token

        Returns:
            django.contrib.auth.models.User: A Django user
        """
        # Create the user
        username_claim = settings.USERNAME_CLAIM
        guest_username_claim = settings.GUEST_USERNAME_CLAIM
        usermodel = get_user_model()

        if (
            guest_username_claim
            and not claims.get(username_claim)
            and not settings.BLOCK_GUEST_USERS
            and claims.get('tid') != settings.TENANT_ID
        ):
            username_claim = guest_username_claim

        if not claims.get(username_claim):
            logger.error("User claim's doesn't have the claim '%s' in his claims: %s" %
                         (username_claim, claims))
            raise PermissionDenied

        userdata = {usermodel.USERNAME_FIELD: claims[username_claim]}

        try:
            user = usermodel.objects.get(**userdata)
        except usermodel.DoesNotExist:
            if settings.CREATE_NEW_USERS:
                user = usermodel.objects.create(**userdata)
                logger.debug("User '%s' has been created.", claims[username_claim])
            else:
                logger.debug("User '%s' doesn't exist and creating users is disabled.", claims[username_claim])
                raise PermissionDenied
        if not user.password:
            user.set_unusable_password()
        return user

    def update_user_attributes(self, user, claims):
        """
        Updates user attributes based on the CLAIM_MAPPING setting.

        Args:
            user (django.contrib.auth.models.User): User model instance
            claims (dict): claims from the access token
        """

        required_fields = [field.name for field in user._meta.fields if field.blank is False]

        for field, claim in settings.CLAIM_MAPPING.items():
            if hasattr(user, field):
                if claim in claims:
                    setattr(user, field, claims[claim])
                    logger.debug("Attribute '%s' for user '%s' was set to '%s'.", field, user, claims[claim])
                else:
                    if field in required_fields:
                        msg = "Claim not found in access token: '{}'. Check ADFS claims mapping."
                        raise ImproperlyConfigured(msg.format(claim))
                    else:
                        logger.warning("Claim '%s' for user field '%s' was not found in "
                                       "the access token for user '%s'. "
                                       "Field is not required and will be left empty", claim, field, user)
            else:
                msg = "User model has no field named '{}'. Check ADFS claims mapping."
                raise ImproperlyConfigured(msg.format(field))

    def update_user_groups(self, user, claims):
        """
        Updates user group memberships based on the GROUPS_CLAIM setting.

        Args:
            user (django.contrib.auth.models.User): User model instance
            claims (dict): Claims from the access token
        """
        if settings.GROUPS_CLAIM is not None:
            # Update the user's group memberships
            django_groups = [group.name for group in user.groups.all()]

            if settings.GROUPS_CLAIM in claims:
                claim_groups = claims[settings.GROUPS_CLAIM]
                if not isinstance(claim_groups, list):
                    claim_groups = [claim_groups, ]
            else:
                logger.debug("The configured groups claim '%s' was not found in the access token",
                             settings.GROUPS_CLAIM)
                claim_groups = []
            if sorted(claim_groups) != sorted(django_groups):
                existing_groups = list(Group.objects.filter(name__in=claim_groups).iterator())
                existing_group_names = frozenset(group.name for group in existing_groups)
                new_groups = []
                if settings.MIRROR_GROUPS:
                    new_groups = [
                        Group.objects.get_or_create(name=name)[0]
                        for name in claim_groups
                        if name not in existing_group_names
                    ]
                else:
                    for name in claim_groups:
                        if name not in existing_group_names:
                            try:
                                group = Group.objects.get(name=name)
                                new_groups.append(group)
                            except ObjectDoesNotExist:
                                pass
                user.groups.set(existing_groups + new_groups)

    def update_user_flags(self, user, claims):
        """
        Updates user boolean attributes based on the BOOLEAN_CLAIM_MAPPING setting.

        Args:
            user (django.contrib.auth.models.User): User model instance
            claims (dict): Claims from the access token
        """
        if settings.GROUPS_CLAIM is not None:
            if settings.GROUPS_CLAIM in claims:
                access_token_groups = claims[settings.GROUPS_CLAIM]
                if not isinstance(access_token_groups, list):
                    access_token_groups = [access_token_groups, ]
            else:
                logger.debug("The configured group claim was not found in the access token")
                access_token_groups = []

            for flag, group in settings.GROUP_TO_FLAG_MAPPING.items():
                if hasattr(user, flag):
                    if not isinstance(group, list):
                        group = [group]

                    if any(group_list_item in access_token_groups for group_list_item in group):
                        value = True
                    else:
                        value = False
                    setattr(user, flag, value)
                    logger.debug("Attribute '%s' for user '%s' was set to '%s'.", flag, user, value)
                else:
                    msg = "User model has no field named '{}'. Check ADFS boolean claims mapping."
                    raise ImproperlyConfigured(msg.format(flag))

        for field, claim in settings.BOOLEAN_CLAIM_MAPPING.items():
            if hasattr(user, field):
                bool_val = False
                if claim in claims and str(claims[claim]).lower() in ['y', 'yes', 't', 'true', 'on', '1']:
                    bool_val = True
                setattr(user, field, bool_val)
                logger.debug("Attribute '%s' for user '%s' was set to '%s'.", field, user, bool_val)
            else:
                msg = "User model has no field named '{}'. Check ADFS boolean claims mapping."
                raise ImproperlyConfigured(msg.format(field))


class AdfsAuthCodeBackend(AdfsBaseBackend):
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

        adfs_response = self.exchange_auth_code(authorization_code, request)
        access_token = adfs_response["access_token"]
        user = self.process_access_token(access_token, adfs_response)
        return user


class AdfsAccessTokenBackend(AdfsBaseBackend):
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
        user = self.process_access_token(access_token)
        return user


class AdfsBackend(AdfsAuthCodeBackend):
    """ Backwards compatible class name """
    pass
