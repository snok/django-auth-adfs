import logging

import jwt
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured, ObjectDoesNotExist

from django_auth_adfs import signals
from django_auth_adfs.config import settings, provider_config

logger = logging.getLogger("django_auth_adfs")


def exchange_auth_code(authorization_code, request):
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
    response = provider_config.session.post(
        provider_config.token_endpoint,
        data,
        timeout=settings.TIMEOUT
    )

    # 200 = valid token received
    # 400 = 'something' is wrong in our request
    if response.status_code == 400:
        logger.error("ADFS server returned an error: %s", response.json()["error_description"])

    if response.status_code != 200:
        logger.error("Unexpected ADFS response: %s", response.content.decode())

    response.raise_for_status()

    adfs_response = response.json()
    return adfs_response


def validate_access_token(access_token):
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
                verify=True,
                audience=settings.AUDIENCE,
                issuer=provider_config.issuer,
                options=options,
            )
        except jwt.ExpiredSignature as error:
            logger.info("Signature has expired: %s", error)
            raise ValueError
        except jwt.DecodeError as error:
            # If it's not the last certificate in the list, skip to the next one
            if idx < len(provider_config.signing_keys) - 1:
                continue
            else:
                logger.info('Error decoding signature: %s', error)
                raise ValueError
        except jwt.InvalidTokenError as error:
            logger.info(str(error))
            raise ValueError


def process_access_token(caller, access_token, adfs_response=None):
    if not access_token:
        raise ValueError('access_token is required')

    logger.debug("Received access token: %s", access_token)
    claims = validate_access_token(access_token)
    if not claims:
        raise ValueError('No claims recieved')

    user = create_user(claims)
    update_user_attributes(user, claims)
    update_user_groups(user, claims)
    update_user_flags(user, claims)

    signals.post_authenticate.send(
        sender=caller,
        user=user,
        claims=claims,
        adfs_response=adfs_response
    )

    user.full_clean()
    user.save()
    return user


def create_user(claims):
    """
    Create the user if it doesn't exist yet

    Args:
        claims (dict): claims from the access token

    Returns:
        django.contrib.auth.models.User: A Django user
    """
    # Create the user
    username_claim = settings.USERNAME_CLAIM
    usermodel = get_user_model()
    user, created = usermodel.objects.get_or_create(**{
        usermodel.USERNAME_FIELD: claims[username_claim]
    })
    if created or not user.password:
        user.set_unusable_password()
        logger.debug("User '%s' has been created.", claims[username_claim])

    return user


def update_user_attributes(user, claims):
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
                    msg = "Claim '{}' for user field '{}' was not found in the access token for user '{}'. " \
                          "Field is not required and will be left empty"
                    logger.warning(msg.format(claim, field, user))
        else:
            msg = "User model has no field named '{}'. Check ADFS claims mapping."
            raise ImproperlyConfigured(msg.format(field))


def update_user_groups(user, claims):
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
            logger.debug(
                "The configured groups claim '%s' was not found in the access token",
                settings.GROUPS_CLAIM
            )
            claim_groups = []

        # Make a diff of the user's groups.
        # Removing a user from all groups and then re-add them would cause
        # the autoincrement value for the database table storing the
        # user-to-group mappings to increment for no reason.
        groups_to_remove = set(django_groups) - set(claim_groups)
        groups_to_add = set(claim_groups) - set(django_groups)

        # Loop through the groups in the group claim and
        # add the user to these groups as needed.
        for group_name in groups_to_remove:
            group = Group.objects.get(name=group_name)
            user.groups.remove(group)
            logger.debug("User removed from group '%s'", group_name)

        for group_name in groups_to_add:
            try:
                if settings.MIRROR_GROUPS:
                    group, _ = Group.objects.get_or_create(name=group_name)
                    logger.debug("Created group '%s'", group_name)
                else:
                    group = Group.objects.get(name=group_name)
                user.groups.add(group)
                logger.debug("User added to group '%s'", group_name)
            except ObjectDoesNotExist:
                # Silently fail for non-existing groups.
                pass


def update_user_flags(user, claims):
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
                value = bool(group in access_token_groups)
                setattr(user, flag, value)
                logger.debug("Attribute '%s' for user '%s' was set to '%s'.", user, flag, value)
            else:
                msg = "User model has no field named '{}'. Check ADFS boolean claims mapping."
                raise ImproperlyConfigured(msg.format(flag))

    for field, claim in settings.BOOLEAN_CLAIM_MAPPING.items():
        if hasattr(user, field):
            bool_val = False
            if claim in claims and str(claims[claim]).lower() in ['y', 'yes', 't', 'true', 'on', '1']:
                bool_val = True
            setattr(user, field, bool_val)
            logger.debug('Attribute "%s" for user "%s" was set to "%s".', user, field, bool_val)
        else:
            msg = "User model has no field named '{}'. Check ADFS boolean claims mapping."
            raise ImproperlyConfigured(msg.format(field))
