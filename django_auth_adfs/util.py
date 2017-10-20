from django_auth_adfs.config import settings


def get_adfs_auth_url():
    """
    This function returns the ADFS authorization URL.

    Returns:
        str: The redirect URI

    """
    return "https://{0}{1}?response_type=code&client_id={2}&resource={3}&redirect_uri={4}".format(
        settings.SERVER,
        settings.AUTHORIZE_PATH,
        settings.CLIENT_ID,
        settings.RESOURCE,
        settings.REDIR_URI,
    )
