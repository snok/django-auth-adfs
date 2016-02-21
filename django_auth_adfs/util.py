from .config import settings


def get_adfs_auth_url():
    """
    This function returns the ADFS authorization URL.

    Returns:
        str: The redirect URI

    """
    return "https://{0}{1}?response_type=code&client_id={2}&resource={3}&redirect_uri={4}".format(
        settings.ADFS_SERVER,
        settings.ADFS_AUTHORIZE_PATH,
        settings.ADFS_CLIENT_ID,
        settings.ADFS_RESOURCE,
        settings.ADFS_REDIR_URI,
    )
