from django_auth_adfs.config import settings
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse


def get_redirect_uri(hostname=None):
    if isinstance(settings.REDIR_URI, (list, tuple)):
        if hostname:
            for uri in settings.REDIR_URI:
                tmp_uri = uri if '://' in uri else 'x://%s' % uri
                parsed_uri = urlparse.urlparse(tmp_uri)
                if parsed_uri.netloc == hostname:
                    return uri
        return settings.REDIR_URI[0]

    return settings.REDIR_URI


def get_adfs_auth_url(hostname=None):
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
        get_redirect_uri(hostname),
    )
