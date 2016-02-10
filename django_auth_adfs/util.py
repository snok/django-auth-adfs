from .config import Settings
from django.core.urlresolvers import reverse

settings = Settings()


def get_redir_uri(request):
    """
    This function returns the ADFS redirect URI.

    If it's configured in the optional setting ``ADFS_REDIR_URI``, that value is returned.
    Else it's determined based on the request object and the reverse URL lookup of ``auth_adfs:login``

    Args:
        request (django.http.request.HttpRequest): A Django Request object

    Returns:
        str: The redirect URI

    """
    if settings.ADFS_REDIR_URI:
        return settings.ADFS_REDIR_URI
    else:
        return "{0}://{1}{2}".format(request.scheme, request.META['HTTP_HOST'], reverse("auth_adfs:login"))


def get_adfs_auth_url(request):
    """
    This function returns the ADFS authorization URL.

    Args:
        request (django.http.request.HttpRequest): A Django Request object

    Returns:
        str: The redirect URI

    """
    redir_url = get_redir_uri(request)
    return "https://{0}{1}?response_type=code&client_id={2}&resource={3}&redirect_uri={4}".format(
        settings.ADFS_SERVER,
        settings.ADFS_AUTHORIZE_PATH,
        settings.ADFS_CLIENT_ID,
        settings.ADFS_RESOURCE,
        redir_url,
    )
