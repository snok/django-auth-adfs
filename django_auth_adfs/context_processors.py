from .config import Settings
from .util import get_adfs_auth_url

settings = Settings()


def adfs_url(request):
    """
    This context processor function makes the ADFS authorization URL available as a Django template variable

    Args:
        request (django.http.request.HttpRequest): A Django Request object

    Returns:
        dict: A dictionary with the ADFS authorization URL
    """

    return {"ADFS_AUTH_URL": get_adfs_auth_url(request)}
