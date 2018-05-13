from django_auth_adfs.util import get_adfs_auth_url
from django_auth_adfs.config import settings


def adfs_url(request):
    """
    This context processor function makes the ADFS authorization URL
    available as a Django template variable.

    Args:
        request (django.http.request.HttpRequest): A Django Request object

    Returns:
        dict: A dictionary with the ADFS authorization URL
    """

    return {"ADFS_AUTH_URL": get_adfs_auth_url(next_url=request.GET.get(settings.REDIRECT_FIELD_NAME))}
