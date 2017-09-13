from django.conf.urls import url, include
import django
from . import views

from pkg_resources import parse_version

if parse_version(django.__version__) >= parse_version('1.9'):
    urlpatterns = [
        url(r'^oauth2/', include('django_auth_adfs.urls')),
        url(r'^context_processor/$', views.context_processor),
    ]
else:
    urlpatterns = [
        url(r'^oauth2/', include('django_auth_adfs.urls', namespace="django_auth_adfs")),
        url(r'^context_processor/$', views.context_processor),
    ]
