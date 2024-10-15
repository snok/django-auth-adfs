from django.urls import include, re_path, path

from tests.views import TestView

urlpatterns = [
    path('', TestView.as_view(), name='test'),
    re_path(r'^oauth2/', include('django_auth_adfs.urls')),
    re_path(r'^oauth2/', include('django_auth_adfs.drf_urls')),
]
