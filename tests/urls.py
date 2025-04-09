from django.urls import include, re_path, path

from .views import page

urlpatterns = [
    re_path(r'^oauth2/', include('django_auth_adfs.urls')),
    re_path(r'^oauth2/', include('django_auth_adfs.drf_urls')),
    path("page", page),
]
