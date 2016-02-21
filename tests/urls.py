from django.conf.urls import url, include

from . import views

urlpatterns = [
    url(r'^oauth2/', include('django_auth_adfs.urls', namespace='auth_adfs')),
    url(r'^context_processor/$', views.context_processor),
]
