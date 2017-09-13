from django.conf.urls import url
from . import views

app_name = "django_auth_adfs"
urlpatterns = [
    url(r'^login$', views.OAuth2View.as_view(), name='login'),
]
