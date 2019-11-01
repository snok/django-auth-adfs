"""mysite URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth.decorators import login_required
from django.urls import include, path
from django.views.generic.base import TemplateView

admin.site.login = login_required(admin.site.login)

urlpatterns = [
    path('', TemplateView.as_view(template_name='home.html'), name='home'),
    path('polls/', include('polls.urls')),
    path('api/', include('polls.api.urls')),

    path('admin/', admin.site.urls, name='admin'),

    # The default rest framework urls shouldn't be included
    # If we include them, we'll end up with the DRF login page,
    # instead of being redirected to the ADFS login page.
    #
    # path('api-auth/', include('rest_framework.urls')),
    #
    path('oauth2/', include('django_auth_adfs.urls')),
    # This overrides the DRF login page
    path('oauth2/', include('django_auth_adfs.drf_urls')),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
