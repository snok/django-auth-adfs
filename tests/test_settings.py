import sys
from copy import deepcopy

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings
from mock import patch
from django_auth_adfs.config import django_settings

from .custom_config import Settings as CustomSettings


class ReloadModuleMixin(object):
    # force re-import and thus module re-evaluation
    def setUp(self):
        sys.modules.pop('django_auth_adfs.config', None)

    def tearDown(self):
        sys.modules.pop('django_auth_adfs.config', None)


class SettingsTests(ReloadModuleMixin, SimpleTestCase):

    def test_no_settings(self):
        from django_auth_adfs.config import Settings

        settings = deepcopy(django_settings)
        del settings.AUTH_ADFS
        with patch("django_auth_adfs.config.django_settings", settings):

            self.assertRaises(ImproperlyConfigured, Settings)

    def test_claim_mapping_overlapping_username_field(self):
        from django_auth_adfs.config import Settings

        settings = deepcopy(django_settings)
        settings.AUTH_ADFS["CLAIM_MAPPING"] = {"username": "samaccountname"}
        with patch("django_auth_adfs.config.django_settings", settings):

            self.assertRaises(ImproperlyConfigured, Settings)

    def test_tenant_and_server(self):
        from django_auth_adfs.config import Settings

        settings = deepcopy(django_settings)
        settings.AUTH_ADFS["TENEANT_ID"] = "abc"
        settings.AUTH_ADFS["server"] = "abc"
        with patch("django_auth_adfs.config.django_settings", settings):

            self.assertRaises(ImproperlyConfigured, Settings)

    def test_unknown_setting(self):
        from django_auth_adfs.config import Settings

        settings = deepcopy(django_settings)
        settings.AUTH_ADFS["dummy"] = "abc"
        with patch("django_auth_adfs.config.django_settings", settings):

            self.assertRaises(ImproperlyConfigured, Settings)

    def test_required_setting(self):
        from django_auth_adfs.config import Settings

        settings = deepcopy(django_settings)
        del settings.AUTH_ADFS["AUDIENCE"]
        with patch("django_auth_adfs.config.django_settings", settings):

            self.assertRaises(ImproperlyConfigured, Settings)


class CustomSettingsTests(ReloadModuleMixin, SimpleTestCase):

    def test_dotted_path(self):
        auth_adfs = deepcopy(django_settings).AUTH_ADFS
        auth_adfs['SETTINGS_CLASS'] = 'tests.custom_config.Settings'

        with override_settings(AUTH_ADFS=auth_adfs):
            from django_auth_adfs.config import settings

            self.assertIsInstance(settings, CustomSettings)
