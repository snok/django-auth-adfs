import sys
from copy import deepcopy

from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, SimpleTestCase, override_settings
from mock import patch
from django_auth_adfs.config import django_settings
from django_auth_adfs.config import Settings
from django_auth_adfs.config import ProviderConfig
from .custom_config import Settings as CustomSettings


class SettingsTests(TestCase):
    def test_no_settings(self):
        settings = deepcopy(django_settings)
        del settings.AUTH_ADFS
        with patch("django_auth_adfs.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured):
                Settings()

    def test_claim_mapping_overlapping_username_field(self):
        settings = deepcopy(django_settings)
        settings.AUTH_ADFS["CLAIM_MAPPING"] = {"username": "samaccountname"}
        with patch("django_auth_adfs.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured):
                Settings()

    def test_tenant_and_server(self):
        settings = deepcopy(django_settings)
        settings.AUTH_ADFS["TENANT_ID"] = "abc"
        settings.AUTH_ADFS["SERVER"] = "abc"
        with patch("django_auth_adfs.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured):
                Settings()

    def test_no_tenant_but_block_guest(self):
        settings = deepcopy(django_settings)
        settings.AUTH_ADFS["SERVER"] = "abc"
        settings.AUTH_ADFS["BLOCK_GUEST_USERS"] = True
        with patch("django_auth_adfs.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured):
                Settings()

    def test_tenant_with_block_users(self):
        settings = deepcopy(django_settings)
        del settings.AUTH_ADFS["SERVER"]
        settings.AUTH_ADFS["TENANT_ID"] = "abc"
        settings.AUTH_ADFS["BLOCK_GUEST_USERS"] = True
        with patch("django_auth_adfs.config.django_settings", settings):
            current_settings = Settings()
            self.assertTrue(current_settings.BLOCK_GUEST_USERS)

    def test_unknown_setting(self):
        settings = deepcopy(django_settings)
        settings.AUTH_ADFS["dummy"] = "abc"
        with patch("django_auth_adfs.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured):
                Settings()

    def test_required_setting(self):
        settings = deepcopy(django_settings)
        del settings.AUTH_ADFS["AUDIENCE"]
        with patch("django_auth_adfs.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured):
                Settings()

    def test_default_failed_response_setting(self):
        settings = deepcopy(django_settings)
        with patch("django_auth_adfs.config.django_settings", settings):
            s = Settings()
            self.assertTrue(callable(s.CUSTOM_FAILED_RESPONSE_VIEW))

    def test_dotted_path_failed_response_setting(self):
        settings = deepcopy(django_settings)
        settings.AUTH_ADFS["CUSTOM_FAILED_RESPONSE_VIEW"] = 'tests.views.test_failed_response'
        with patch("django_auth_adfs.config.django_settings", settings):
            s = Settings()
            self.assertTrue(callable(s.CUSTOM_FAILED_RESPONSE_VIEW))

    def test_settings_version(self):
        settings = deepcopy(django_settings)
        current_settings = Settings()
        self.assertEqual(current_settings.VERSION, "v1.0")
        settings.AUTH_ADFS["TENANT_ID"] = "abc"
        del settings.AUTH_ADFS["SERVER"]
        settings.AUTH_ADFS["VERSION"] = "v2.0"
        with patch("django_auth_adfs.config.django_settings", settings):
            current_settings = Settings()
            self.assertEqual(current_settings.VERSION, "v2.0")

    def test_not_azure_but_version_is_set(self):
        settings = deepcopy(django_settings)
        settings.AUTH_ADFS["SERVER"] = "abc"
        settings.AUTH_ADFS["VERSION"] = "v2.0"
        with patch("django_auth_adfs.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured):
                Settings()

    def test_configured_proxy(self):
        settings = Settings()
        settings.PROXIES = {'http': '10.0.0.1'}
        with patch("django_auth_adfs.config.settings", settings):
            provider_config = ProviderConfig()
            self.assertEqual(provider_config.session.proxies, {'http': '10.0.0.1'})

    def test_no_configured_proxy(self):
        provider_config = ProviderConfig()
        self.assertIsNone(provider_config.session.proxies)


class CustomSettingsTests(SimpleTestCase):
    def setUp(self):
        sys.modules.pop('django_auth_adfs.config', None)

    def tearDown(self):
        sys.modules.pop('django_auth_adfs.config', None)

    def test_dotted_path(self):
        auth_adfs = deepcopy(django_settings).AUTH_ADFS
        auth_adfs['SETTINGS_CLASS'] = 'tests.custom_config.Settings'

        with override_settings(AUTH_ADFS=auth_adfs):
            from django_auth_adfs.config import settings
            self.assertIsInstance(settings, CustomSettings)
