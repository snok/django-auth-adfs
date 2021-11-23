import sys
from copy import deepcopy

from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, SimpleTestCase, override_settings
from mock import patch
from django_auth_adfs.config import django_settings
from django_auth_adfs.config import Settings, REQUIRED_SETTINGS
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

    def test_idps_as_mutually_exclusive(self):
        settings = deepcopy(django_settings)
        settings.AUTH_ADFS["IDPS"] = {}
        with patch("django_auth_adfs.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured):
                Settings()

    def test_idps_empty_entries(self):
        settings = deepcopy(django_settings)
        for setting in REQUIRED_SETTINGS:
            if setting in settings.AUTH_ADFS:
                del settings.AUTH_ADFS[setting]
        settings.AUTH_ADFS["IDPS"] = {}
        with patch("django_auth_adfs.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured) as cm:
                Settings()

            self.assertEqual(
                str(cm.exception),
                "The IDPS configuration must have at least one configuration defined."
            )

    def test_idps_missing_required_settings_in_entry(self):
        settings = deepcopy(django_settings)
        for setting in REQUIRED_SETTINGS:
            if setting in settings.AUTH_ADFS:
                del settings.AUTH_ADFS[setting]
        settings.AUTH_ADFS["IDPS"] = {
            "adfs": {
                "CLIENT_ID": "abc"
            }
        }
        with patch("django_auth_adfs.config.django_settings", settings):
            with self.assertRaises(ImproperlyConfigured) as cm:
                Settings()

            self.assertEqual(
                str(cm.exception),
                "django_auth_adfs setting 'AUDIENCE' has not been set for IDP key 'adfs'"
            )

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
