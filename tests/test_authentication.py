from copy import deepcopy

from django.contrib.auth.models import User, Group
from django.core.exceptions import PermissionDenied
from django.test import TestCase, RequestFactory
from mock import Mock, patch

from django_auth_adfs import signals
from django_auth_adfs.backend import AdfsAuthCodeBackend
from django_auth_adfs.config import ProviderConfig, Settings
from .utils import mock_adfs


class AuthenticationTests(TestCase):
    def setUp(self):
        Group.objects.create(name='group1')
        Group.objects.create(name='group2')
        Group.objects.create(name='group3')
        self.request = RequestFactory().get('/oauth2/callback')
        self.signal_handler = Mock()
        signals.post_authenticate.connect(self.signal_handler)

    @mock_adfs("2012")
    def test_post_authenticate_signal_send(self):
        backend = AdfsAuthCodeBackend()
        backend.authenticate(self.request, authorization_code="dummycode")
        self.assertEqual(self.signal_handler.call_count, 1)

    @mock_adfs("2012")
    def test_with_auth_code_2012(self):
        backend = AdfsAuthCodeBackend()
        user = backend.authenticate(self.request, authorization_code="dummycode")
        self.assertIsInstance(user, User)
        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "Doe")
        self.assertEqual(user.email, "john.doe@example.com")
        self.assertEqual(len(user.groups.all()), 2)
        self.assertEqual(user.groups.all()[0].name, "group1")
        self.assertEqual(user.groups.all()[1].name, "group2")

    @mock_adfs("2016")
    def test_with_auth_code_2016(self):
        backend = AdfsAuthCodeBackend()
        user = backend.authenticate(self.request, authorization_code="dummycode")
        self.assertIsInstance(user, User)
        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "Doe")
        self.assertEqual(user.email, "john.doe@example.com")
        self.assertEqual(len(user.groups.all()), 2)
        self.assertEqual(user.groups.all()[0].name, "group1")
        self.assertEqual(user.groups.all()[1].name, "group2")

    @mock_adfs("azure")
    def test_with_auth_code_azure(self):
        from django_auth_adfs.config import django_settings
        settings = deepcopy(django_settings)
        del settings.AUTH_ADFS["SERVER"]
        settings.AUTH_ADFS["TENANT_ID"] = "dummy_tenant_id"
        with patch("django_auth_adfs.config.django_settings", settings):
            with patch("django_auth_adfs.config.settings", Settings()):
                with patch("django_auth_adfs.backend.provider_config", ProviderConfig()):
                    backend = AdfsAuthCodeBackend()
                    user = backend.authenticate(self.request, authorization_code="dummycode")
                    self.assertIsInstance(user, User)
                    self.assertEqual(user.first_name, "John")
                    self.assertEqual(user.last_name, "Doe")
                    self.assertEqual(user.email, "john.doe@example.com")
                    self.assertEqual(len(user.groups.all()), 2)
                    self.assertEqual(user.groups.all()[0].name, "group1")
                    self.assertEqual(user.groups.all()[1].name, "group2")

    @mock_adfs("2016")
    def test_empty(self):
        backend = AdfsAuthCodeBackend()
        self.assertIsNone(backend.authenticate(self.request))

    @mock_adfs("2016")
    def test_group_claim(self):
        backend = AdfsAuthCodeBackend()
        with patch("django_auth_adfs.backend.settings.GROUPS_CLAIM", "nonexisting"):
            user = backend.authenticate(self.request, authorization_code="dummycode")
            self.assertIsInstance(user, User)
            self.assertEqual(user.first_name, "John")
            self.assertEqual(user.last_name, "Doe")
            self.assertEqual(user.email, "john.doe@example.com")
            self.assertEqual(len(user.groups.all()), 0)

    @mock_adfs("2016")
    def test_empty_keys(self):
        backend = AdfsAuthCodeBackend()
        with patch("django_auth_adfs.config.provider_config.signing_keys", []):
            self.assertRaises(PermissionDenied, backend.authenticate, self.request, authorization_code='testcode')

    @mock_adfs("2016")
    def test_group_removal(self):
        user, created = User.objects.get_or_create(**{
            User.USERNAME_FIELD: "testuser"
        })
        group = Group.objects.get(name="group3")
        user.groups.add(group)
        user.save()

        self.assertEqual(user.groups.all()[0].name, "group3")

        backend = AdfsAuthCodeBackend()

        user = backend.authenticate(self.request, authorization_code="dummycode")
        self.assertIsInstance(user, User)
        self.assertEqual(user.first_name, "John")
        self.assertEqual(user.last_name, "Doe")
        self.assertEqual(user.email, "john.doe@example.com")
        self.assertEqual(len(user.groups.all()), 2)
        self.assertEqual(user.groups.all()[0].name, "group1")
        self.assertEqual(user.groups.all()[1].name, "group2")
