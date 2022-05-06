import base64

from django_auth_adfs.exceptions import MFARequired

try:
    from urllib.parse import urlparse, parse_qs
except ImportError:  # Python 2.7
    from urlparse import urlparse, parse_qs

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

    @mock_adfs("2016", mfa_error=True)
    def test_mfa_error_backends(self):
        with self.assertRaises(MFARequired):
            backend = AdfsAuthCodeBackend()
            backend.authenticate(self.request, authorization_code="dummycode")

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

    @mock_adfs("azure", guest=True)
    def test_with_auth_code_azure_guest_block(self):
        from django_auth_adfs.config import django_settings
        settings = deepcopy(django_settings)
        del settings.AUTH_ADFS["SERVER"]
        settings.AUTH_ADFS["TENANT_ID"] = "dummy_tenant_id"
        settings.AUTH_ADFS["BLOCK_GUEST_USERS"] = True
        # Patch audience since we're patching django_auth_adfs.backend.settings to load Settings() as well
        settings.AUTH_ADFS["AUDIENCE"] = 'microsoft:identityserver:your-RelyingPartyTrust-identifier'
        with patch("django_auth_adfs.config.django_settings", settings):
            with patch('django_auth_adfs.backend.settings', Settings()):
                with patch("django_auth_adfs.config.settings", Settings()):
                    with patch("django_auth_adfs.backend.provider_config", ProviderConfig()):
                        with self.assertRaises(PermissionDenied, msg=''):
                            backend = AdfsAuthCodeBackend()
                            _ = backend.authenticate(self.request, authorization_code="dummycode")

    @mock_adfs("azure", guest=True)
    def test_with_auth_code_azure_guest_no_block(self):
        from django_auth_adfs.config import django_settings
        settings = deepcopy(django_settings)
        del settings.AUTH_ADFS["SERVER"]
        settings.AUTH_ADFS["TENANT_ID"] = "dummy_tenant_id"
        settings.AUTH_ADFS["BLOCK_GUEST_USERS"] = False
        # Patch audience since we're patching django_auth_adfs.backend.settings to load Settings() as well
        settings.AUTH_ADFS["AUDIENCE"] = 'microsoft:identityserver:your-RelyingPartyTrust-identifier'
        with patch("django_auth_adfs.config.django_settings", settings):
            with patch('django_auth_adfs.backend.settings', Settings()):
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

    @mock_adfs("azure", version='v2.0')
    def test_version_two_endpoint_calls_correct_url(self):
        from django_auth_adfs.config import django_settings
        settings = deepcopy(django_settings)
        del settings.AUTH_ADFS["SERVER"]
        settings.AUTH_ADFS["TENANT_ID"] = "dummy_tenant_id"
        settings.AUTH_ADFS["VERSION"] = 'v2.0'
        # Patch audience since we're patching django_auth_adfs.backend.settings to load Settings() as well
        with patch("django_auth_adfs.config.django_settings", settings):
            with patch('django_auth_adfs.backend.settings', Settings()):
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

    @mock_adfs("2016", empty_keys=True)
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
        user.set_unusable_password()
        user.save()

        self.assertEqual(user.groups.all()[0].name, "group3")
        self.assertEqual(len(user.groups.all()), 1)

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
    def test_group_removal_overlap(self):
        user, created = User.objects.get_or_create(**{
            User.USERNAME_FIELD: "testuser"
        })
        group_one = Group.objects.get(name="group1")
        group_three = Group.objects.get(name="group3")
        user.groups.add(group_one, group_three)
        user.set_unusable_password()
        user.save()

        self.assertEqual(user.groups.all()[0].name, "group1")
        self.assertEqual(user.groups.all()[1].name, "group3")
        self.assertEqual(len(user.groups.all()), 2)

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
    def test_group_to_flag_mapping(self):
        group_to_flag_mapping = {
            "is_staff": ["group1", "group4"],
            "is_superuser": "group2",
        }
        with patch("django_auth_adfs.backend.settings.GROUP_TO_FLAG_MAPPING", group_to_flag_mapping):
            with patch("django_auth_adfs.backend.settings.BOOLEAN_CLAIM_MAPPING", {}):
                backend = AdfsAuthCodeBackend()

                user = backend.authenticate(self.request, authorization_code="dummycode")
                self.assertIsInstance(user, User)
                self.assertEqual(user.first_name, "John")
                self.assertEqual(user.last_name, "Doe")
                self.assertEqual(user.email, "john.doe@example.com")
                self.assertEqual(len(user.groups.all()), 2)
                self.assertTrue(user.is_staff)
                self.assertTrue(user.is_superuser)

    @mock_adfs("2016")
    def test_boolean_claim_mapping(self):
        boolean_claim_mapping = {
            "is_superuser": "user_is_superuser",
        }
        with patch("django_auth_adfs.backend.settings.BOOLEAN_CLAIM_MAPPING", boolean_claim_mapping):
            backend = AdfsAuthCodeBackend()

            user = backend.authenticate(self.request, authorization_code="dummycode")
            self.assertIsInstance(user, User)
            self.assertEqual(user.first_name, "John")
            self.assertEqual(user.last_name, "Doe")
            self.assertEqual(user.email, "john.doe@example.com")
            self.assertEqual(len(user.groups.all()), 2)
            self.assertFalse(user.is_staff)
            self.assertTrue(user.is_superuser)

    @mock_adfs("2016")
    def test_authentication(self):
        response = self.client.get("/oauth2/callback", {'code': 'testcode'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], "/")

    @mock_adfs("2016")
    def test_mfa_error(self):
        with patch('django_auth_adfs.views.authenticate') as mock_auth:
            mock_auth.side_effect = MFARequired('Mock error')
            response = self.client.get("/oauth2/callback", {'code': 'testcode'})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(
                response['Location'],
                "https://adfs.example.com/adfs/oauth2/authorize/?response_type=code&"
                "client_id=your-configured-client-id&resource=your-adfs-RPT-name&"
                "redirect_uri=http%3A%2F%2Ftestserver%2Foauth2%2Fcallback&state=Lw%3D%3D&scope=openid&"
                "amr_values=ngcmfa"
            )

    @mock_adfs("2016")
    def test_callback_redir(self):
        state = base64.urlsafe_b64encode("/test/".encode())
        response = self.client.get("/oauth2/callback", {'code': 'testcode', "state": state})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], "/test/")

    @mock_adfs("2016")
    def test_missing_code(self):
        response = self.client.get("/oauth2/callback")
        self.assertEqual(response.status_code, 400)

    @mock_adfs("2016")
    def test_login_redir(self):
        response = self.client.get("/test/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], '/oauth2/login?next=/test/')

    @mock_adfs("2012")
    def test_oauth_redir_2012(self):
        response = self.client.get("/oauth2/login?next=/test/")
        self.assertEqual(response.status_code, 302)
        redir = urlparse(response["Location"])
        qs = parse_qs(redir.query)
        sq_expected = {
            'client_id': ['your-configured-client-id'],
            'state': ['L3Rlc3Qv'],
            'response_type': ['code'],
            'resource': ['your-adfs-RPT-name'],
            'redirect_uri': ['http://testserver/oauth2/callback']
        }
        self.assertEqual(redir.scheme, 'https')
        self.assertEqual(redir.hostname, 'adfs.example.com')
        self.assertEqual(redir.path.rstrip("/"), '/adfs/oauth2/authorize')
        self.assertEqual(qs, sq_expected)

    @mock_adfs("2016")
    def test_oauth_redir_2016(self):
        response = self.client.get("/oauth2/login?next=/test/")
        self.assertEqual(response.status_code, 302)
        redir = urlparse(response["Location"])
        qs = parse_qs(redir.query)
        qs_expected = {
            'scope': ['openid'],
            'client_id': ['your-configured-client-id'],
            'state': ['L3Rlc3Qv'],
            'response_type': ['code'],
            'resource': ['your-adfs-RPT-name'],
            'redirect_uri': ['http://testserver/oauth2/callback']
        }
        self.assertEqual(redir.scheme, 'https')
        self.assertEqual(redir.hostname, 'adfs.example.com')
        self.assertEqual(redir.path.rstrip("/"), '/adfs/oauth2/authorize')
        self.assertEqual(qs, qs_expected)

    @mock_adfs("azure")
    def test_oauth_redir_azure_version_one(self):
        from django_auth_adfs.config import django_settings
        settings = deepcopy(django_settings)
        del settings.AUTH_ADFS["SERVER"]
        settings.AUTH_ADFS["TENANT_ID"] = "dummy_tenant_id"
        with patch("django_auth_adfs.config.django_settings", settings), \
                patch("django_auth_adfs.config.settings", Settings()), \
                patch("django_auth_adfs.views.provider_config", ProviderConfig()):
            response = self.client.get("/oauth2/login?next=/test/")
            self.assertEqual(response.status_code, 302)
            redir = urlparse(response["Location"])
            qs = parse_qs(redir.query)
            sq_expected = {
                'scope': ['openid'],
                'client_id': ['your-configured-client-id'],
                'state': ['L3Rlc3Qv'],
                'response_type': ['code'],
                'resource': ['your-adfs-RPT-name'],
                'redirect_uri': ['http://testserver/oauth2/callback']
            }
            self.assertEqual(redir.scheme, 'https')
            self.assertEqual(redir.hostname, 'login.microsoftonline.com')
            self.assertEqual(redir.path.rstrip("/"), '/01234567-89ab-cdef-0123-456789abcdef/oauth2/authorize')
            self.assertEqual(qs, sq_expected)

    @mock_adfs("azure")
    def test_oauth_redir_azure_version_two(self):
        from django_auth_adfs.config import django_settings
        settings = deepcopy(django_settings)
        del settings.AUTH_ADFS["SERVER"]
        settings.AUTH_ADFS["TENANT_ID"] = "dummy_tenant_id"
        settings.AUTH_ADFS["VERSION"] = 'v2.0'
        with patch("django_auth_adfs.config.django_settings", settings), \
                patch("django_auth_adfs.config.settings", Settings()), \
                patch("django_auth_adfs.views.provider_config", ProviderConfig()):
            response = self.client.get("/oauth2/login?next=/test/")
            self.assertEqual(response.status_code, 302)
            redir = urlparse(response["Location"])
            qs = parse_qs(redir.query)
            sq_expected = {
                'scope': ['openid api://your-adfs-RPT-name/.default'],
                'client_id': ['your-configured-client-id'],
                'state': ['L3Rlc3Qv'],
                'response_type': ['code'],
                'redirect_uri': ['http://testserver/oauth2/callback']
            }
            self.assertEqual(redir.scheme, 'https')
            self.assertEqual(redir.hostname, 'login.microsoftonline.com')
            self.assertEqual(redir.path.rstrip("/"), '/01234567-89ab-cdef-0123-456789abcdef/oauth2/authorize')
            self.assertEqual(qs, sq_expected)

    @mock_adfs("2016")
    def test_inactive_user(self):
        user = User.objects.create(**{
            User.USERNAME_FIELD: "testuser",
            "is_active": False
        })
        response = self.client.get("/oauth2/callback", {'code': 'testcode'})
        self.assertContains(response, "Your account is disabled", status_code=403)
        user.delete()

    @mock_adfs("2016")
    def test_nonexisting_user(self):
        from django_auth_adfs.config import django_settings
        settings = deepcopy(django_settings)
        settings.AUTH_ADFS["CREATE_NEW_USERS"] = False
        with patch("django_auth_adfs.config.django_settings", settings),\
                patch("django_auth_adfs.backend.settings", Settings()):
            backend = AdfsAuthCodeBackend()
            self.assertRaises(PermissionDenied, backend.authenticate, self.request, authorization_code='testcode')
