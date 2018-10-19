import base64
import json
import os
import re
import time
from datetime import datetime, tzinfo, timedelta

import jwt
import responses
from cryptography import x509
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_key_and_cert():
    signing_key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"example.com"),
    ])
    signing_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        signing_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.utcnow() + timedelta(days=10)
        # Sign our certificate with our private key
    ).sign(
        signing_key, hashes.SHA256(), crypto_default_backend()
    ).public_bytes(crypto_serialization.Encoding.DER)
    return signing_key, signing_cert


class SimpleUtc(tzinfo):
    def tzname(self, dt):
        return "UTC"

    def utcoffset(self, dt):
        return timedelta(0)


def load_json(file):
    with open(os.path.join(os.path.dirname(__file__), file), mode="r") as f:
        data = json.load(f)
    return data


def build_access_token_adfs(request):
    issuer = "http://adfs.example.com/adfs/services/trust"
    return do_build_access_token(request, issuer)


def build_access_token_azure(request):
    issuer = "https://sts.windows.net/01234567-89ab-cdef-0123-456789abcdef/"
    return do_build_access_token(request, issuer)


def do_build_access_token(request, issuer):
    issued_at = int(time.time())
    expires = issued_at + 3600
    auth_time = datetime.utcnow()
    auth_time = auth_time.replace(tzinfo=SimpleUtc(), microsecond=0)
    claims = {
        "aud": "microsoft:identityserver:your-RelyingPartyTrust-identifier",
        "iss": issuer,
        "iat": issued_at,
        "exp": expires,
        "winaccountname": "testuser",
        "group": ["group1", "group2"],
        "given_name": "John",
        "family_name": "Doe",
        "email": "john.doe@example.com",
        "sub": "john.doe@example.com",
        "user_is_staff": "True",
        "user_is_superuser": "yes",
        "appid": "your-configured-client-id",
        "auth_time": auth_time.isoformat(),
        "authmethod": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        "ver": "1.0"
    }
    token = jwt.encode(claims, signing_key_B, algorithm="RS256")
    response = {
        'resource': 'django_website.adfs.relying_party_id',
        'token_type': 'bearer',
        'refresh_token_expires_in': 28799,
        'refresh_token': 'random_refresh_token',
        'expires_in': 3600,
        'id_token': 'not_used',
        'access_token': token.decode()
    }
    return 200, [], json.dumps(response)


def build_openid_keys(request):
    keys = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "dummythumbprint",
                "x5t": "dummythumbprint",
                "n": "somebase64encodedmodulus",
                "e": "somebase64encodedexponent",
                "x5c": [base64.b64encode(signing_cert_A).decode(), ]
            },
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "dummythumbprint",
                "x5t": "dummythumbprint",
                "n": "somebase64encodedmodulus",
                "e": "somebase64encodedexponent",
                "x5c": [base64.b64encode(signing_cert_B).decode(), ]
            },
        ]
    }
    return 200, [], json.dumps(keys)


def build_adfs_meta(request):
    with open(os.path.join(os.path.dirname(__file__), "mock_files/FederationMetadata.xml"), mode="r") as f:
        data = "".join(f.readlines())
    data = data.replace("REPLACE_WITH_CERT_A", base64.b64encode(signing_cert_A).decode())
    data = data.replace("REPLACE_WITH_CERT_B", base64.b64encode(signing_cert_B).decode())
    return 200, [], data


def mock_adfs(adfs_version):
    if adfs_version not in ["2012", "2016", "azure"]:
        raise NotImplementedError("This version of ADFS is not implemented")

    def do_mock(test_func):
        def wrapper(*original_args, **original_kwargs):
            prefix_table = {
                "2012": "https://adfs.example.com",
                "2016": "https://adfs.example.com",
                "azure": "https://login.microsoftonline.com",
            }
            prefix = prefix_table[adfs_version]
            openid_cfg = re.compile(prefix + r".*\.well-known/openid-configuration")
            openid_keys = re.compile(prefix + r".*/discovery/keys")
            adfs_meta = re.compile(prefix + r".*/FederationMetadata/2007-06/FederationMetadata\.xml")
            token_endpoint = re.compile(prefix + r".*/oauth2/token")
            with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
                # https://github.com/getsentry/responses
                if adfs_version == "2016":
                    rsps.add(
                        rsps.GET, openid_cfg,
                        json=load_json("mock_files/adfs-openid-configuration.json")
                    )
                    rsps.add_callback(
                        rsps.GET, openid_keys,
                        callback=build_openid_keys,
                        content_type='application/json',
                    )
                elif adfs_version == "azure":
                    rsps.add(
                        rsps.GET, openid_cfg,
                        json=load_json("mock_files/azure-openid-configuration.json")
                    )
                    rsps.add_callback(
                        rsps.GET, openid_keys,
                        callback=build_openid_keys,
                        content_type='application/json',
                    )
                else:
                    rsps.add(
                        rsps.GET, openid_cfg,
                        status=404
                    )
                    rsps.add(
                        rsps.GET, openid_keys,
                        status=404
                    )

                rsps.add_callback(
                    rsps.GET, adfs_meta,
                    callback=build_adfs_meta,
                    content_type='application/xml',
                )
                if adfs_version == "azure":
                    rsps.add_callback(
                        rsps.POST, token_endpoint,
                        callback=build_access_token_azure,
                        content_type='application/json',
                    )
                else:
                    rsps.add_callback(
                        rsps.POST, token_endpoint,
                        callback=build_access_token_adfs,
                        content_type='application/json',
                    )

                test_func(*original_args, **original_kwargs)
        return wrapper
    return do_mock


signing_key_A, signing_cert_A = generate_key_and_cert()
signing_key_B, signing_cert_B = generate_key_and_cert()
