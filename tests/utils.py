import base64
import json
import os
import re
import time
from datetime import datetime, tzinfo, timedelta
from functools import partial

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


def build_access_token_azure_not_guest(request):
    issuer = "https://sts.windows.net/01234567-89ab-cdef-0123-456789abcdef/"
    return do_build_access_token(request, issuer, schema='dummy_tenant_id')


def build_access_token_azure_guest(request):
    issuer = "https://sts.windows.net/01234567-89ab-cdef-0123-456789abcdef/"
    return do_build_access_token(request, issuer, schema='guest_tenant_id')


def build_access_token_azure_guest_no_upn(request):
    issuer = "https://sts.windows.net/01234567-89ab-cdef-0123-456789abcdef/"
    return do_build_access_token(request, issuer, schema='guest_tenant_id', no_upn=True)


def build_access_token_azure_guest_with_idp(request):
    issuer = "https://sts.windows.net/01234567-89ab-cdef-0123-456789abcdef/"
    return do_build_access_token(request, issuer, schema='dummy_tenant_id', no_upn=True, idp="guest_idp")


def build_access_token_azure_groups_in_claim_source(request):
    issuer = "https://sts.windows.net/01234567-89ab-cdef-0123-456789abcdef/"
    return do_build_access_token(request, issuer, groups_in_claim_names=True)


def do_build_mfa_error(request):
    response = {'error_description': 'AADSTS50076'}
    return 400, [], json.dumps(response)


def do_build_graph_response(request):
    return do_build_ms_graph_groups(request)


def do_build_graph_response_no_group_perm(request):
    return do_build_ms_graph_groups(request, missing_group_names=True)


def do_build_access_token(request, issuer, schema=None, no_upn=False, idp=None, groups_in_claim_names=False):
    issued_at = int(time.time())
    expires = issued_at + 3600
    auth_time = datetime.utcnow()
    auth_time = auth_time.replace(tzinfo=SimpleUtc(), microsecond=0)
    claims = {
        "aud": "microsoft:identityserver:your-RelyingPartyTrust-identifier",
        "iss": issuer,
        "idp": idp or issuer,
        "iat": issued_at,
        "exp": expires,
        "winaccountname": "testuser",
        "group": ["group1", "group2"],
        "given_name": "John",
        "family_name": "Doe",
        "email": "john.doe@example.com",
        "sub": "john.doe@example.com",
        "custom_employee_id": 182,
        "user_is_staff": "True",
        "user_is_superuser": "yes",
        "appid": "your-configured-client-id",
        "auth_time": auth_time.isoformat(),
        "authmethod": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        "ver": "1.0"
    }
    if schema:
        claims['tid'] = schema
    if issuer.startswith('https://sts.windows.net'):
        claims['upn'] = 'testuser'
        claims['groups'] = claims['group']
    if no_upn:
        del claims['upn']
    if groups_in_claim_names:
        if 'groups' in claims:
            del claims['groups']
        del claims['group']
        claims['_claim_names'] = {
            "groups": "src1",
        }
        claims['_claim_sources'] = {
            "src1": {
                "endpoint": (
                    "https://graph.windows.net/01234567-89ab-cdef-0123-456789abcdef"
                    "/users/23456789-01bc-defg-1234-56789bcdefg/getMemberObjects"
                ),
            }
        }
    token = jwt.encode(claims, signing_key_b, algorithm="RS256")
    response = {
        'resource': 'django_website.adfs.relying_party_id',
        'token_type': 'bearer',
        'refresh_token_expires_in': 28799,
        'refresh_token': 'random_refresh_token',
        'expires_in': 3600,
        'id_token': 'not_used',
        'access_token': token.decode() if isinstance(token, bytes) else token  # PyJWT>=2 returns a str instead of bytes
    }
    return 200, [], json.dumps(response)


def do_build_obo_access_token(request):
    obo_token = {
        "aud": "https://graph.microsoft.com",
        "iss": "https://sts.windows.net/01234567-89ab-cdef-0123-456789abcdef/",
        "iat": 1660851337,
        "nbf": 1660851337,
        "exp": 1660856510,
        "acct": 0,
        "acr": "1",
        "aio": (
            "AUQAu/8TBCDAcvfLrjwjR53Uci8V5KCONDvJXGEFM/gMeVSp6/LV338RTspRjxIhbmNLcAGa80KVXXglM7+ea1uqRKkRNCa9bQ=="
        ),
        "amr": [
            "wia",
            "mfa"
        ],
        "app_displayname": "AppName",
        "appid": "2345a5bc-123a-0a1b-0a12-a12345b6cd7e",
        "appidacr": "1",
        "family_name": "Doe",
        "given_name": "John",
        "idtyp": "user",
        "ipaddr": "1.2.3.4",
        "name": "Doe, John (Expert)",
        "oid": "2345a5bc-123a-0a1b-0a12-a12345b6cd7e",
        "onprem_sid": "S-1-5-21-456123456-1364589140-123456543-563809",
        "platf": "5",
        "puid": "10030000AD9D1530",
        "rh": "0.AS8A1AA4aCjPK0uCpKTt25xSNwMAAAAAAAAAwAAAAAAAAAAvAEQ.",
        "scp": "email GroupMember.Read.All openid profile User.Read",
        "signin_state": [
            "inknownntwk"
        ],
        "sub": "PZBipRglYn2dgemAP_qDM3QzF1nosfdylWx8hsEwzYA",
        "tenant_region_scope": "EU",
        "tid": "01234567-89ab-cdef-0123-456789abcdef",
        "unique_name": "john.doe@example.com",
        "upn": "john.doe@example.com",
        "uti": "D8NUc9MAwkutG-iBUnsBAA",
        "ver": "1.0",
        "wids": [
            "2345a5bc-123a-0a1b-0a12-a12345b6cd7e",
        ],
        "xms_tcdt": 1467198948
    }
    token = jwt.encode(obo_token, signing_key_b, algorithm="RS256")
    response = {
        'token_type': 'bearer',
        'scope': 'email GroupMember.Read.All openid profile User.Read',
        'expires_in': '4872',
        'ext_expires_in': '4872',
        'expires_on': '1660856510',
        'not_before': '1660851337',
        'resource': 'https://graph.microsoft.com',
        'refresh_token': 'not_used',
        'access_token': token.decode() if isinstance(token, bytes) else token  # PyJWT>=2 returns a str instead of bytes
    }
    return 200, [], json.dumps(response)


def do_build_ms_graph_groups(request, missing_group_names=False):
    response = {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#groups",
        "value": [
            {
                "id": "12ab345c-6abc-427f-85ca-93fc0cc7f00d",
                "deletedDateTime": None,
                "classification": None,
                "createdDateTime": "2020-11-02T13:06:02Z",
                "creationOptions": [],
                "description": None,
                "displayName": "group1",
                "expirationDateTime": None,
                "groupTypes": [],
                "isAssignableToRole": None,
                "mail": None,
                "mailEnabled": False,
                "mailNickname": "group1",
                "membershipRule": None,
                "membershipRuleProcessingState": None,
                "onPremisesDomainName": "example.com",
                "onPremisesLastSyncDateTime": "2022-08-18T19:32:43Z",
                "onPremisesNetBiosName": "COMPANY",
                "onPremisesSamAccountName": "group1",
                "onPremisesSecurityIdentifier": "S-1-5-21-1234567891-1234567891-1234567891-123456",
                "onPremisesSyncEnabled": True,
                "preferredDataLocation": None,
                "preferredLanguage": None,
                "proxyAddresses": [],
                "renewedDateTime": "2020-11-02T13:06:02Z",
                "resourceBehaviorOptions": [],
                "resourceProvisioningOptions": [],
                "securityEnabled": False,
                "securityIdentifier": "S-1-12-1-1234567891-1234567891-1234567891-1234567891",
                "theme": None,
                "visibility": None,
                "onPremisesProvisioningErrors": []
            },
            {
                "id": "23ab456c-7abc-427f-85ca-93fc0cc7f00d",
                "deletedDateTime": None,
                "classification": None,
                "createdDateTime": "2020-11-02T13:06:02Z",
                "creationOptions": [],
                "description": None,
                "displayName": "group2",
                "expirationDateTime": None,
                "groupTypes": [],
                "isAssignableToRole": None,
                "mail": None,
                "mailEnabled": False,
                "mailNickname": "group2",
                "membershipRule": None,
                "membershipRuleProcessingState": None,
                "onPremisesDomainName": "example.com",
                "onPremisesLastSyncDateTime": "2022-08-18T19:32:43Z",
                "onPremisesNetBiosName": "COMPANY",
                "onPremisesSamAccountName": "group2",
                "onPremisesSecurityIdentifier": "S-1-5-21-1234567891-1234567891-1234567891-123456",
                "onPremisesSyncEnabled": True,
                "preferredDataLocation": None,
                "preferredLanguage": None,
                "proxyAddresses": [],
                "renewedDateTime": "2020-11-02T13:06:02Z",
                "resourceBehaviorOptions": [],
                "resourceProvisioningOptions": [],
                "securityEnabled": False,
                "securityIdentifier": "S-1-12-1-1234567891-1234567891-1234567891-1234567891",
                "theme": None,
                "visibility": None,
                "onPremisesProvisioningErrors": []
            },
        ]
    }
    if missing_group_names:
        for group in response["value"]:
            group["displayName"] = None
    return 200, [], json.dumps(response)


def build_openid_keys(request, empty_keys=False):
    if empty_keys:
        keys = {"keys": []}
    else:
        keys = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "dummythumbprint",
                    "x5t": "dummythumbprint",
                    "n": "somebase64encodedmodulus",
                    "e": "somebase64encodedexponent",
                    "x5c": [base64.b64encode(signing_cert_a).decode(), ]
                },
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "dummythumbprint",
                    "x5t": "dummythumbprint",
                    "n": "somebase64encodedmodulus",
                    "e": "somebase64encodedexponent",
                    "x5c": [base64.b64encode(signing_cert_b).decode(), ]
                },
            ]
        }
    return 200, [], json.dumps(keys)


def build_adfs_meta(request):
    with open(os.path.join(os.path.dirname(__file__), "mock_files/FederationMetadata.xml"), mode="r") as f:
        data = "".join(f.readlines())
    data = data.replace("REPLACE_WITH_CERT_A", base64.b64encode(signing_cert_a).decode())
    data = data.replace("REPLACE_WITH_CERT_B", base64.b64encode(signing_cert_b).decode())
    return 200, [], data


def mock_adfs(
    adfs_version,
    empty_keys=False,
    mfa_error=False,
    guest=False,
    version=None,
    requires_obo=False,
    missing_graph_group_perm=False,
):
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
            ms_graph_endpoint = "https://graph.microsoft.com/"
            if version == "v2.0":
                openid_cfg = re.compile(prefix + r".*{}/\.well-known/openid-configuration".format(version))
                token_endpoint = re.compile(prefix + r".*/oauth2/{}/token".format(version))
            else:
                openid_cfg = re.compile(prefix + r".*\.well-known/openid-configuration")
                token_endpoint = re.compile(prefix + r".*/oauth2/token")
            openid_keys = re.compile(prefix + r".*/discovery/keys")
            adfs_meta = re.compile(prefix + r".*/FederationMetadata/2007-06/FederationMetadata\.xml")
            ms_graph_groups = re.compile(ms_graph_endpoint + r".*/transitiveMemberOf/microsoft.graph.group")
            with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
                # https://github.com/getsentry/responses
                if adfs_version == "2016":
                    rsps.add(
                        rsps.GET, openid_cfg,
                        json=load_json("mock_files/adfs-openid-configuration.json")
                    )
                    rsps.add_callback(
                        rsps.GET, openid_keys,
                        callback=partial(build_openid_keys, empty_keys=empty_keys),
                        content_type='application/json',
                    )
                elif adfs_version == "azure":
                    if version == "v2.0":
                        rsps.add(
                            rsps.GET, openid_cfg,
                            json=load_json("mock_files/azure-openid-configuration-v2.json")
                        )
                    else:
                        rsps.add(
                            rsps.GET, openid_cfg,
                            json=load_json("mock_files/azure-openid-configuration.json")
                        )
                    rsps.add_callback(
                        rsps.GET, openid_keys,
                        callback=partial(build_openid_keys, empty_keys=empty_keys),
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
                    if guest:
                        rsps.add_callback(
                            rsps.POST, token_endpoint,
                            callback=build_access_token_azure_guest,
                            content_type='application/json',
                        )
                    rsps.add_callback(
                        rsps.POST, token_endpoint,
                        callback=build_access_token_azure,
                        content_type='application/json',
                    )
                    if requires_obo:
                        if mfa_error:
                            rsps.add_callback(
                                rsps.GET, token_endpoint,
                                callback=do_build_mfa_error,
                                content_type='application/json',
                            )
                        else:
                            rsps.add_callback(
                                rsps.GET, token_endpoint,
                                callback=do_build_obo_access_token,
                                content_type='application/json'
                            )
                        if missing_graph_group_perm:
                            rsps.add_callback(
                                rsps.GET, ms_graph_groups,
                                callback=do_build_graph_response_no_group_perm,
                                content_type='application/json',
                            )
                        else:
                            rsps.add_callback(
                                rsps.GET, ms_graph_groups,
                                callback=do_build_graph_response,
                                content_type='application/json',
                            )
                else:
                    if mfa_error:
                        rsps.add_callback(
                            rsps.POST, token_endpoint,
                            callback=do_build_mfa_error,
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


signing_key_a, signing_cert_a = generate_key_and_cert()
signing_key_b, signing_cert_b = generate_key_and_cert()
