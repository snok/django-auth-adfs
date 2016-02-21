import json
import time
from datetime import datetime, tzinfo, timedelta

import jwt


class SimpleUtc(tzinfo):
    def tzname(self):
        return "UTC"

    def utcoffset(self, dt):
        return timedelta(0)


def get_base_claims():
    """
    Returns:
        dict
    """

    claims = json.loads("""
    {
        "aud":"microsoft:identityserver:your-RelyingPartyTrust-identifier",
        "iss":"http://adfs.example.com/adfs/services/trust",
        "iat":1,
        "exp":1,
        "winaccountname":"testuser",
        "group":["group1","group2"],
        "given_name":"John",
        "family_name":"Doe",
        "email":"john.doe@example.com",
        "sub": "john.doe@example.com",
        "appid": "your-configured-client-id",
        "auth_time": "2016-02-16T06:42:21.629Z",
        "authmethod": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        "ver": "1.0"
    }""")
    claims["iat"] = int(time.time())
    claims["exp"] = claims["iat"]+3600

    auth_time = datetime.utcnow()
    auth_time = auth_time.replace(tzinfo=SimpleUtc(), microsecond=0)
    claims["auth_time"] = auth_time.isoformat()

    return claims


def encode_jwt(claims):
    rsa_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAy3JZC0ZF+8XpDQxQQDZEtmThOLnhld1TlLTBSEX7lLLoDvlT
Vfop3LgWhdGhW1gM3Wa47oR3ni3JoXrbky+cAkMkslzu+p4xMS1ApZApZUFh9ZL9
eEXrvqZLYG0N20ffHkKd8XVN4w5nYQWHxp2uSECrStVAnL2m6DH1/TlaDQAmrmay
e+djXAxZjR6m/SQxQXOn6tLL9BMEF/UVt8GocSuATJdrXaKg9ubwR3j7GRfRNNy1
v+5LYfcRVFrFmupbL/6k8fUHeQ1qKNAhAvpcZl+4df1phUZJMnwcQncXI3zqypz8
bTTjTvu//iKr2U7Ih3TJdf/F51lPF0JaVB30jQIDAQABAoIBAQCx/pc9L/xmrN6b
FdzYcSJo2ZXaxXZCYeOQRRydmOzlSimRgD2TCU262CyMY73iZwTKZ+cAd1EYSUMR
TqXw/kRmDkx66KgFCIZNWiQnNhuhhTSpYDL3GWWJ5YApGwB2i0j/9pSs/k5oit+T
mP0Tnj0u5bV3wV/IQn1WxO9M3vKUT66Hi0iVhk0UP2Gzpp6Yl02UhrWMmfaJehvR
bDN/98zfBmMCRd59wA+o+501oc86S0kWaGPljvbs5CqPyhjidTgYRalfZq+bpFk5
Mh2viYzK/0ihk+j4zEef6I/q6qWfY40UxT550uT/0FjkI+TOS0RUmmt9zzsqP+ig
6ZIBqoBZAoGBAPoJxyrvI+ubY4td+6cHm2e32q1dpepvdgsfbwvIb4spTSUuC74D
hPzC+umtwCP++3FTFGeluDQgqH9YaA6QM5UeoeztQiuenmrbMR5p5wCPNQ67F4Ys
NGQrMOqjfaxSZ0npRIfv44vo1KOri4y5zY2E0LpHUenqQ5pKUUa1WkUfAoGBANBM
LV/GM/6l7muJB1OB0TtIRJzG4UUMfZambPXsTkMTXcw1ZG22j3x/YSmEqWW0q1tG
lL6otqNJy0Op5p8XJv0DalaA30K/Gb5Q+P9t9Vzx/92UcfQvkaNlUhIBAkFLXCI7
TMdS4zXLTNo9+j5pRWixui1hgvdwswEnMPsjjYTTAoGBAOQgm7kOawWBxrbXTs08
YYul8TyP3tsgSuEnEtf7Tdn4Gsy7UDdTWriK5QbjYhT1hVAF7u4KAyB8U3+sl3QC
GS4Kvs4+Qkst83em+Q+4q+yUvGHuTS47kql5xq2t8PGSVW7YB5DHTCLQkYGq+C2z
MFnYPeBXReNXu8o/2BvdRrkdAoGAK7yjFmYmysSKsHfAWw96IImHJqg36ui5giWF
4Ylx0XHCkztuz/6yWEDi5PXfH+T0yiCi4PnKB7VaAeYt75/L5vqNnIZI2toHjMex
0OiEybRitmMSHmTSns2Kkw81KwKo4OM0tvG3lbcPdw/meK5gDaCr6BV+i3hVjdtt
1H3dnFMCgYEApjfUKue/qbV/P9CUfu8+CCHLjQo00cKljZXtzagChIO5bMZ+jeIR
h7wYqFo4fHj8QnfvaNmeoorfCAipwpMW6wOZz62DbYMbRrkbPM0QaMD1RFr+St8x
AfJq5XYuxoMS4jr4GsaBdoW1aSldBsTcn971LTW2g/QyapTYlUjThi0=
-----END RSA PRIVATE KEY-----
    """
    return jwt.encode(claims, rsa_key, algorithm="RS256")
