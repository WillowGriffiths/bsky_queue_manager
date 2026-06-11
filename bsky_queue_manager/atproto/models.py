import base64
import json

from cryptography.hazmat.primitives.asymmetric import ec
from django.contrib.auth.models import User
from django.db import models


class ATProtoAccount(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="atproto")
    did = models.CharField(max_length=255, unique=True)

    access_token = models.TextField()
    refresh_token = models.TextField()
    token_expiry = models.DateTimeField()

    dpop_private_jwk = models.TextField()

    dpop_nonce = models.CharField(max_length=512, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    pds = models.TextField()
    auth_server = models.TextField()

    def get_private_key(self) -> ec.EllipticCurvePrivateKey:
        jwk = self.get_jwk()
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric.ec import (
            SECP256R1,
            EllipticCurvePrivateNumbers,
            EllipticCurvePublicNumbers,
        )

        def b64url_to_int(s):
            padded = s + "=" * (-len(s) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

        pub = EllipticCurvePublicNumbers(
            x=b64url_to_int(jwk["x"]),
            y=b64url_to_int(jwk["y"]),
            curve=SECP256R1(),
        )
        priv = EllipticCurvePrivateNumbers(
            private_value=b64url_to_int(jwk["d"]),
            public_numbers=pub,
        )
        return priv.private_key(default_backend())

    def get_jwk(self) -> dict:
        return json.loads(str(self.dpop_private_jwk))

    def set_jwk(self, jwk: dict):
        self.dpop_private_jwk = json.dumps(jwk)

    def is_token_expired(self) -> bool:
        from django.utils import timezone

        return timezone.now() >= self.token_expiry
