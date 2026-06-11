import requests
import time
import uuid
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec


def post_with_dpop(
    url: str,
    private_key: ec.EllipticCurvePrivateKey,
    jwk: dict,
    access_token: str | None = None,
    nonce: str | None = None,
    max_retries: int = 1,
    **kwargs,
) -> requests.Response:
    """
    POST to a DPoP-protected endpoint, automatically retrying with a fresh
    nonce if the server returns one via the DPoP-Nonce header.

    Args:
        url: Full request URL.
        private_key: ES256 private key.
        jwk: JWK dict (with 'd' — public-only version is derived internally).
        access_token: Bearer token to bind the proof to (adds 'ath' claim).
        nonce: DPoP nonce from a prior response (optional, auto-updated).
        max_retries: How many times to retry on a nonce mismatch (default 1).
        **kwargs: Passed straight through to requests.post() (data, json, headers, …).

    Returns:
        The final requests.Response object.

    Raises:
        requests.HTTPError: If the request fails after all retries.
    """
    for attempt in range(max_retries + 1):
        proof = _build_dpop_proof(private_key, jwk, "POST", url, access_token, nonce)

        extra_headers = {"DPoP": proof}
        if access_token:
            extra_headers["Authorization"] = f"DPoP {access_token}"

        # Merge caller-supplied headers without clobbering DPoP ones
        merged_headers = {**kwargs.pop("headers", {}), **extra_headers}

        response = requests.post(url, headers=merged_headers, **kwargs)

        # Grab a new nonce whether the request succeeded or not —
        # the server may rotate it on every response.
        new_nonce = response.headers.get("DPoP-Nonce")
        if new_nonce:
            nonce = new_nonce

        # 401 with use_dpop_nonce means we need to retry with the nonce we
        # just captured; any other status exits immediately.
        if (
            not response.ok
            and _is_nonce_error(response)
            and attempt < max_retries
            and nonce
        ):
            continue

        return response

    raise Exception("This shouldn't happen! Is max_retries less than zero?")


def generate_dpop_key():
    # Generate P-256 private key (required by atproto)
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key


def key_to_jwk(private_key):
    """Export private key as JWK dict."""
    public_key = private_key.public_key()
    pub_numbers = (
        public_key.public_numbers()
        if hasattr(public_key, "public_key")
        else public_key.public_numbers()
    )
    priv_numbers = private_key.private_numbers()

    def int_to_base64url(n, length=32):
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    return {
        "kty": "EC",
        "crv": "P-256",
        "x": int_to_base64url(pub_numbers.x),
        "y": int_to_base64url(pub_numbers.y),
        "d": int_to_base64url(priv_numbers.private_value),
    }


def _build_dpop_proof(
    private_key: ec.EllipticCurvePrivateKey,
    jwk: dict,
    method: str,
    url: str,
    access_token: str | None = None,
    nonce: str | None = None,
) -> str:
    import jwt  # PyJWT

    public_jwk = {k: v for k, v in jwk.items() if k != "d"}

    headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk}

    claims = {
        "jti": str(uuid.uuid4()),
        "htm": method.upper(),
        "htu": url,
        "iat": int(time.time()),
    }

    if nonce:
        claims["nonce"] = nonce

    if access_token:
        ath = (
            base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        claims["ath"] = ath

    return jwt.encode(claims, private_key, algorithm="ES256", headers=headers)


def _is_nonce_error(response: requests.Response) -> bool:
    """Return True when the response signals a missing/stale DPoP nonce."""
    # The spec mandates WWW-Authenticate: DPoP error="use_dpop_nonce"
    www_auth = response.headers.get("WWW-Authenticate", "")
    if "use_dpop_nonce" in www_auth:
        return True
    # Some servers also surface this in the JSON body
    try:
        body = response.json()
        return body.get("error") == "use_dpop_nonce"
    except Exception:
        return False
