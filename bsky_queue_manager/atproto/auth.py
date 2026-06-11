import logging

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

from .models import ATProtoAccount
from .dpop import generate_dpop_key, key_to_jwk, post_with_dpop

logger = logging.getLogger(__name__)


class ATProtoBackend(BaseBackend):
    def authenticate(
        self,
        request,
        code: str,
        code_verifier: str,
        redirect_uri: str,
        client_id: str,
        auth_server: str,
        pds: str,
    ):
        """
        Called during OAuth callback. Exchanges the auth code for tokens,
        creates or updates the User and ATProtoAccount, and returns the User.
        """
        if not code:
            return None

        # Generate a fresh DPoP keypair for this session
        private_key = generate_dpop_key()
        jwk = key_to_jwk(private_key)

        try:
            token_response, nonce = self._exchange_code(
                code,
                code_verifier,
                redirect_uri,
                client_id,
                auth_server,
                private_key,
                jwk,
            )
        except Exception:
            logger.exception("DPoP token exchange failed")
            return None

        did = token_response["sub"]
        access_token = token_response["access_token"]
        refresh_token = token_response["refresh_token"]
        expires_in = token_response.get("expires_in", 3600)

        user, _ = User.objects.get_or_create(username=did)
        try:
            account = ATProtoAccount.objects.get(did=did)
        except ATProtoAccount.DoesNotExist:
            account = ATProtoAccount(did=did)
            account.user = user

        # Persist everything onto the account
        account.access_token = access_token
        account.refresh_token = refresh_token
        account.token_expiry = timezone.now() + timedelta(seconds=expires_in)
        account.set_jwk(jwk)
        account.dpop_nonce = nonce
        account.pds = pds
        account.auth_server = auth_server
        account.save()

        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def refresh_tokens(self, account: ATProtoAccount) -> bool:
        """
        Use the refresh token to obtain a new access token.
        Updates the account in place and saves. Returns True on success.
        """
        private_key = account.get_private_key()
        jwk = account.get_jwk()

        response = post_with_dpop(
            f"{account.auth_server}/oauth/token",
            private_key=private_key,
            jwk=jwk,
            access_token=None,  # no access token during refresh
            nonce=account.dpop_nonce,
            data={
                "grant_type": "refresh_token",
                "refresh_token": account.refresh_token,
            },
        )

        if not response.ok:
            logger.warning("Token refresh failed: %s", response.text)
            account.save(update_fields=["dpop_nonce"])
            return False

        data = response.json()
        account.access_token = data["access_token"]
        account.refresh_token = data.get("refresh_token", account.refresh_token)
        account.token_expiry = timezone.now() + timedelta(
            seconds=data.get("expires_in", 3600)
        )
        account.save()
        return True

    def revoke_token(self, account: ATProtoAccount):
        """Revoke the access token and clear stored credentials."""
        try:
            post_with_dpop(
                f"{account.auth_server}/oauth/revoke",
                private_key=account.get_private_key(),
                jwk=account.get_jwk(),
                access_token=account.access_token,
                nonce=account.dpop_nonce,
                data={"token": account.access_token},
            )
        except Exception:
            logger.warning("Token revocation request failed", exc_info=True)
        finally:
            account.access_token = ""
            account.refresh_token = ""
            account.dpop_nonce = None
            account.save()

    def _exchange_code(
        self,
        code,
        code_verifier,
        redirect_uri,
        client_id,
        auth_server,
        private_key,
        jwk,
    ) -> tuple[dict, str | None]:
        nonce = None

        response = post_with_dpop(
            f"{auth_server}/oauth/token",
            private_key=private_key,
            jwk=jwk,
            nonce=nonce,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": code_verifier,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
            },
        )
        if not response.ok:
            logger.error(
                "Token exchange failed %s: %s", response.status_code, response.text
            )

        response.raise_for_status()

        logger.info("nonce: %s", nonce)
        return response.json(), nonce
