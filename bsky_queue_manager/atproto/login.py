import base64
import hashlib
import secrets
from urllib.parse import urlencode, urlparse
import os

import requests
from atproto import IdResolver
from django.contrib.auth import authenticate, login
from django.http import HttpRequest, HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect, render

from bsky_queue_manager.forms import LoginForm

RESOLVER = IdResolver()


# IMPORTANT TODO: SSRF-protection


def _pkce_pair() -> tuple[str, str]:
    code_verifier = secrets.token_urlsafe(64)
    verifier_bytes = code_verifier.encode("ascii")
    sha256_hash = hashlib.sha256(verifier_bytes).digest()

    code_challenge = base64.urlsafe_b64encode(sha256_hash).decode("ascii").rstrip("=")

    return code_verifier, code_challenge


# TODO: actual client ID document


def _get_redirect_uri() -> str:
    if os.environ.get("VERCEL_URL"):
        external_url = f"https://{os.environ['VERCEL_URL']}"
    else:
        external_url = "http://127.0.0.1:8000"

    return f"{external_url}/oauth_callback"


def _get_client_id() -> str:
    if os.environ.get("VERCEL_URL"):
        client_id = f"https://{os.environ['VERCEL_URL']}/client-metadata.json"
    else:
        redirect_uri = _get_redirect_uri()

        id_params = {
            "redirect_uri": redirect_uri,
        }
        id_query_string = urlencode(id_params)

        client_id = f"http://localhost?{id_query_string}"

    return client_id


def _is_safe_next(next_url: str) -> bool:
    """
    Returns True only if next_url is a relative path on this server.
    Rejects absolute URLs (which could point to external sites) and
    protocol-relative URLs like //evil.com.
    """
    if not next_url:
        return False

    parsed = urlparse(next_url)

    if parsed.scheme or parsed.netloc:
        return False

    if not next_url.startswith("/") or next_url.startswith("//"):
        return False

    return True


def _init(request: HttpRequest, handle: str) -> str | HttpResponseRedirect:
    """
    Initialise the AtProto OAuth flow.

    Args:
        request: the HttpRequest recieved to the /login endpoint.
        handle: the handle we're trying to log in with

    Returns:
        An HttpResponseRedirect taking the user to their PDS to authenticate,
        or a str representing an error message.
    """

    did = RESOLVER.handle.resolve(handle)
    if did is None:
        return "Failed to resolve DID! Is your handle correct?"

    doc = RESOLVER.did.resolve(did)
    if doc is None:
        return "Failed to resolve DID information! This might be a backend error."

    pds_address = doc.get_service_endpoint("#atproto_pds", "AtprotoPersonalDataServer")
    if pds_address is None:
        return "Failed to find PDS information! Is your handle correct?"

    try:
        oauth_resource_url = f"{pds_address}/.well-known/oauth-protected-resource"
        oauth_resource = requests.get(oauth_resource_url).json()
        oauth_server_url = oauth_resource["authorization_servers"][0]
    except Exception:
        return "Failed to find OAuth information! Is your handle correct?"

    code_verifier, code_challenge = _pkce_pair()
    state = secrets.token_urlsafe(32)
    redirect_uri = _get_redirect_uri()
    client_id = _get_client_id()

    form_data = {
        "client_id": client_id,
        "response_type": "code",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "redirect_uri": redirect_uri,
        "scope": "atproto",
    }

    response = requests.post(f"{oauth_server_url}/oauth/par", data=form_data)
    try:
        response.raise_for_status()
        request_uri = response.json()["request_uri"]
    except Exception:
        return "Failed to initialise OAuth flow! This might be a backend error."

    redirect_params = {
        "client_id": client_id,
        "request_uri": request_uri,
    }
    redirect_query_string = urlencode(redirect_params)
    redirect_url = f"{oauth_server_url}/oauth/authorize?{redirect_query_string}"

    raw_next = request.POST.get("next", default="/")
    next = raw_next if _is_safe_next(raw_next) else "/"

    request.session[f"oauth_state_{state}"] = state
    request.session[f"oauth_code_verifier_{state}"] = code_verifier
    request.session[f"oauth_server_url_{state}"] = oauth_server_url
    request.session[f"pds_address_{state}"] = pds_address
    request.session[f"next_{state}"] = next

    return HttpResponseRedirect(redirect_url)


def client_metadata_view(request: HttpRequest):
    client_id = _get_client_id()
    redirect_uri = _get_redirect_uri()

    metadata = {
        "client_id": client_id,
        "client_name": "Queuesky",
        "redirect_uris": [redirect_uri],
        "scope": "atproto",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "web",
        "dpop_bound_access_tokens": True,
    }

    return JsonResponse(metadata)


def login_view(request: HttpRequest):
    """
    This view presents a form requesting a user's ATProto handle so we can
    initiate the OAuth flow.
    """

    if request.user.is_authenticated:
        return redirect("/")

    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            res = _init(request, form.cleaned_data["handle"])

            if isinstance(res, str):
                form.add_error("handle", res)
            else:
                return res
    else:
        form = LoginForm()

    return render(request, "bsky_queue_manager/login.html", {"form": form})


def oauth_callback_view(request: HttpRequest):
    """
    This view completes the AtProto OAuth flow. It logs in with the auth
    framework if the provided information is valid.

    Args:
        request: the HttpRequest recieved to the /oauth_callback endpoint.
    """

    incoming_state = request.GET.get("state")
    auth_code = request.GET.get("code")

    if not incoming_state or not auth_code:
        return redirect("/login")

    saved_state = request.session.pop(f"oauth_state_{incoming_state}", None)

    if saved_state is None:
        return redirect("/login")

    oauth_code = request.GET.get("code")

    code_verifier = request.session.pop(f"oauth_code_verifier_{incoming_state}")
    oauth_server_url = request.session.pop(f"oauth_server_url_{incoming_state}")
    pds_address = request.session.pop(f"pds_address_{incoming_state}")
    next = request.session.pop(f"next_{incoming_state}")

    user = authenticate(
        request,
        code=oauth_code,
        code_verifier=code_verifier,
        redirect_uri=_get_redirect_uri(),
        client_id=_get_client_id(),
        auth_server=oauth_server_url,
        pds=pds_address,
    )
    if user:
        login(request, user, backend="bsky_queue_manager.atproto.auth.ATProtoBackend")
        return redirect(next)
    else:
        return redirect("/login")
