"""Microsoft Entra ID sign-in: OpenID Connect authorization code flow with PKCE.

The backend is a confidential client: it holds the client secret, exchanges the code
server-side and verifies the ID token's signature against the tenant's published keys,
so nothing the browser sends is trusted on its own. Network calls live here, behind
small functions, so tests can replace them.
"""

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

from app.core.config import get_settings

FLOW_COOKIE = "sso_flow"
FLOW_MAX_AGE_SECONDS = 600
_SCOPES = "openid profile email"
_jwks_clients: dict[str, jwt.PyJWKClient] = {}


class EntraError(Exception):
    """The sign-in could not be completed; the message is for the server log only."""


@dataclass(frozen=True)
class Flow:
    state: str
    nonce: str
    verifier: str


def _authority() -> str:
    settings = get_settings()
    return f"{settings.entra_authority_host.rstrip('/')}/{settings.entra_tenant_id}"


def redirect_uri() -> str:
    return f"{get_settings().api_base_url}/auth/sso/callback"


def issuer() -> str:
    # Entra always issues v2.0 tokens from login.microsoftonline.com for the tenant.
    return f"https://login.microsoftonline.com/{get_settings().entra_tenant_id}/v2.0"


def new_flow() -> Flow:
    return Flow(
        state=secrets.token_urlsafe(24),
        nonce=secrets.token_urlsafe(24),
        verifier=secrets.token_urlsafe(48),
    )


def encode_flow(flow: Flow) -> str:
    """The flow travels in a short-lived HttpOnly cookie, signed so it cannot be forged."""
    settings = get_settings()
    return jwt.encode(
        {
            "state": flow.state,
            "nonce": flow.nonce,
            "verifier": flow.verifier,
            "purpose": "entra-sso",
        },
        settings.secret_key,
        algorithm="HS256",
    )


def decode_flow(value: str | None) -> Flow:
    if not value:
        raise EntraError("sign-in cookie missing (expired, or opened in another browser)")
    try:
        data = jwt.decode(value, get_settings().secret_key, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise EntraError(f"sign-in cookie invalid: {exc}") from exc
    if data.get("purpose") != "entra-sso":
        raise EntraError("sign-in cookie has the wrong purpose")
    return Flow(state=data["state"], nonce=data["nonce"], verifier=data["verifier"])


def authorization_url(flow: Flow) -> str:
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(flow.verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    query = urlencode(
        {
            "client_id": get_settings().entra_client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri(),
            "response_mode": "query",
            "scope": _SCOPES,
            "state": flow.state,
            "nonce": flow.nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{_authority()}/oauth2/v2.0/authorize?{query}"


def exchange_code(code: str, verifier: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        response = httpx.post(
            f"{_authority()}/oauth2/v2.0/token",
            data={
                "client_id": settings.entra_client_id,
                "client_secret": settings.entra_client_secret,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri(),
                "code_verifier": verifier,
                "scope": _SCOPES,
            },
            timeout=15,
        )
    except httpx.HTTPError as exc:
        raise EntraError(f"token endpoint unreachable: {exc}") from exc
    if response.status_code != 200:
        # Entra's error body names the problem (e.g. AADSTS7000215 wrong secret).
        raise EntraError(f"token endpoint returned {response.status_code}: {response.text[:300]}")
    return response.json()


def signing_key(id_token: str) -> Any:
    jwks_url = f"{_authority()}/discovery/v2.0/keys"
    client = _jwks_clients.get(jwks_url)
    if client is None:
        client = _jwks_clients[jwks_url] = jwt.PyJWKClient(jwks_url, cache_keys=True)
    return client.get_signing_key_from_jwt(id_token).key


def validate_id_token(id_token: str, nonce: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        claims = jwt.decode(
            id_token,
            signing_key(id_token),
            algorithms=["RS256"],
            audience=settings.entra_client_id,
            issuer=issuer(),
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
            leeway=60,
        )
    except jwt.PyJWTError as exc:
        raise EntraError(f"ID token rejected: {exc}") from exc
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise EntraError("ID token nonce does not match this sign-in")
    if claims.get("tid") != settings.entra_tenant_id:
        raise EntraError("ID token is from another tenant")
    if not claims.get("oid"):
        raise EntraError("ID token has no object id")
    return claims
