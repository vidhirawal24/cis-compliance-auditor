"""Verified identity and canonical role permissions; no user-metadata authority."""

import json
import threading
import time
from dataclasses import dataclass
from importlib.resources import files
from uuid import UUID

import httpx
import jwt
from fastapi import HTTPException

MATRIX = json.loads(files("cisguard_contracts.v1").joinpath("permissions.json").read_text())


@dataclass(frozen=True)
class Identity:
    user_id: UUID
    aal: str
    expires: int
    email: str | None
    mfa_enrolled: bool = False


class TokenVerifier:
    def __init__(self, settings, transport=None):
        self.settings = settings
        self.transport = transport
        self.keys = {}
        self.loaded_at = 0.0
        self.lock = threading.Lock()

    def _request(self, path, headers=None):
        try:
            with httpx.Client(transport=self.transport, timeout=10, follow_redirects=False) as client:
                response = client.get(self.settings.supabase_url + path, headers=headers)
            if response.status_code >= 500:
                raise HTTPException(503, "Authentication provider unavailable")
            return response
        except httpx.HTTPError:
            raise HTTPException(503, "Authentication provider unavailable") from None

    def _key(self, kid, algorithm):
        with self.lock:
            now = time.monotonic()
            # Bounded cache; unknown kids trigger a refresh, throttled against random-kid flooding.
            if now - self.loaded_at > 300 or (kid not in self.keys and now - self.loaded_at > 5):
                response = self._request("/auth/v1/.well-known/jwks.json")
                if response.status_code != 200:
                    raise HTTPException(503, "Signing keys unavailable")
                try:
                    keys = response.json()["keys"]
                    self.keys = {
                        k["kid"]: k
                        for k in keys
                        if k.get("kty") in ("RSA", "EC") and k.get("use", "sig") == "sig"
                    }
                except (ValueError, KeyError, TypeError):
                    raise HTTPException(503, "Invalid signing key response") from None
                self.loaded_at = now
            key = self.keys.get(kid)
            if not key or key.get("alg", algorithm) != algorithm:
                raise HTTPException(401, "Unrecognized signing key")
            if (algorithm == "RS256" and key["kty"] != "RSA") or (
                algorithm == "ES256" and (key["kty"] != "EC" or key.get("crv") != "P-256")
            ):
                raise HTTPException(401, "Invalid signing key type")
            return jwt.PyJWK.from_dict(key, algorithm=algorithm).key

    def verify(self, token):
        if not token or len(token) > 16384:
            raise HTTPException(401, "Invalid access token")
        try:
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg")
            if algorithm not in ("RS256", "ES256", "HS256") or header.get("crit"):
                raise HTTPException(401, "Unsupported token algorithm")
            options = {
                "require": ["exp", "iat", "sub", "iss", "aud"],
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
                "verify_aud": True,
                "verify_iss": True,
            }
            if algorithm in ("RS256", "ES256"):
                claims = jwt.decode(
                    token,
                    self._key(header.get("kid"), algorithm),
                    algorithms=[algorithm],
                    audience="authenticated",
                    issuer=self.settings.supabase_url + "/auth/v1",
                    options=options,
                )
            else:
                # Legacy HS256 secret is never fetched or inferred from the public anon key.
                claims = None
            # Online check also covers revoked/deleted users and legacy signature validation.
            response = self._request(
                "/auth/v1/user",
                {
                    "apikey": self.settings.supabase_anon_key.get_secret_value(),
                    "Authorization": "Bearer " + token,
                },
            )
            if response.status_code != 200:
                raise HTTPException(401, "Invalid or revoked access token")
            user = response.json()
            if claims is None:
                claims = jwt.decode(
                    token,
                    options={**options, "verify_signature": False},
                    audience="authenticated",
                    issuer=self.settings.supabase_url + "/auth/v1",
                )
            subject = UUID(claims["sub"])
            if UUID(user["id"]) != subject or claims.get("role") != "authenticated":
                raise HTTPException(401, "Invalid user identity")
            aal = claims.get("aal", "aal1")
            if aal not in ("aal1", "aal2"):
                raise HTTPException(401, "Invalid assurance level")
            email = user.get("email") if user.get("email_confirmed_at") else None
            enrolled = aal == "aal2" or any(f.get("status") == "verified" for f in user.get("factors", []))
            return Identity(subject, aal, claims["exp"], email.lower() if email else None, enrolled)
        except (jwt.PyJWTError, ValueError, KeyError, TypeError):
            raise HTTPException(401, "Invalid access token") from None


def require_permission(role, permission, aal, *, privileged=False):
    if permission not in MATRIX["roles"].get(role, []):
        raise HTTPException(403, "Permission denied")
    if (privileged or role in MATRIX["mfa_roles"]) and aal != "aal2":
        raise HTTPException(403, "MFA_REQUIRED")


def require_independent_approver(approver_id, author_id, operator_id):
    if approver_id in (author_id, operator_id):
        raise HTTPException(403, "Approver must differ from plan author and operator")
