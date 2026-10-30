"""Worker-only OpenBao KV v2 access. No API route returns these values."""

from dataclasses import dataclass
from uuid import UUID
from urllib.parse import urlsplit
import httpx
from pydantic import SecretStr


@dataclass(frozen=True)
class WorkerGrant:
    org_id: UUID
    reference_id: UUID
    token: SecretStr  # short-lived, exact-path token provisioned to the eligible worker


class OpenBao:
    def __init__(self, address, transport=None):
        origin = urlsplit(address)
        if (
            not origin.hostname
            or origin.username
            or origin.path not in ("", "/")
            or origin.query
            or origin.fragment
        ):
            raise ValueError("Invalid OpenBao address")
        if origin.scheme == "http":
            if origin.hostname not in ("localhost", "127.0.0.1"):
                raise ValueError("HTTP OpenBao is only permitted on loopback/localhost development")
        elif origin.scheme != "https":
            raise ValueError("OpenBao requires a fixed HTTPS origin or local HTTP loopback")
        self.address, self.transport = address.rstrip("/"), transport

    def login_approle(self, role_id: str | SecretStr, secret_id: str | SecretStr) -> SecretStr:
        r_val = role_id.get_secret_value() if isinstance(role_id, SecretStr) else role_id
        s_val = secret_id.get_secret_value() if isinstance(secret_id, SecretStr) else secret_id
        try:
            with httpx.Client(transport=self.transport, timeout=10, follow_redirects=False) as client:
                res = client.post(
                    f"{self.address}/v1/auth/approle/login",
                    json={"role_id": r_val, "secret_id": s_val},
                )
            if res.status_code != 200:
                raise PermissionError(f"OpenBao AppRole authentication denied (HTTP {res.status_code})")
            payload = res.json()
            client_token = payload.get("auth", {}).get("client_token")
            if not client_token:
                raise PermissionError("OpenBao AppRole response missing client token")
            return SecretStr(client_token)
        except (httpx.HTTPError, KeyError, TypeError) as exc:
            if isinstance(exc, PermissionError):
                raise
            raise PermissionError("OpenBao service unreachable or login failed") from None

    def read_kv_secret(self, path: str, token: SecretStr, kv_mount: str = "secret") -> dict[str, SecretStr]:
        clean_path = path.lstrip("/")
        t_val = token.get_secret_value()
        try:
            with httpx.Client(transport=self.transport, timeout=10, follow_redirects=False) as client:
                res = client.get(
                    f"{self.address}/v1/{kv_mount}/data/{clean_path}",
                    headers={"X-Vault-Token": t_val},
                )
            if res.status_code == 404:
                raise KeyError(f"Secret not found at path '{clean_path}' in mount '{kv_mount}'")
            if res.status_code in (401, 403):
                raise PermissionError(f"Permission denied to path '{clean_path}' in mount '{kv_mount}'")
            if res.status_code != 200:
                raise PermissionError(f"Secret retrieval failed (HTTP {res.status_code})")
            data = res.json().get("data", {}).get("data", {})
            if not isinstance(data, dict):
                raise ValueError("Invalid KV v2 payload structure")
            return {k: SecretStr(str(v)) for k, v in data.items()}
        except (httpx.HTTPError, TypeError) as exc:
            if isinstance(exc, (PermissionError, KeyError)):
                raise
            raise PermissionError("OpenBao service unavailable") from None

    def list_kv_root(self, token: SecretStr, kv_mount: str = "secret") -> list[str]:
        t_val = token.get_secret_value()
        try:
            with httpx.Client(transport=self.transport, timeout=10, follow_redirects=False) as client:
                res = client.request(
                    "LIST",
                    f"{self.address}/v1/{kv_mount}/metadata",
                    headers={"X-Vault-Token": t_val},
                )
            if res.status_code in (401, 403):
                raise PermissionError(f"Permission denied: worker cannot list KV root (HTTP {res.status_code})")
            if res.status_code == 200:
                keys = res.json().get("data", {}).get("keys", [])
                return keys
            raise PermissionError(f"Listing unexpected status HTTP {res.status_code}")
        except httpx.HTTPError:
            raise PermissionError("OpenBao service unavailable") from None

    def read(self, grant: WorkerGrant, org_id: UUID, reference_id: UUID):
        if grant.org_id != org_id or grant.reference_id != reference_id:
            raise PermissionError("Worker grant scope mismatch")
        path = f"/v1/device-secrets/data/{org_id}/{reference_id}"
        try:
            with httpx.Client(transport=self.transport, timeout=10, follow_redirects=False) as client:
                response = client.get(
                    self.address + path, headers={"X-Vault-Token": grant.token.get_secret_value()}
                )
            if response.status_code != 200:
                raise PermissionError("Secret unavailable or worker grant denied")
            data = response.json()["data"]["data"]
            if not isinstance(data, dict) or not data or any(not isinstance(v, str) for v in data.values()):
                raise ValueError("Invalid secret payload")
            return {k: SecretStr(v) for k, v in data.items()}
        except (httpx.HTTPError, KeyError, TypeError):
            raise PermissionError("Secret provider unavailable") from None
