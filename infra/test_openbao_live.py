import pytest
from pydantic import SecretStr
from cisguard_api.bao import OpenBao
from cisguard_api.settings import get_settings

s = get_settings()

print("=== OPENBAO LIVE INTEGRATION AUDIT ===")

# 1. Verify Configuration Loading
print(f"Loading OpenBao address: {s.openbao_addr} (mount: {s.openbao_kv_mount})")
assert s.openbao_addr == "http://127.0.0.1:8201"
assert s.openbao_kv_mount == "secret"
role_id = s.openbao_role_id
secret_id = s.openbao_secret_id
assert len(role_id.get_secret_value()) > 0, "Role ID missing from settings"
assert len(secret_id.get_secret_value()) > 0, "Secret ID missing from settings"
print("  [PASS] Configuration loaded securely as SecretStr (masked)")

# 2. Initialize Client
bao = OpenBao(s.openbao_addr)
print("  [PASS] OpenBao client initialized")

# 3. Test AppRole Authentication
print("Authenticating with AppRole...")
client_token = bao.login_approle(role_id, secret_id)
assert isinstance(client_token, SecretStr)
assert len(client_token.get_secret_value()) > 0
print(f"  [PASS] AppRole login succeeded. Token acquired (masked length: {len(client_token.get_secret_value())})")

# 4. Read Authorized Device Secret
secret_path = "cisguard/devices/lab-router"
print(f"Reading KV v2 secret at '{secret_path}'...")
credentials = bao.read_kv_secret(secret_path, client_token, kv_mount=s.openbao_kv_mount)
print("  Secret fields present:", list(credentials.keys()))
assert "username" in credentials
assert "password" in credentials
assert credentials["username"].get_secret_value() == "demo"
assert credentials["password"].get_secret_value() == "dummy-only"
# Verify masking in string representations
assert "dummy-only" not in str(credentials)
assert "dummy-only" not in repr(credentials)
print("  [PASS] Device secret retrieved and verified! Secret masking confirmed in repr/str.")

# 5. Test Missing Secret Behavior (404 -> KeyError)
print("Testing non-existent secret handling...")
try:
    bao.read_kv_secret("cisguard/devices/nonexistent-device", client_token, kv_mount=s.openbao_kv_mount)
    raise AssertionError("Expected KeyError for missing secret")
except KeyError as e:
    print(f"  [PASS] Missing secret correctly raised KeyError: {e}")

# 6. Test Restricted Worker Cannot List Root of KV Store (403 -> PermissionError)
print("Testing root KV listing restriction...")
try:
    keys = bao.list_kv_root(client_token, kv_mount=s.openbao_kv_mount)
    raise AssertionError(f"Expected PermissionError, but listing succeeded: {keys}")
except PermissionError as e:
    print(f"  [PASS] Root KV listing correctly denied with HTTP 403 / PermissionError: {e}")

# 7. Test Invalid AppRole Credentials (Error Handling)
print("Testing invalid AppRole Secret ID...")
try:
    bao.login_approle(role_id, SecretStr("invalid-secret-id-0000-000000000000"))
    raise AssertionError("Expected PermissionError for invalid Secret ID")
except PermissionError as e:
    print(f"  [PASS] Invalid Secret ID correctly raised PermissionError: {e}")

print("=== OPENBAO AUDIT COMPLETE: ALL PASS ===")

