import base64
import hashlib
import hmac
import time
from uuid import UUID
from fastapi import HTTPException


def encode_cursor(org_id, last_id, key):
    payload = f"{org_id}:{last_id}:{int(time.time()) + 900}"
    signature = hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{signature}".encode()).decode()


def decode_cursor(cursor, org_id, key):
    try:
        if len(cursor) > 512 or not key:
            raise ValueError()
        tenant, last, expires, signature = (
            base64.b64decode(cursor, altchars=b"-_", validate=True).decode().split(":")
        )
        payload = f"{tenant}:{last}:{expires}"
        expected = hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if (
            not hmac.compare_digest(signature, expected)
            or UUID(tenant) != org_id
            or int(expires) <= time.time()
        ):
            raise ValueError()
        return UUID(last)
    except (ValueError, UnicodeError):
        raise HTTPException(422, "Invalid or expired cursor") from None
