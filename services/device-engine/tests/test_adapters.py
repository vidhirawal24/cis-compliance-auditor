import pytest

from cisguard_device.adapters import AdapterRegistry, UnsupportedPlatformError


def test_unsupported_adapter_is_explicit() -> None:
    registry = AdapterRegistry()
    with pytest.raises(UnsupportedPlatformError, match="not_real") as captured:
        registry.get("not_real")
    assert captured.value.platform == "not_real"
