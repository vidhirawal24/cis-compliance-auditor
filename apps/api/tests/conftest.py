from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages/contracts/v1"))
sys.path.insert(0, str(ROOT / "apps/api"))

# Unit HTTP denial tests must not write to the configured live database.
import pytest


@pytest.fixture(autouse=True)
def no_live_http_audit(monkeypatch):
    monkeypatch.setattr('cisguard_api.main.record_denial', lambda *args: None)


@pytest.fixture
def synthetic_device_engine(monkeypatch):
    """Explicit opt-in for legacy synthetic fixture tests; never a runtime default."""
    from cisguard_api.settings import get_settings
    monkeypatch.setattr(get_settings(), 'environment', 'test')
    monkeypatch.setattr(get_settings(), 'enable_synthetic_fixtures', True)
