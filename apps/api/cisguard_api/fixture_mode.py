"""Synthetic demonstrations must never silently become runtime evidence."""
from .settings import get_settings


def enabled() -> bool:
    settings = get_settings()
    return settings.environment == 'test' and settings.enable_synthetic_fixtures
