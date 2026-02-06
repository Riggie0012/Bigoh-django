from .settings import *  # noqa: F403

# Production defaults (can still be overridden by env flags in settings.py)
DEBUG = False

# Fail fast if SECRET_KEY is still the unsafe fallback.
if SECRET_KEY == "unsafe-dev-key":  # noqa: F405
    raise RuntimeError("DJANGO_SECRET_KEY is required in production.")
