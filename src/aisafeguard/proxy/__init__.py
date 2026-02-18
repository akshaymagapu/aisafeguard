"""FastAPI proxy for AISafe Guard."""

from aisafeguard.proxy.server import create_app

__all__ = ["create_app"]
