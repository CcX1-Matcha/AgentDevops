"""Compatibility entrypoint.

Run ``uvicorn app:app`` from the repository root, or use
``uvicorn backend.app.main:app`` when importing the package explicitly.
"""

from backend.app.main import app

__all__ = ["app"]
