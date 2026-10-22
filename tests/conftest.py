"""Every test runs OFFLINE: sockets are blocked and API keys are removed from the environment."""
import socket

import pytest


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    def refuse(*a, **k):
        raise RuntimeError("network access attempted in a test")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    for k in ("TYPESAFE_API_KEY", "ANTHROPIC_API_KEY", "PEEPHOLE_KILL_SWITCH"):
        monkeypatch.delenv(k, raising=False)
    try:
        import pydantic_ai.models as m
        monkeypatch.setattr(m, "ALLOW_MODEL_REQUESTS", False)
    except Exception:
        pass
