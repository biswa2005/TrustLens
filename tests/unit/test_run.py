import asyncio

from links.services.runtime import event_loop_factory


def test_windows_launcher_forces_psycopg_compatible_event_loop():
    assert event_loop_factory("win32") is asyncio.SelectorEventLoop


def test_non_windows_launcher_uses_uvicorn_default_loop():
    assert event_loop_factory("linux") is None
