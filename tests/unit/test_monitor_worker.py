import asyncio

from links import worker
from links.worker import _safe_loop


def test_safe_loop_cancellation_propagates_cleanly():
    async def scenario():
        started = asyncio.Event()

        async def callback():
            started.set()
            await asyncio.Event().wait()

        task = asyncio.create_task(_safe_loop("test", callback, 60))
        await started.wait()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            return
        raise AssertionError("cancelled worker loop did not propagate cancellation")

    asyncio.run(scenario())


def test_ct_stream_closes_source_on_cancellation(monkeypatch):
    async def scenario():
        connected = asyncio.Event()
        closed = asyncio.Event()

        class FakeSource:
            async def connect(self):
                connected.set()

            async def messages(self):
                await asyncio.Event().wait()
                yield {}

            async def close(self):
                closed.set()

        monkeypatch.setattr(worker, "WebSocketCTSource", FakeSource)
        monkeypatch.setattr(worker.db, "pool", None)
        task = asyncio.create_task(worker._ct_stream_loop())
        await connected.wait()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert closed.is_set()

    asyncio.run(scenario())
