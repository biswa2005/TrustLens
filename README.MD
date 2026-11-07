# TrustLens

Boilerplate FastAPI project managed with `uv`.

## Run

```bash
uv sync
uv run uvicorn --app-dir src main:app --host 0.0.0.0 --port 8000
```

Then open http://localhost:8000.

## Health

- `GET /` -> `{"status": "ok"}`
