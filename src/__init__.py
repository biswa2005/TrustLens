def main() -> None:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent))

    from links.services.runtime import run_uvicorn

    run_uvicorn("main:app", host="0.0.0.0", port=8000)
