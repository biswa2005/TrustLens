def main() -> None:
    import os
    import sys

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

    import uvicorn
    from main import app

    uvicorn.run(app, host="0.0.0.0", port=8000)
