import sys
from pathlib import Path
from dotenv import load_dotenv

ROOT=Path(__file__).resolve().parent
load_dotenv(ROOT/".env")
sys.path.insert(0, str(ROOT / "src"))

def main():
    from links.services.runtime import run_uvicorn
    run_uvicorn("main:app", host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
