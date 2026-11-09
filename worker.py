from pathlib import Path
import sys
from dotenv import load_dotenv

_root = Path(__file__).resolve().parent
load_dotenv(_root / ".env")
sys.path.insert(0, str(_root / "src"))

from links.worker import main


if __name__ == "__main__":
    main()
