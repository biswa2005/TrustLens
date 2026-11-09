from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from links.services.tls.distrust import load_dataset, validate_manifest


def main() -> None:
    manifest = validate_manifest()
    dataset = load_dataset()
    expected_records = len(manifest.get("records", []))
    if len(dataset.records) != expected_records:
        raise SystemExit(f"CA distrust verification failed: {len(dataset.records)} of {expected_records} records verified")
    print(f"Verified {len(dataset.records)} CA distrust records ({dataset.version})")


if __name__ == "__main__":
    main()
