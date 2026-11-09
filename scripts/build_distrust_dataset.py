from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

ROOT = Path(__file__).resolve().parents[1] / "src" / "links" / "data" / "ca_distrust"


def main():
    import json
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    print("id\tsubject\tissuer\tserial\tcertificate_sha256\tspki_sha256\tmanifest_match")
    for item in manifest.get("records", []):
        cert = x509.load_pem_x509_certificate((ROOT / item["cert_file"]).read_bytes())
        fp = cert.fingerprint(hashes.SHA256()).hex()
        spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        import hashlib
        print(f"{item['id']}\t{cert.subject.rfc4514_string()}\t{cert.issuer.rfc4514_string()}\t{cert.serial_number:x}\t{fp}\t{hashlib.sha256(spki).hexdigest()}\t{fp == item['expected_cert_sha256'].replace(':', '').lower()}")


if __name__ == "__main__":
    main()
