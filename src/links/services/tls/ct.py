from cryptography import x509


def inspect_embedded_scts(cert: x509.Certificate) -> tuple[str, dict]:
    """Classify embedded SCT presence and basic structure; does not validate signatures or logs."""
    try:
        extension = cert.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps).value
    except x509.ExtensionNotFound:
        return "not_present", {}
    except ValueError:
        return "embedded_present_malformed", {"reason": "malformed_extension"}
    try:
        scts = tuple(extension)
        if not scts:
            return "embedded_present_malformed", {"reason": "empty_sct_list"}
        for item in scts:
            if item.version.name.lower() != "v1" or not item.log_id or item.timestamp is None:
                return "embedded_present_malformed", {"reason": "invalid_sct_fields"}
        return "embedded_present_parsed", {"sct_count": len(scts)}
    except (ValueError, TypeError, AttributeError):
        return "embedded_present_malformed", {"reason": "malformed_sct"}
