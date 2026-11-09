from __future__ import annotations

import idna
import tldextract
from confusable_homoglyphs.confusables import confusables_data

_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
_KEYBOARD = {"a": "sqwz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
             "g": "ftyhbv", "i": "ujko", "l": "kop", "n": "bhjm", "o": "iklp",
             "r": "edft", "s": "awedxz", "t": "rfgy", "u": "yihj", "y": "tugh"}
_COMBOS = ("login", "secure", "verify", "account", "support", "online", "signin", "update", "portal", "wallet")
_TLD_ALTS = ("com", "net", "org", "co", "info", "site", "online", "app", "io", "xyz")


def _homoglyph_replacements(char: str):
    emitted = 0
    for item in confusables_data.get(char, ()):
        candidate = item.get("c", "")
        if len(candidate) != 1 or candidate.isascii() or not candidate.isalpha():
            continue
        try:
            encoded = idna.encode(candidate, uts46=True).decode("ascii").lower()
        except (idna.IDNAError, UnicodeError):
            continue
        if encoded == char:
            continue
        yield candidate
        emitted += 1
        if emitted == 3:
            break


def generate_candidates(domain_ascii: str, known_own_domains=(), cap: int = 500) -> list[str]:
    """Return deterministic ASCII candidates from ten prioritized mutation families."""
    ext = _extract(domain_ascii)
    if not ext.domain or not ext.suffix:
        return []
    label, suffix = ext.domain.lower(), ext.suffix.lower()
    own = {domain_ascii.lower(), *(str(item).lower() for item in known_own_domains)}
    candidates: list[str] = []
    seen: set[str] = set()

    def add(value: str):
        if len(candidates) >= cap:
            return
        try:
            ascii_name = idna.encode(value.lower(), uts46=True).decode("ascii")
        except (idna.IDNAError, UnicodeError):
            return
        if ascii_name not in own and ascii_name not in seen:
            seen.add(ascii_name)
            candidates.append(ascii_name)

    # 1. Single-character omission.
    for i in range(len(label)):
        add(label[:i] + label[i + 1:] + "." + suffix)
    # 2. Adjacent transposition.
    for i in range(len(label) - 1):
        if label[i] != label[i + 1]:
            add(label[:i] + label[i + 1] + label[i] + label[i + 2:] + "." + suffix)
    # 3. One Unicode confusable substitution (punycoded by add()).
    for i, char in enumerate(label):
        for replacement in _homoglyph_replacements(char):
            add(label[:i] + replacement + label[i + 1:] + "." + suffix)
    # 4. Hyphen insertion at each interior boundary.
    for i in range(1, len(label)):
        add(label[:i] + "-" + label[i:] + "." + suffix)
    # 5. Bitsquatting, flipping one bit in a lower-case ASCII letter.
    for i, char in enumerate(label):
        code = ord(char)
        for bit in (1, 2, 4, 8, 16):
            replacement = chr(code ^ bit)
            if replacement.isascii() and replacement.isalnum():
                add(label[:i] + replacement + label[i + 1:] + "." + suffix)
    # 6. Security-word combosquatting.
    for word in _COMBOS:
        add(label + word + "." + suffix)
        add(word + label + "." + suffix)
    # 7. Repeated-character insertion.
    for i, char in enumerate(label):
        add(label[:i] + char + label[i:] + "." + suffix)
    # 8. Adjacent keyboard substitutions.
    for i, char in enumerate(label):
        for replacement in _KEYBOARD.get(char, ""):
            add(label[:i] + replacement + label[i + 1:] + "." + suffix)
    # 9. Dot/hyphen boundary variants.
    for i in range(1, len(label)):
        add(label[:i] + "." + label[i:] + "." + suffix)
    # 10. Common TLD substitution.
    for tld in _TLD_ALTS:
        if tld != suffix:
            add(label + "." + tld)
    return candidates[:max(0, min(cap, 500))]
