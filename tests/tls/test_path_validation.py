from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.x509.name import _ASN1Type

from links.models_tls import ChainStatus
from links.services.tls.path_validator import validate_chain
from scripts.make_tls_fixtures import (
    FIXED_NOW,
    ec_key,
    ed448_key,
    issue_ca,
    issue_leaf,
    issue_self_signed_leaf,
    make_store,
    name,
)


def _root(common_name="Trusted Root", *, key_number=1, path_length=None):
    key = ec_key(key_number)
    cert = issue_ca(common_name, key, serial=key_number, path_length=path_length)
    return cert, key


def test_valid_chain_ending_at_store_root():
    root, root_key = _root()
    leaf = issue_leaf(root, root_key, serial=101)

    status, _ = validate_chain(leaf, [root], "example.test", FIXED_NOW, make_store([root]))

    assert status == ChainStatus.VALID_TRUSTED


def test_leaf_issuer_matches_store_root_subject_and_key_identifiers():
    root, root_key = _root("Direct Store Issuer", key_number=2)
    leaf = issue_leaf(root, root_key, serial=102)

    status, _ = validate_chain(leaf, [], "example.test", FIXED_NOW, make_store([root]))

    assert status == ChainStatus.VALID_TRUSTED


def test_cross_signed_supplied_root_key_anchors_and_truncates_chain():
    trusted_root, trusted_key = _root("Store Root", key_number=10)
    missing_issuer_key = ec_key(11)
    cross_signed = issue_ca(
        "Cross Signed Root", trusted_key, serial=11,
        issuer=name("Missing Cross Sign Issuer"), issuer_key=missing_issuer_key,
    )
    intermediate_key = ec_key(12)
    intermediate = issue_ca(
        "Intermediate", intermediate_key, serial=12,
        issuer=cross_signed.subject, issuer_key=trusted_key, path_length=0,
    )
    leaf = issue_leaf(intermediate, intermediate_key, serial=112)

    status, _ = validate_chain(
        leaf, [intermediate, cross_signed], "example.test", FIXED_NOW,
        make_store([trusted_root]),
    )

    assert status == ChainStatus.VALID_TRUSTED


def test_missing_top_issuer_is_incomplete_chain():
    unrelated_root, _ = _root("Unrelated Store Root", key_number=20)
    top_key = ec_key(21)
    top = issue_ca(
        "Supplied Top", top_key, serial=21,
        issuer=name("Absent Issuer"), issuer_key=ec_key(22),
    )
    leaf = issue_leaf(top, top_key, serial=121)

    status, _ = validate_chain(leaf, [top], "example.test", FIXED_NOW, make_store([unrelated_root]))

    assert status == ChainStatus.INCOMPLETE_CHAIN


def test_valid_self_signed_leaf_is_self_signed():
    leaf = issue_self_signed_leaf(serial=301)
    unrelated_root, _ = _root("Self-Signed Leaf Test Root", key_number=304)

    status, _ = validate_chain(leaf, [], "example.test", FIXED_NOW, make_store([unrelated_root]))

    assert status == ChainStatus.SELF_SIGNED


def test_invalid_self_signature_is_signature_invalid():
    leaf_key = ec_key(302)
    leaf = issue_self_signed_leaf(serial=302, key=leaf_key, signer_key=ec_key(303))
    unrelated_root, _ = _root("Invalid Self Signature Test Root", key_number=305)

    status, _ = validate_chain(leaf, [], "example.test", FIXED_NOW, make_store([unrelated_root]))

    assert status == ChainStatus.SIGNATURE_INVALID


def test_self_signed_untrusted_root_is_untrusted_root():
    untrusted_root, untrusted_key = _root("Untrusted Root", key_number=31)
    unrelated_root, _ = _root("Different Trusted Root", key_number=32)
    leaf = issue_leaf(untrusted_root, untrusted_key, serial=131)

    status, _ = validate_chain(
        leaf, [untrusted_root], "example.test", FIXED_NOW, make_store([unrelated_root]),
    )

    assert status == ChainStatus.UNTRUSTED_ROOT


def test_expired_leaf_reports_expired():
    root, root_key = _root("Expired Leaf Test Root", key_number=40)
    leaf = issue_leaf(
        root, root_key, serial=140,
        not_before=FIXED_NOW - timedelta(days=10),
        not_after=FIXED_NOW - timedelta(seconds=1),
    )

    status, evidence = validate_chain(leaf, [root], "example.test", FIXED_NOW, make_store([root]))

    assert status == ChainStatus.EXPIRED
    assert evidence["index"] == 0


def test_expired_intermediate_reports_expired():
    root, root_key = _root("Expired Intermediate Test Root", key_number=41)
    int_key = ec_key(42)
    intermediate = issue_ca(
        "Expired Intermediate", int_key, serial=42,
        issuer=root.subject, issuer_key=root_key, path_length=0,
        not_before=FIXED_NOW - timedelta(days=10),
        not_after=FIXED_NOW - timedelta(seconds=1),
    )
    leaf = issue_leaf(intermediate, int_key, serial=142)

    status, evidence = validate_chain(
        leaf, [intermediate, root], "example.test", FIXED_NOW, make_store([root]),
    )

    assert status == ChainStatus.EXPIRED
    assert evidence["index"] == 1


def test_not_yet_valid_intermediate_reports_not_yet_valid():
    root, root_key = _root("Future Intermediate Test Root", key_number=43)
    int_key = ec_key(44)
    intermediate = issue_ca(
        "Future Intermediate", int_key, serial=44,
        issuer=root.subject, issuer_key=root_key, path_length=0,
        not_before=FIXED_NOW + timedelta(seconds=1),
        not_after=FIXED_NOW + timedelta(days=30),
    )
    leaf = issue_leaf(intermediate, int_key, serial=144)

    status, evidence = validate_chain(
        leaf, [intermediate, root], "example.test", FIXED_NOW, make_store([root]),
    )

    assert status == ChainStatus.NOT_YET_VALID
    assert evidence["index"] == 1


def test_valid_chain_with_two_intermediates_passes_path_length():
    root, root_key = _root("Two Intermediate Root", key_number=50)
    upper_key = ec_key(51)
    upper = issue_ca(
        "Upper Intermediate", upper_key, serial=51,
        issuer=root.subject, issuer_key=root_key, path_length=1,
    )
    lower_key = ec_key(52)
    lower = issue_ca(
        "Lower Intermediate", lower_key, serial=52,
        issuer=upper.subject, issuer_key=upper_key, path_length=0,
    )
    leaf = issue_leaf(lower, lower_key, serial=152)

    status, _ = validate_chain(
        leaf, [lower, upper, root], "example.test", FIXED_NOW, make_store([root]),
    )

    assert status == ChainStatus.VALID_TRUSTED


def test_path_length_zero_above_an_intermediate_is_violated():
    root, root_key = _root("Path Constraint Root", key_number=60)
    upper_key = ec_key(61)
    upper = issue_ca(
        "Path Length Zero Upper", upper_key, serial=61,
        issuer=root.subject, issuer_key=root_key, path_length=0,
    )
    lower_key = ec_key(62)
    lower = issue_ca(
        "Path Constraint Lower", lower_key, serial=62,
        issuer=upper.subject, issuer_key=upper_key, path_length=0,
    )
    leaf = issue_leaf(lower, lower_key, serial=162)

    status, evidence = validate_chain(
        leaf, [lower, upper, root], "example.test", FIXED_NOW, make_store([root]),
    )

    assert status == ChainStatus.PATH_CONSTRAINT_VIOLATED
    assert evidence["reason"] == "path_length_exceeded"


def test_same_name_different_der_string_type_anchors_by_spki():
    trusted_key = ec_key(70)
    printable_name = name("Encoded Root", string_type=_ASN1Type.PrintableString)
    utf8_name = name("Encoded Root", string_type=_ASN1Type.UTF8String)
    trusted_root = issue_ca(
        "Unused", trusted_key, serial=70, subject=printable_name,
    )
    cross_signed = issue_ca(
        "Unused", trusted_key, serial=71, subject=utf8_name,
        issuer=name("Encoding Cross Signer"), issuer_key=ec_key(71),
    )
    leaf = issue_leaf(cross_signed, trusted_key, serial=171)

    assert trusted_root.subject == cross_signed.subject
    assert trusted_root.subject.public_bytes() != cross_signed.subject.public_bytes()
    status, _ = validate_chain(
        leaf, [cross_signed], "example.test", FIXED_NOW, make_store([trusted_root]),
    )

    assert status == ChainStatus.VALID_TRUSTED


def test_unsupported_ed448_signature_is_inconclusive():
    root_key = ed448_key()
    root = issue_ca("Ed448 Root", root_key, serial=80)
    leaf = issue_leaf(root, root_key, serial=180)

    status, _ = validate_chain(leaf, [root], "example.test", FIXED_NOW, make_store([root]))

    assert status == ChainStatus.INCONCLUSIVE


def test_chain_depth_limit_is_reachable():
    root, issuer_key = _root("Depth Root", key_number=90)
    supplied = [root]
    for index in range(91, 101):
        key = ec_key(index)
        cert = issue_ca(
            f"Depth Intermediate {index}", key, serial=index,
            issuer=supplied[-1].subject, issuer_key=issuer_key, path_length=None,
        )
        supplied.append(cert)
        issuer_key = key
    leaf = issue_leaf(supplied[-1], issuer_key, serial=201)

    status, evidence = validate_chain(
        leaf, supplied, "example.test", FIXED_NOW, make_store([root]),
    )

    assert status == ChainStatus.RESOURCE_LIMIT_EXCEEDED
    assert evidence["reason"] == "chain_depth"
