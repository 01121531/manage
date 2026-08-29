"""Pure cryptographic helpers for the closed runtime-attestation fixture profile.

This module only verifies caller-supplied bytes.  It has no filesystem, network,
clock, subprocess, signing, or key-generation capability.  The RFC 3161 parser
intentionally accepts one closed DER/CMS profile rather than claiming to be a
general CMS implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import binascii
import hashlib
import hmac
import re
from typing import Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import ExtendedKeyUsageOID


_B64 = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"


class RuntimeAttestationCryptoError(ValueError):
    """One closed-profile cryptographic artifact is invalid."""


def _invalid() -> RuntimeAttestationCryptoError:
    return RuntimeAttestationCryptoError("runtime attestation cryptographic evidence is invalid")


def decode_base64(value: object, *, minimum: int = 1, maximum: int = 262_144) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum * 2
        or len(value) % 4 != 0
        or _B64.fullmatch(value) is None
    ):
        raise _invalid()
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise _invalid() from error
    if not minimum <= len(raw) <= maximum:
        raise _invalid()
    if not hmac.compare_digest(base64.b64encode(raw).decode("ascii"), value):
        raise _invalid()
    return raw


def decode_base64_file(raw: bytes, *, maximum: int = 262_144) -> bytes:
    if type(raw) is not bytes or not raw.endswith(b"\n") or b"\r" in raw:
        raise _invalid()
    try:
        text = raw[:-1].decode("ascii")
    except UnicodeError as error:
        raise _invalid() from error
    return decode_base64(text, maximum=maximum)


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    if (
        not isinstance(payload_type, str)
        or not payload_type
        or len(payload_type) > 255
        or type(payload) is not bytes
        or not payload
        or len(payload) > 1_048_576
    ):
        raise _invalid()
    try:
        kind = payload_type.encode("utf-8")
    except UnicodeError as error:
        raise _invalid() from error
    return (
        b"DSSEv1 "
        + str(len(kind)).encode("ascii")
        + b" "
        + kind
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _utc(value: str) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise _invalid()
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise _invalid() from error


def _ecdsa_public_key(value: object) -> ec.EllipticCurvePublicKey:
    if not isinstance(value, ec.EllipticCurvePublicKey) or not isinstance(
        value.curve, ec.SECP256R1
    ):
        raise _invalid()
    return value


def verify_ecdsa_signature(
    public_key: object,
    signature: bytes,
    message: bytes,
) -> None:
    if (
        type(signature) is not bytes
        or not 64 <= len(signature) <= 80
        or type(message) is not bytes
        or not message
    ):
        raise _invalid()
    try:
        _ecdsa_public_key(public_key).verify(signature, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as error:
        raise _invalid() from error


def verify_ed25519_signature(public_key_raw: bytes, signature: bytes, message: bytes) -> None:
    if (
        type(public_key_raw) is not bytes
        or len(public_key_raw) != 32
        or type(signature) is not bytes
        or len(signature) != 64
        or type(message) is not bytes
        or not message
    ):
        raise _invalid()
    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(signature, message)
    except (InvalidSignature, ValueError) as error:
        raise _invalid() from error


def ed25519_key_id(public_key_raw: bytes) -> str:
    if type(public_key_raw) is not bytes or len(public_key_raw) != 32:
        raise _invalid()
    return "ed25519-sha256:" + hashlib.sha256(public_key_raw).hexdigest()


def ed25519_spki_sha256(public_key_raw: bytes) -> bytes:
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key_raw)
        spki = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except ValueError as error:
        raise _invalid() from error
    return hashlib.sha256(spki).digest()


def signed_record_message(domain: str, payload: bytes) -> bytes:
    if (
        not isinstance(domain, str)
        or not domain
        or len(domain) > 255
        or not domain.isascii()
        or type(payload) is not bytes
        or not payload
        or len(payload) > 1_048_576
    ):
        raise _invalid()
    return domain.encode("ascii") + b"\0" + len(payload).to_bytes(8, "big") + payload


def _verify_certificate_signature(
    certificate: x509.Certificate,
    issuer: x509.Certificate,
) -> None:
    if certificate.signature_hash_algorithm.name != "sha256":
        raise _invalid()
    verify_ecdsa_signature(
        issuer.public_key(), certificate.signature, certificate.tbs_certificate_bytes
    )


def _load_certificate(raw: bytes) -> x509.Certificate:
    if type(raw) is not bytes or not 128 <= len(raw) <= 16_384:
        raise _invalid()
    try:
        certificate = x509.load_der_x509_certificate(raw)
    except ValueError as error:
        raise _invalid() from error
    if certificate.public_bytes(serialization.Encoding.DER) != raw:
        raise _invalid()
    _ecdsa_public_key(certificate.public_key())
    return certificate


def verify_certificate_chain(
    *,
    leaf_der: bytes,
    root_der: bytes,
    verification_time: datetime,
    purpose: str,
) -> tuple[x509.Certificate, x509.Certificate]:
    if verification_time.tzinfo is None or verification_time.utcoffset() != timezone.utc.utcoffset(None):
        raise _invalid()
    leaf = _load_certificate(leaf_der)
    root = _load_certificate(root_der)
    try:
        root_constraints = root.extensions.get_extension_for_class(x509.BasicConstraints)
        root_usage = root.extensions.get_extension_for_class(x509.KeyUsage)
        leaf_constraints = leaf.extensions.get_extension_for_class(x509.BasicConstraints)
        leaf_usage = leaf.extensions.get_extension_for_class(x509.KeyUsage)
        leaf_eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound as error:
        raise _invalid() from error
    if (
        root.issuer != root.subject
        or not root_constraints.critical
        or not root_constraints.value.ca
        or not root_usage.critical
        or not root_usage.value.key_cert_sign
        or not root_usage.value.crl_sign
        or root_usage.value.digital_signature
        or leaf.issuer != root.subject
        or not leaf_constraints.critical
        or leaf_constraints.value.ca
        or not leaf_usage.critical
        or not leaf_usage.value.digital_signature
        or leaf_usage.value.key_cert_sign
        or not (root.not_valid_before_utc <= verification_time <= root.not_valid_after_utc)
        or not (leaf.not_valid_before_utc <= verification_time <= leaf.not_valid_after_utc)
    ):
        raise _invalid()
    if purpose == "code_signing":
        expected_eku = ExtendedKeyUsageOID.CODE_SIGNING
        if leaf_eku.critical:
            raise _invalid()
    elif purpose == "time_stamping":
        expected_eku = ExtendedKeyUsageOID.TIME_STAMPING
        if not leaf_eku.critical:
            raise _invalid()
    else:
        raise _invalid()
    if list(leaf_eku.value) != [expected_eku]:
        raise _invalid()
    _verify_certificate_signature(root, root)
    _verify_certificate_signature(leaf, root)
    return leaf, root


def certificate_serial_hex(certificate: x509.Certificate) -> str:
    return format(certificate.serial_number, "x")


def decode_der_utf8_string(raw: bytes) -> str:
    node, end = _read_node(raw, 0)
    if end != len(raw) or node.tag != 0x0C or not node.value:
        raise _invalid()
    try:
        return node.value.decode("utf-8")
    except UnicodeError as error:
        raise _invalid() from error


def rfc6962_leaf_hash(body: bytes) -> bytes:
    if type(body) is not bytes or not body or len(body) > 262_144:
        raise _invalid()
    return hashlib.sha256(b"\x00" + body).digest()


def rfc6962_pair_hash(left: bytes, right: bytes) -> bytes:
    if type(left) is not bytes or len(left) != 32 or type(right) is not bytes or len(right) != 32:
        raise _invalid()
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_two_leaf_inclusion(
    *,
    body: bytes,
    log_index: int,
    tree_size: int,
    proof_hashes: Sequence[bytes],
    expected_root: bytes,
) -> bytes:
    if tree_size != 2 or log_index not in (0, 1) or len(proof_hashes) != 1:
        raise _invalid()
    sibling = proof_hashes[0]
    if type(sibling) is not bytes or len(sibling) != 32 or len(expected_root) != 32:
        raise _invalid()
    leaf = rfc6962_leaf_hash(body)
    root = rfc6962_pair_hash(leaf, sibling) if log_index == 0 else rfc6962_pair_hash(sibling, leaf)
    if not hmac.compare_digest(root, expected_root):
        raise _invalid()
    return leaf


def verify_checkpoint_note(
    *,
    note_raw: bytes,
    expected_origin: str,
    expected_tree_size: int,
    expected_root_hash: bytes,
    public_key_raw: bytes,
) -> None:
    if (
        type(note_raw) is not bytes
        or not note_raw.endswith(b"\n")
        or len(note_raw) > 16_384
        or b"\r" in note_raw
        or note_raw.count(b"\n\n") != 1
    ):
        raise _invalid()
    text, signature_block = note_raw.split(b"\n\n", 1)
    note_text = text + b"\n"
    try:
        decoded_text = note_text.decode("utf-8")
        signature_line = signature_block.decode("utf-8")
    except UnicodeError as error:
        raise _invalid() from error
    lines = decoded_text.splitlines()
    if len(lines) != 3 or lines[0] != expected_origin or lines[1] != str(expected_tree_size):
        raise _invalid()
    try:
        root = base64.b64decode(lines[2], validate=True)
    except (ValueError, binascii.Error) as error:
        raise _invalid() from error
    if root != expected_root_hash or base64.b64encode(root).decode("ascii") != lines[2]:
        raise _invalid()
    prefix = "— " + expected_origin + " "
    if not signature_line.startswith(prefix) or not signature_line.endswith("\n"):
        raise _invalid()
    encoded = signature_line[len(prefix) : -1]
    signature_record = decode_base64(encoded, minimum=68, maximum=68)
    expected_key_id = hashlib.sha256(
        expected_origin.encode("utf-8") + b"\n\x01" + public_key_raw
    ).digest()[:4]
    if signature_record[:4] != expected_key_id:
        raise _invalid()
    verify_ed25519_signature(public_key_raw, signature_record[4:], note_text)


@dataclass(frozen=True)
class VerifiedRFC3161Timestamp:
    generated_at: datetime
    nonce: int
    serial_number: int
    tsa_certificate_serial_hex: str
    token_sha256: str


@dataclass(frozen=True)
class _DerNode:
    tag: int
    value: bytes
    full: bytes


def _read_node(data: bytes, offset: int) -> tuple[_DerNode, int]:
    if type(data) is not bytes or offset < 0 or offset >= len(data):
        raise _invalid()
    start = offset
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F or offset >= len(data):
        raise _invalid()
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or offset + count > len(data) or data[offset] == 0:
            raise _invalid()
        length = int.from_bytes(data[offset : offset + count], "big")
        if length < 0x80:
            raise _invalid()
        offset += count
    end = offset + length
    if end > len(data):
        raise _invalid()
    return _DerNode(tag=tag, value=data[offset:end], full=data[start:end]), end


def _one(data: bytes, *, tag: int) -> _DerNode:
    node, end = _read_node(data, 0)
    if end != len(data) or node.tag != tag:
        raise _invalid()
    return node


def _children(node: _DerNode, *, tag: int) -> list[_DerNode]:
    if node.tag != tag:
        raise _invalid()
    result: list[_DerNode] = []
    offset = 0
    while offset < len(node.value):
        child, offset = _read_node(node.value, offset)
        result.append(child)
    return result


def _integer(node: _DerNode) -> int:
    if (
        node.tag != 0x02
        or not node.value
        or node.value[0] & 0x80
        or (len(node.value) > 1 and node.value[0] == 0 and not node.value[1] & 0x80)
    ):
        raise _invalid()
    return int.from_bytes(node.value, "big")


def _oid(node: _DerNode) -> str:
    if node.tag != 0x06 or not node.value:
        raise _invalid()
    first = node.value[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    value = 0
    pending = False
    for byte in node.value[1:]:
        if not pending and byte == 0x80:
            raise _invalid()
        value = (value << 7) | (byte & 0x7F)
        pending = bool(byte & 0x80)
        if not pending:
            parts.append(value)
            value = 0
    if pending:
        raise _invalid()
    return ".".join(str(item) for item in parts)


def _algorithm(node: _DerNode, expected_oid: str) -> None:
    children = _children(node, tag=0x30)
    if len(children) not in (1, 2) or _oid(children[0]) != expected_oid:
        raise _invalid()
    if len(children) == 2 and not (children[1].tag == 0x05 and children[1].value == b""):
        raise _invalid()


def _der_length(length: int) -> bytes:
    if length < 0:
        raise _invalid()
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _set_from_implicit(node: _DerNode) -> bytes:
    if node.tag != 0xA0:
        raise _invalid()
    return b"\x31" + _der_length(len(node.value)) + node.value


def _generalized_time(node: _DerNode) -> datetime:
    if node.tag != 0x18:
        raise _invalid()
    try:
        value = node.value.decode("ascii")
        if not re.fullmatch(r"\d{14}Z", value):
            raise ValueError
        return datetime.strptime(value, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
    except (UnicodeError, ValueError) as error:
        raise _invalid() from error


def _parse_attribute(node: _DerNode) -> tuple[str, _DerNode]:
    fields = _children(node, tag=0x30)
    if len(fields) != 2:
        raise _invalid()
    values = _children(fields[1], tag=0x31)
    if len(values) != 1:
        raise _invalid()
    return _oid(fields[0]), values[0]


def verify_rfc3161_response(
    *,
    response_der: bytes,
    expected_signature: bytes,
    expected_nonce: int,
    expected_policy_oid: str,
    tsa_root_der: bytes,
) -> VerifiedRFC3161Timestamp:
    if type(response_der) is not bytes or not 256 <= len(response_der) <= 65_536:
        raise _invalid()
    response = _children(_one(response_der, tag=0x30), tag=0x30)
    if len(response) != 2:
        raise _invalid()
    status = _children(response[0], tag=0x30)
    if len(status) != 1 or _integer(status[0]) != 0:
        raise _invalid()
    content_info = _children(response[1], tag=0x30)
    if len(content_info) != 2 or _oid(content_info[0]) != OID_SIGNED_DATA:
        raise _invalid()
    signed_data_container = _children(content_info[1], tag=0xA0)
    if len(signed_data_container) != 1:
        raise _invalid()
    signed_data = _children(signed_data_container[0], tag=0x30)
    if len(signed_data) != 5 or _integer(signed_data[0]) != 3:
        raise _invalid()
    digest_algorithms = _children(signed_data[1], tag=0x31)
    if len(digest_algorithms) != 1:
        raise _invalid()
    _algorithm(digest_algorithms[0], OID_SHA256)
    encap = _children(signed_data[2], tag=0x30)
    if len(encap) != 2 or _oid(encap[0]) != OID_TST_INFO:
        raise _invalid()
    econtent = _children(encap[1], tag=0xA0)
    if len(econtent) != 1 or econtent[0].tag != 0x04:
        raise _invalid()
    tst_info_raw = econtent[0].value
    certificate_nodes = _children(signed_data[3], tag=0xA0)
    if len(certificate_nodes) != 1 or certificate_nodes[0].tag != 0x30:
        raise _invalid()
    tsa_leaf_der = certificate_nodes[0].full
    signer_infos = _children(signed_data[4], tag=0x31)
    if len(signer_infos) != 1:
        raise _invalid()
    signer = _children(signer_infos[0], tag=0x30)
    if len(signer) != 6 or _integer(signer[0]) != 1:
        raise _invalid()
    sid = _children(signer[1], tag=0x30)
    if len(sid) != 2:
        raise _invalid()
    _algorithm(signer[2], OID_SHA256)
    signed_attrs = signer[3]
    attrs = _children(signed_attrs, tag=0xA0)
    if [item.full for item in attrs] != sorted(item.full for item in attrs):
        raise _invalid()
    parsed_attrs = dict(_parse_attribute(item) for item in attrs)
    if set(parsed_attrs) != {OID_CONTENT_TYPE, OID_MESSAGE_DIGEST}:
        raise _invalid()
    if _oid(parsed_attrs[OID_CONTENT_TYPE]) != OID_TST_INFO:
        raise _invalid()
    digest_node = parsed_attrs[OID_MESSAGE_DIGEST]
    if digest_node.tag != 0x04 or digest_node.value != hashlib.sha256(tst_info_raw).digest():
        raise _invalid()
    _algorithm(signer[4], OID_ECDSA_SHA256)
    if signer[5].tag != 0x04:
        raise _invalid()
    signature = signer[5].value
    tst = _children(_one(tst_info_raw, tag=0x30), tag=0x30)
    if len(tst) != 6 or _integer(tst[0]) != 1 or _oid(tst[1]) != expected_policy_oid:
        raise _invalid()
    imprint = _children(tst[2], tag=0x30)
    if len(imprint) != 2 or imprint[1].tag != 0x04:
        raise _invalid()
    _algorithm(imprint[0], OID_SHA256)
    if imprint[1].value != hashlib.sha256(expected_signature).digest():
        raise _invalid()
    serial_number = _integer(tst[3])
    generated_at = _generalized_time(tst[4])
    nonce = _integer(tst[5])
    if serial_number < 1 or nonce != expected_nonce:
        raise _invalid()
    leaf, _ = verify_certificate_chain(
        leaf_der=tsa_leaf_der,
        root_der=tsa_root_der,
        verification_time=generated_at,
        purpose="time_stamping",
    )
    if sid[0].full != leaf.issuer.public_bytes() or _integer(sid[1]) != leaf.serial_number:
        raise _invalid()
    verify_ecdsa_signature(leaf.public_key(), signature, _set_from_implicit(signed_attrs))
    return VerifiedRFC3161Timestamp(
        generated_at=generated_at,
        nonce=nonce,
        serial_number=serial_number,
        tsa_certificate_serial_hex=certificate_serial_hex(leaf),
        token_sha256=hashlib.sha256(response_der).hexdigest(),
    )

