"""Verify exact provider evidence bytes for the synthetic T206 fixture.

The public entrypoint is intentionally pure: it receives bytes and caller pins,
performs no I/O, uses no host clock, and never signs or generates a key.  The
fixture proves the verification mechanics only; it does not confer production
authority on the synthetic signers or receipts.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
import re
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

try:
    from scripts.external_json import parse_unique_json_bytes
    from scripts.runtime_attestation_crypto import (
        RuntimeAttestationCryptoError,
        decode_base64,
        decode_base64_file,
        decode_der_utf8_string,
        dsse_pae,
        ed25519_key_id,
        signed_record_message,
        verify_certificate_chain,
        verify_checkpoint_note,
        verify_ecdsa_signature,
        verify_ed25519_signature,
        verify_rfc3161_response,
        verify_two_leaf_inclusion,
    )
    from scripts.target_intake_runtime_attestation_intake import (
        RuntimeAttestationIntakeError,
        verify_runtime_attestation_protocol_bytes,
    )
except ModuleNotFoundError:
    from external_json import parse_unique_json_bytes
    from runtime_attestation_crypto import (
        RuntimeAttestationCryptoError,
        decode_base64,
        decode_base64_file,
        decode_der_utf8_string,
        dsse_pae,
        ed25519_key_id,
        signed_record_message,
        verify_certificate_chain,
        verify_checkpoint_note,
        verify_ecdsa_signature,
        verify_ed25519_signature,
        verify_rfc3161_response,
        verify_two_leaf_inclusion,
    )
    from target_intake_runtime_attestation_intake import (
        RuntimeAttestationIntakeError,
        verify_runtime_attestation_protocol_bytes,
    )


SIGSTORE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
SIMPLE_SIGNING_TYPE = "cosign container image signature"
TSA_POLICY_OID = "1.3.6.1.4.1.57264.2"
FULCIO_ISSUER_OID = "1.3.6.1.4.1.57264.1.8"
FULCIO_RUNNER_OID = "1.3.6.1.4.1.57264.1.11"
FULCIO_REPOSITORY_OID = "1.3.6.1.4.1.57264.1.12"
FULCIO_COMMIT_OID = "1.3.6.1.4.1.57264.1.13"
FULCIO_REF_OID = "1.3.6.1.4.1.57264.1.14"
FULCIO_REPOSITORY_ID_OID = "1.3.6.1.4.1.57264.1.15"
FULCIO_OWNER_ID_OID = "1.3.6.1.4.1.57264.1.17"
FULCIO_WORKFLOW_OID = "1.3.6.1.4.1.57264.1.18"
FULCIO_VISIBILITY_OID = "1.3.6.1.4.1.57264.1.22"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_MAX_RAW = 4_194_304


class RuntimeAttestationProviderError(ValueError):
    """The closed provider fixture is invalid or overstates authority."""


def _invalid() -> RuntimeAttestationProviderError:
    return RuntimeAttestationProviderError(
        "target intake runtime attestation provider evidence is invalid"
    )


@dataclass(frozen=True)
class RawProviderInputs:
    cosign_payload: bytes
    cosign_bundle: bytes
    github_bundle: bytes
    trusted_root: bytes
    revocation_snapshot: bytes
    rekor_checkpoint: bytes
    cosign_timestamp: bytes
    github_timestamp: bytes
    target_observer: bytes
    provider_write_receipt: bytes
    provider_read_receipt: bytes
    cosign_cli_result: bytes
    github_cli_result: bytes

    def named(self) -> dict[str, bytes]:
        return {item.name.replace("_", "-"): getattr(self, item.name) for item in fields(self)}


@dataclass(frozen=True)
class RuntimeAttestationProviderPins:
    t204_policy_sha256: str
    t205_profile_sha256: str
    t205_evidence_sha256: str
    t205_runtime_subject_sha256: str
    adapter_profile_sha256: str
    evidence_index_sha256: str
    cosign_executable_sha256: str
    github_executable_sha256: str


@dataclass(frozen=True)
class VerifiedRuntimeAttestationProviderFixture:
    runtime_subject_sha256: str
    runtime_artifact_digest: str
    adapter_profile_sha256: str
    evidence_index_sha256: str
    cosign_payload_sha256: str
    github_statement_sha256: str
    checkpoint_sha256: str
    target_observation_sha256: str
    provider_head_sha256: str
    fixture_signature_cryptography_verified: bool
    fixture_tsa_cryptography_verified: bool
    fixture_transparency_inclusion_verified: bool
    fixture_receipt_cryptography_verified: bool
    trust_root_currentness_verified: bool
    revocation_freshness_verified: bool
    provider_native_cas_verified: bool
    original_execution_verified: bool
    runtime_authority_verified: bool
    production_acceptance: bool


def _closed(value: object, names: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != names:
        raise _invalid()
    return value


def _raw_json(raw: bytes, maximum: int = _MAX_RAW) -> object:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise _invalid()
    try:
        return parse_unique_json_bytes(raw)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise _invalid() from error


def _artifact_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")


def _canonical_json(raw: bytes) -> object:
    value = _raw_json(raw, 262_144)
    if raw != _artifact_bytes(value):
        raise _invalid()
    return value


def _sha(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _invalid()
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise _invalid()
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise _invalid() from error
    return parsed


def _same(left: object, right: object) -> None:
    if not isinstance(left, str) or not isinstance(right, str) or not hmac.compare_digest(left, right):
        raise _invalid()


def _verify_pin(raw: bytes, expected: str) -> str:
    actual = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual, _sha(expected)):
        raise _invalid()
    return actual


def _parse_profile(raw: bytes) -> dict[str, Any]:
    profile = _closed(
        _canonical_json(raw),
        {
            "schema_version", "synthetic", "production_acceptance", "verification_time",
            "repository", "workflow_ref", "certificate_identity", "oidc_issuer",
            "source_commit", "release_tag", "runner_environment", "repository_id",
            "repository_owner_id", "repository_visibility", "checkpoint_origin",
            "cosign_cli_version", "github_cli_version",
        },
    )
    if (
        profile["schema_version"] != 1
        or profile["synthetic"] is not True
        or profile["production_acceptance"] is not False
        or profile["repository"] != "https://github.com/01121531/manage"
        or profile["workflow_ref"] != "01121531/manage/.github/workflows/release.yml@refs/tags/v0.0.0-fixture"
        or profile["certificate_identity"] != "https://github.com/01121531/manage/.github/workflows/release.yml@refs/tags/v0.0.0-fixture"
        or profile["oidc_issuer"] != "https://token.actions.githubusercontent.com"
        or profile["release_tag"] != "v0.0.0-fixture"
        or profile["runner_environment"] != "github-hosted"
        or profile["repository_id"] != "205000001"
        or profile["repository_owner_id"] != "205000002"
        or profile["repository_visibility"] != "public"
        or profile["checkpoint_origin"] != "rekor.synthetic.runtime-attestation.t206"
        or profile["cosign_cli_version"] != "v3.0.6-fixture"
        or profile["github_cli_version"] != "gh-attestation-v2-fixture"
    ):
        raise _invalid()
    _time(profile["verification_time"])
    if not isinstance(profile["source_commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", profile["source_commit"]):
        raise _invalid()
    return profile


def _verify_index(raw: bytes, inputs: RawProviderInputs, *, t205_evidence_sha256: str, subject_sha256: str) -> dict[str, Any]:
    index = _closed(
        _canonical_json(raw),
        {"schema_version", "synthetic", "production_acceptance", "t205_evidence_sha256", "runtime_subject_sha256", "assets"},
    )
    if index["schema_version"] != 1 or index["synthetic"] is not True or index["production_acceptance"] is not False:
        raise _invalid()
    _same(index["t205_evidence_sha256"], t205_evidence_sha256)
    _same(index["runtime_subject_sha256"], subject_sha256)
    assets = index["assets"]
    named = inputs.named()
    if not isinstance(assets, dict) or set(assets) != set(named):
        raise _invalid()
    for name, artifact in named.items():
        entry = _closed(assets[name], {"sha256", "size"})
        if entry["size"] != len(artifact) or not hmac.compare_digest(_sha(entry["sha256"]), hashlib.sha256(artifact).hexdigest()):
            raise _invalid()
    return index


def _root(raw: bytes) -> dict[str, Any]:
    root = _closed(
        _canonical_json(raw),
        {
            "schema_version", "synthetic", "valid_from", "valid_until",
            "fulcio_root_der_b64", "tsa_root_der_b64", "rekor_public_key_b64",
            "revocation_public_key_b64", "target_observer_public_key_b64", "provider_public_key_b64",
        },
    )
    if root["schema_version"] != 1 or root["synthetic"] is not True or _time(root["valid_from"]) >= _time(root["valid_until"]):
        raise _invalid()
    return root


def _extension(certificate: x509.Certificate, oid: str) -> str:
    try:
        item = certificate.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid))
    except x509.ExtensionNotFound as error:
        raise _invalid() from error
    if item.critical or not isinstance(item.value, x509.UnrecognizedExtension):
        raise _invalid()
    return decode_der_utf8_string(item.value.value)


def _identity(certificate: x509.Certificate) -> str:
    try:
        san = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound as error:
        raise _invalid() from error
    uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    if san.critical or len(uris) != 1:
        raise _invalid()
    return uris[0]


def _bundle(raw: bytes, content_key: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes, bytes]:
    bundle = _closed(_raw_json(raw), {"mediaType", "verificationMaterial", content_key})
    if bundle["mediaType"] != SIGSTORE_MEDIA_TYPE:
        raise _invalid()
    material = _closed(bundle["verificationMaterial"], {"certificate", "tlogEntries"})
    certificate = _closed(material["certificate"], {"rawBytes"})
    tlogs = material["tlogEntries"]
    if not isinstance(tlogs, list) or len(tlogs) != 1:
        raise _invalid()
    tlog = _closed(tlogs[0], {"canonicalizedBody", "logIndex", "inclusionProof"})
    proof = _closed(tlog["inclusionProof"], {"treeSize", "rootHash", "hashes"})
    hashes_value = proof["hashes"]
    if not isinstance(hashes_value, list) or len(hashes_value) != 1:
        raise _invalid()
    return (
        bundle,
        tlog,
        decode_base64(certificate["rawBytes"], maximum=16_384),
        decode_base64(tlog["canonicalizedBody"]),
        decode_base64(hashes_value[0], minimum=32, maximum=32),
    )


def _verify_tlog(
    *,
    body_raw: bytes,
    expected_content_hash: str,
    expected_signature_b64: str,
    expected_certificate_b64: str,
    tlog: dict[str, Any],
    sibling: bytes,
    checkpoint_root: bytes,
) -> None:
    body = _closed(_raw_json(body_raw), {"apiVersion", "kind", "spec"})
    spec = _closed(body["spec"], {"data", "signature"})
    data = _closed(spec["data"], {"hash"})
    body_hash = _closed(data["hash"], {"algorithm", "value"})
    signature = _closed(spec["signature"], {"content", "publicKey"})
    public_key = _closed(signature["publicKey"], {"content"})
    if (
        body["apiVersion"] != "0.0.1"
        or body["kind"] != "hashedrekord"
        or body_hash != {"algorithm": "sha256", "value": expected_content_hash}
        or signature["content"] != expected_signature_b64
        or public_key["content"] != expected_certificate_b64
    ):
        raise _invalid()
    verify_two_leaf_inclusion(
        body=body_raw,
        log_index=tlog["logIndex"],
        tree_size=tlog["inclusionProof"]["treeSize"],
        proof_hashes=[sibling],
        expected_root=checkpoint_root,
    )
    if decode_base64(tlog["inclusionProof"]["rootHash"], minimum=32, maximum=32) != checkpoint_root:
        raise _invalid()


def _verify_signed_record(raw: bytes, *, domain: str, public_key: bytes) -> tuple[dict[str, Any], bytes]:
    envelope = _closed(_raw_json(raw), {"domain", "payload", "signature", "key_id"})
    if envelope["domain"] != domain or envelope["key_id"] != ed25519_key_id(public_key):
        raise _invalid()
    payload_raw = decode_base64(envelope["payload"], maximum=1_048_576)
    signature_raw = decode_base64(envelope["signature"], minimum=64, maximum=64)
    verify_ed25519_signature(public_key, signature_raw, signed_record_message(domain, payload_raw))
    payload = _raw_json(payload_raw)
    if not isinstance(payload, dict):
        raise _invalid()
    return payload, payload_raw


def _verify_cli(raw: bytes, *, tool: str, version: str, executable_sha256: str, bundle_sha256: str, payload_sha256: str) -> None:
    result = _closed(_raw_json(raw, 2_097_152), {"tool", "version", "executable_sha256", "argv", "exit_code", "bundle_sha256", "payload_sha256", "stdout_sha256", "synthetic"})
    if (
        result["tool"] != tool
        or result["version"] != version
        or result["synthetic"] is not True
        or result["exit_code"] != 0
        or result["executable_sha256"] != executable_sha256
        or result["bundle_sha256"] != bundle_sha256
        or result["payload_sha256"] != payload_sha256
        or not isinstance(result["argv"], list)
        or not result["argv"]
    ):
        raise _invalid()
    _sha(result["stdout_sha256"])


def verify_runtime_attestation_provider_bytes(
    *,
    t204_policy_raw: bytes,
    t205_profile_raw: bytes,
    t205_evidence_raw: bytes,
    adapter_profile_raw: bytes,
    evidence_index_raw: bytes,
    raw_inputs: RawProviderInputs,
    pins: RuntimeAttestationProviderPins,
) -> VerifiedRuntimeAttestationProviderFixture:
    """Verify the closed T206 fixture from exact caller-supplied bytes."""

    try:
        prior = verify_runtime_attestation_protocol_bytes(
            policy_raw=t204_policy_raw,
            profile_raw=t205_profile_raw,
            evidence_raw=t205_evidence_raw,
            expected_policy_sha256=pins.t204_policy_sha256,
            expected_profile_sha256=pins.t205_profile_sha256,
            expected_runtime_subject_sha256=pins.t205_runtime_subject_sha256,
        )
        t205_evidence_sha256 = _verify_pin(t205_evidence_raw, pins.t205_evidence_sha256)
        profile_sha256 = _verify_pin(adapter_profile_raw, pins.adapter_profile_sha256)
        index_sha256 = _verify_pin(evidence_index_raw, pins.evidence_index_sha256)
        profile = _parse_profile(adapter_profile_raw)
        _verify_index(
            evidence_index_raw,
            raw_inputs,
            t205_evidence_sha256=t205_evidence_sha256,
            subject_sha256=prior.runtime_subject_sha256,
        )
        evidence_value = _raw_json(t205_evidence_raw)
        if not isinstance(evidence_value, dict):
            raise _invalid()
        evidence = evidence_value
        subject = evidence["runtime_subject"]
        root = _root(raw_inputs.trusted_root)
        fulcio_root_der = decode_base64(root["fulcio_root_der_b64"], maximum=16_384)
        tsa_root_der = decode_base64(root["tsa_root_der_b64"], maximum=16_384)
        rekor_key = decode_base64(root["rekor_public_key_b64"], minimum=32, maximum=32)
        revocation_key = decode_base64(root["revocation_public_key_b64"], minimum=32, maximum=32)
        target_key = decode_base64(root["target_observer_public_key_b64"], minimum=32, maximum=32)
        provider_key = decode_base64(root["provider_public_key_b64"], minimum=32, maximum=32)
        if len({rekor_key, revocation_key, target_key, provider_key}) != 4:
            raise _invalid()

        cosign, cosign_tlog, cosign_cert_der, cosign_body, cosign_sibling = _bundle(raw_inputs.cosign_bundle, "messageSignature")
        message = _closed(cosign["messageSignature"], {"messageDigest", "signature"})
        message_digest = _closed(message["messageDigest"], {"algorithm", "digest"})
        cosign_signature = decode_base64(message["signature"], maximum=1024)
        cosign_payload_sha256 = hashlib.sha256(raw_inputs.cosign_payload).hexdigest()
        if message_digest["algorithm"] != "SHA2_256" or decode_base64(message_digest["digest"], minimum=32, maximum=32).hex() != cosign_payload_sha256:
            raise _invalid()

        github, github_tlog, github_cert_der, github_body, github_sibling = _bundle(raw_inputs.github_bundle.rstrip(b"\n"), "dsseEnvelope")
        if not raw_inputs.github_bundle.endswith(b"\n") or raw_inputs.github_bundle.count(b"\n") != 1:
            raise _invalid()
        envelope = _closed(github["dsseEnvelope"], {"payloadType", "payload", "signatures"})
        signatures = envelope["signatures"]
        if envelope["payloadType"] != INTOTO_PAYLOAD_TYPE or not isinstance(signatures, list) or len(signatures) != 1:
            raise _invalid()
        dsse_signature_entry = _closed(signatures[0], {"sig", "keyid"})
        if dsse_signature_entry["keyid"] != "":
            raise _invalid()
        statement_raw = decode_base64(envelope["payload"], maximum=1_048_576)
        github_signature = decode_base64(dsse_signature_entry["sig"], maximum=1024)
        pae_raw = dsse_pae(INTOTO_PAYLOAD_TYPE, statement_raw)

        cosign_timestamp = verify_rfc3161_response(
            response_der=decode_base64_file(raw_inputs.cosign_timestamp),
            expected_signature=cosign_signature,
            expected_nonce=20601,
            expected_policy_oid=TSA_POLICY_OID,
            tsa_root_der=tsa_root_der,
        )
        github_timestamp = verify_rfc3161_response(
            response_der=decode_base64_file(raw_inputs.github_timestamp),
            expected_signature=github_signature,
            expected_nonce=20602,
            expected_policy_oid=TSA_POLICY_OID,
            tsa_root_der=tsa_root_der,
        )
        cosign_cert, _ = verify_certificate_chain(
            leaf_der=cosign_cert_der, root_der=fulcio_root_der,
            verification_time=cosign_timestamp.generated_at, purpose="code_signing",
        )
        github_cert, _ = verify_certificate_chain(
            leaf_der=github_cert_der, root_der=fulcio_root_der,
            verification_time=github_timestamp.generated_at, purpose="code_signing",
        )
        verify_ecdsa_signature(cosign_cert.public_key(), cosign_signature, raw_inputs.cosign_payload)
        verify_ecdsa_signature(github_cert.public_key(), github_signature, pae_raw)
        if _identity(cosign_cert) != profile["certificate_identity"] or _identity(github_cert) != profile["certificate_identity"]:
            raise _invalid()
        for certificate in (cosign_cert, github_cert):
            if _extension(certificate, FULCIO_ISSUER_OID) != profile["oidc_issuer"]:
                raise _invalid()
        expected_oids = {
            FULCIO_RUNNER_OID: profile["runner_environment"],
            FULCIO_REPOSITORY_OID: profile["repository"],
            FULCIO_COMMIT_OID: profile["source_commit"],
            FULCIO_REF_OID: "refs/tags/" + profile["release_tag"],
            FULCIO_REPOSITORY_ID_OID: profile["repository_id"],
            FULCIO_OWNER_ID_OID: profile["repository_owner_id"],
            FULCIO_WORKFLOW_OID: profile["workflow_ref"],
            FULCIO_VISIBILITY_OID: profile["repository_visibility"],
        }
        for oid, expected in expected_oids.items():
            if _extension(github_cert, oid) != expected:
                raise _invalid()

        revocation, _ = _verify_signed_record(raw_inputs.revocation_snapshot, domain="runtime-attestation/revocation/v1", public_key=revocation_key)
        revocation = _closed(revocation, {"snapshot_at", "non_revoked_certificate_serials", "synthetic"})
        serials = revocation["non_revoked_certificate_serials"]
        if revocation["synthetic"] is not True or _time(revocation["snapshot_at"]) != _time(profile["verification_time"]) or serials != [format(cosign_cert.serial_number, "x"), format(github_cert.serial_number, "x")]:
            raise _invalid()

        checkpoint_lines = raw_inputs.rekor_checkpoint.split(b"\n")
        if len(checkpoint_lines) < 4:
            raise _invalid()
        checkpoint_root = decode_base64(checkpoint_lines[2].decode("ascii"), minimum=32, maximum=32)
        verify_checkpoint_note(
            note_raw=raw_inputs.rekor_checkpoint,
            expected_origin=profile["checkpoint_origin"],
            expected_tree_size=2,
            expected_root_hash=checkpoint_root,
            public_key_raw=rekor_key,
        )
        cosign_cert_b64 = base64.b64encode(cosign_cert_der).decode("ascii")
        github_cert_b64 = base64.b64encode(github_cert_der).decode("ascii")
        _verify_tlog(
            body_raw=cosign_body, expected_content_hash=cosign_payload_sha256,
            expected_signature_b64=message["signature"], expected_certificate_b64=cosign_cert_b64,
            tlog=cosign_tlog, sibling=cosign_sibling, checkpoint_root=checkpoint_root,
        )
        _verify_tlog(
            body_raw=github_body, expected_content_hash=hashlib.sha256(pae_raw).hexdigest(),
            expected_signature_b64=dsse_signature_entry["sig"], expected_certificate_b64=github_cert_b64,
            tlog=github_tlog, sibling=github_sibling, checkpoint_root=checkpoint_root,
        )

        payload = _closed(_raw_json(raw_inputs.cosign_payload), {"critical", "optional"})
        critical = _closed(payload["critical"], {"identity", "image", "type"})
        identity = _closed(critical["identity"], {"docker-reference"})
        image = _closed(critical["image"], {"docker-manifest-digest"})
        if critical["type"] != SIMPLE_SIGNING_TYPE or identity["docker-reference"] != "ghcr.io/01121531/email-api" or image["docker-manifest-digest"] != prior.runtime_artifact_digest or not isinstance(payload["optional"], dict):
            raise _invalid()

        statement = _closed(_raw_json(statement_raw), {"_type", "subject", "predicateType", "predicate"})
        statement_subjects = statement["subject"]
        if statement["_type"] != INTOTO_STATEMENT_TYPE or statement["predicateType"] != SLSA_PREDICATE_TYPE or not isinstance(statement_subjects, list) or len(statement_subjects) != 1:
            raise _invalid()
        statement_subject = _closed(statement_subjects[0], {"name", "digest"})
        if statement_subject["name"] != "ghcr.io/01121531/email-api" or statement_subject["digest"] != {"sha256": prior.runtime_artifact_digest.split(":", 1)[1]}:
            raise _invalid()
        predicate = _closed(statement["predicate"], {"buildDefinition", "runDetails"})
        definition = _closed(predicate["buildDefinition"], {"buildType", "externalParameters", "internalParameters", "resolvedDependencies"})
        external = _closed(definition["externalParameters"], {"ref", "repository", "workflow"})
        internal = _closed(definition["internalParameters"], {"github_event_name", "hermetic_build_claim"})
        dependencies = definition["resolvedDependencies"]
        if (
            definition["buildType"] != "https://actions.github.io/buildtypes/workflow/v1"
            or external != {"ref": "refs/tags/" + profile["release_tag"], "repository": profile["repository"], "workflow": ".github/workflows/release.yml"}
            or internal != {"github_event_name": "push", "hermetic_build_claim": False}
            or not isinstance(dependencies, list) or len(dependencies) != 1
        ):
            raise _invalid()
        dependency = _closed(dependencies[0], {"uri", "digest"})
        if dependency["digest"] != {"gitCommit": profile["source_commit"]}:
            raise _invalid()

        target, target_raw = _verify_signed_record(raw_inputs.target_observer, domain="runtime-attestation/target-observer/v1", public_key=target_key)
        target = _closed(target, {"runtime_subject_sha256", "artifact_digest", "deploy_selected_digest", "target_observed_digest", "target_process_identity_sha256", "target_loaded_evidence_sha256", "observed_at", "synthetic"})
        if (
            target["synthetic"] is not True
            or target["runtime_subject_sha256"] != prior.runtime_subject_sha256
            or target["artifact_digest"] != prior.runtime_artifact_digest
            or target["deploy_selected_digest"] != subject["deploy_selected_digest"]
            or target["target_observed_digest"] != subject["target_observed_digest"]
            or target["target_process_identity_sha256"] != subject["target_process_identity_sha256"]
            or target["target_loaded_evidence_sha256"] != subject["target_loaded_evidence_sha256"]
            or _time(target["observed_at"]) != _time(evidence["target_observation"]["observed_at"])
        ):
            raise _invalid()

        provider_head = evidence["provider_head"]
        write, write_raw = _verify_signed_record(raw_inputs.provider_write_receipt, domain="runtime-attestation/provider-cas-write/v1", public_key=provider_key)
        write = _closed(write, {"status", "if_match", "prior_generation", "new_generation", "new_etag", "runtime_subject_sha256", "cas_request_id", "proposed_entry_sha256", "synthetic"})
        if (
            write["synthetic"] is not True or write["status"] != 201
            or write["if_match"] != '"' + subject["expected_prior_provider_head"] + '"'
            or write["prior_generation"] != subject["generation_sequence"]
            or write["new_generation"] != subject["proposed_provider_sequence"]
            or write["new_etag"] != '"' + provider_head["proposed_entry_sha256"] + '"'
            or write["runtime_subject_sha256"] != prior.runtime_subject_sha256
            or write["cas_request_id"] != subject["cas_request_id"]
            or write["proposed_entry_sha256"] != provider_head["proposed_entry_sha256"]
        ):
            raise _invalid()
        read, read_raw = _verify_signed_record(raw_inputs.provider_read_receipt, domain="runtime-attestation/provider-cas-read/v1", public_key=provider_key)
        read = _closed(read, {"status", "etag", "generation", "current_head", "write_receipt_payload_sha256", "automatic_retry_performed", "synthetic"})
        if (
            read["synthetic"] is not True or read["status"] != 200
            or read["etag"] != write["new_etag"] or read["generation"] != write["new_generation"]
            or read["current_head"] != write["proposed_entry_sha256"]
            or read["write_receipt_payload_sha256"] != hashlib.sha256(write_raw).hexdigest()
            or read["automatic_retry_performed"] is not False
            or provider_head["read_after_current_head"] != read["current_head"]
        ):
            raise _invalid()

        _verify_cli(
            raw_inputs.cosign_cli_result, tool="cosign", version=profile["cosign_cli_version"],
            executable_sha256=_sha(pins.cosign_executable_sha256), bundle_sha256=hashlib.sha256(raw_inputs.cosign_bundle).hexdigest(),
            payload_sha256=cosign_payload_sha256,
        )
        _verify_cli(
            raw_inputs.github_cli_result, tool="gh-attestation", version=profile["github_cli_version"],
            executable_sha256=_sha(pins.github_executable_sha256), bundle_sha256=hashlib.sha256(raw_inputs.github_bundle).hexdigest(),
            payload_sha256=hashlib.sha256(statement_raw).hexdigest(),
        )
    except (RuntimeAttestationCryptoError, RuntimeAttestationIntakeError, KeyError, TypeError, ValueError, UnicodeError) as error:
        if isinstance(error, RuntimeAttestationProviderError):
            raise
        raise _invalid() from error

    return VerifiedRuntimeAttestationProviderFixture(
        runtime_subject_sha256=prior.runtime_subject_sha256,
        runtime_artifact_digest=prior.runtime_artifact_digest,
        adapter_profile_sha256=profile_sha256,
        evidence_index_sha256=index_sha256,
        cosign_payload_sha256=cosign_payload_sha256,
        github_statement_sha256=hashlib.sha256(statement_raw).hexdigest(),
        checkpoint_sha256=hashlib.sha256(raw_inputs.rekor_checkpoint).hexdigest(),
        target_observation_sha256=hashlib.sha256(target_raw).hexdigest(),
        provider_head_sha256=hashlib.sha256(read_raw).hexdigest(),
        fixture_signature_cryptography_verified=True,
        fixture_tsa_cryptography_verified=True,
        fixture_transparency_inclusion_verified=True,
        fixture_receipt_cryptography_verified=True,
        trust_root_currentness_verified=False,
        revocation_freshness_verified=False,
        provider_native_cas_verified=False,
        original_execution_verified=False,
        runtime_authority_verified=False,
        production_acceptance=False,
    )
