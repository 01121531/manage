"""Validate reviewed PCI/CVV and OIDC deployment decision envelopes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import MAX_INTAKE_JSON_BYTES, load_unique_json
from platform.config import Settings
from platform.models import Base
from platform.schemas import CardRevealResponse
from platform.uploads import _sub2_card_payload


CARD_PCI_DECISION = (
    ROOT / "deploy" / "decision-envelopes" / "card-pci.synthetic.json"
)
OIDC_IDENTITY_DECISION = (
    ROOT
    / "deploy"
    / "decision-envelopes"
    / "oidc-deployment-identity.synthetic.json"
)
KEYCLOAK_REALM = ROOT / "infra" / "keycloak" / "email-platform-realm.json"

_COMMON_KEYS = {
    "schema_version",
    "decision_type",
    "decision_reference",
    "synthetic",
    "decision_status",
    "review_reference",
    "production_acceptance",
    "prohibited_content",
}
_CARD_KEYS = _COMMON_KEYS | {"field_inventory", "pci_scope"}
_OIDC_KEYS = _COMMON_KEYS | {"deployment_identity", "acr_to_loa", "clients"}
_PROHIBITED_KEYS = {
    "contains_live_credentials",
    "contains_personal_data",
    "contains_pan_values",
    "contains_cvv_values",
    "contains_token_values",
}
_FIELD_KEYS = {
    "source",
    "platform_database_storage",
    "api_reveal",
    "sub2_egress",
}
_PCI_SCOPE_KEYS = {
    "classification",
    "assessment_reference",
    "card_vault_owner_reference",
}
_IDENTITY_KEYS = {
    "issuer_reference",
    "subject_claim",
    "tenant_claim",
    "device_claim",
    "device_id_ownership",
    "token_sample_policy",
}
_ACR_KEYS = {
    "required_acr",
    "loa",
    "authentication_methods",
    "mapping_review_reference",
}
_CLIENT_KEYS = {
    "client_type",
    "authorization_flow",
    "pkce_method",
    "device_flow",
}
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_PLACEHOLDERS = {"example", "placeholder", "tbd", "todo", "unknown"}


def _safe_reference(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _REFERENCE.fullmatch(value) is not None
        and value.casefold() not in _PLACEHOLDERS
    )


def _common_errors(document: dict[str, Any], expected_type: str | None) -> list[str]:
    errors: list[str] = []
    decision_type = document.get("decision_type")
    if document.get("schema_version") != 1 or decision_type not in {
        "card_pci_boundary",
        "oidc_deployment_identity",
    }:
        errors.append("decision envelope identity is invalid")
    if expected_type is not None and decision_type != expected_type:
        errors.append("decision envelope type does not match the intake item")
    if document.get("production_acceptance") is not False:
        errors.append("decision envelope must not claim production acceptance")

    synthetic = document.get("synthetic")
    reference = document.get("decision_reference")
    review_reference = document.get("review_reference")
    status = document.get("decision_status")
    if not isinstance(synthetic, bool) or not _safe_reference(reference):
        errors.append("decision envelope reference is invalid")
    elif synthetic:
        if (
            not reference.startswith("synthetic-")
            or status != "pending"
            or review_reference is not None
        ):
            errors.append("synthetic decision envelope metadata is invalid")
    elif (
        reference.startswith("synthetic-")
        or status != "approved"
        or not _safe_reference(review_reference)
        or reference == review_reference
    ):
        errors.append("reviewed decision envelope approval metadata is invalid")

    prohibited = document.get("prohibited_content")
    if (
        not isinstance(prohibited, dict)
        or set(prohibited) != _PROHIBITED_KEYS
        or any(value is not False for value in prohibited.values())
    ):
        errors.append("decision envelope prohibited-content declaration is invalid")
    return errors


def _card_errors(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    inventory = document.get("field_inventory")
    if not isinstance(inventory, dict) or set(inventory) != {"pan", "expiry", "cvv"}:
        return ["card decision field inventory is invalid"]
    if any(not isinstance(item, dict) or set(item) != _FIELD_KEYS for item in inventory.values()):
        return ["card decision field schema is invalid"]
    expected = {
        "pan": {
            "source": "external_card_vault",
            "platform_database_storage": False,
            "api_reveal": "mfa_one_time",
            "sub2_egress": "reviewed_contract_only",
        },
        "expiry": {
            "source": "external_card_vault_optional",
            "platform_database_storage": False,
            "api_reveal": "with_pan",
            "sub2_egress": "reviewed_contract_only",
        },
        "cvv": {
            "source": "prohibited",
            "platform_database_storage": False,
            "api_reveal": "prohibited",
            "sub2_egress": "prohibited",
        },
    }
    if inventory != expected:
        errors.append("card decision conflicts with the repository card-data boundary")

    scope = document.get("pci_scope")
    if not isinstance(scope, dict) or set(scope) != _PCI_SCOPE_KEYS:
        errors.append("card decision PCI scope schema is invalid")
    elif document.get("synthetic") is True:
        if scope != {
            "classification": "pending",
            "assessment_reference": None,
            "card_vault_owner_reference": None,
        }:
            errors.append("synthetic card decision PCI scope must remain pending")
    elif (
        scope.get("classification")
        not in {"in_scope", "service_provider_shared_responsibility"}
        or not _safe_reference(scope.get("assessment_reference"))
        or not _safe_reference(scope.get("card_vault_owner_reference"))
        or len(
            {
                document.get("review_reference"),
                scope.get("assessment_reference"),
                scope.get("card_vault_owner_reference"),
            }
        )
        != 3
    ):
        errors.append("reviewed card decision PCI scope is incomplete")
    return errors


def _oidc_errors(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    identity = document.get("deployment_identity")
    if not isinstance(identity, dict) or set(identity) != _IDENTITY_KEYS:
        errors.append("OIDC deployment identity schema is invalid")
    else:
        expected_claims = {
            "subject_claim": "sub",
            "tenant_claim": "tenant_id",
            "device_claim": "device_id",
            "device_id_ownership": "platform_registration_bound_to_subject",
        }
        if any(identity.get(key) != value for key, value in expected_claims.items()):
            errors.append("OIDC claim or device ownership decision is incompatible")
        if identity.get("token_sample_policy") not in {
            "omitted",
            "irreversibly_redacted_external_evidence",
        }:
            errors.append("OIDC token sample policy is invalid")
        issuer = identity.get("issuer_reference")
        if document.get("synthetic") is True:
            if issuer is not None:
                errors.append("synthetic OIDC decision must not name an issuer")
        elif not _safe_reference(issuer):
            errors.append("reviewed OIDC issuer reference is missing")

    acr = document.get("acr_to_loa")
    if not isinstance(acr, dict) or set(acr) != _ACR_KEYS:
        errors.append("OIDC ACR-to-LoA schema is invalid")
    else:
        if (
            acr.get("required_acr") != "urn:email-platform:acr:mfa"
            or acr.get("loa") != "multi_factor"
        ):
            errors.append("OIDC ACR-to-LoA decision weakens the step-up boundary")
        methods = acr.get("authentication_methods")
        if (
            not isinstance(methods, list)
            or not methods
            or len(methods) != len(set(methods))
            or not set(methods).issubset({"otp", "webauthn"})
        ):
            errors.append("OIDC authentication-method decision is invalid")
        mapping_reference = acr.get("mapping_review_reference")
        if document.get("synthetic") is True:
            if mapping_reference is not None:
                errors.append("synthetic OIDC mapping must remain unreviewed")
        elif not _safe_reference(mapping_reference):
            errors.append("reviewed OIDC mapping reference is missing")
        elif len(
            {
                document.get("review_reference"),
                mapping_reference,
                identity.get("issuer_reference") if isinstance(identity, dict) else None,
            }
        ) != 3:
            errors.append("reviewed OIDC decision references are not independent")

    clients = document.get("clients")
    if not isinstance(clients, dict) or set(clients) != {"web", "desktop"}:
        errors.append("OIDC client decision schema is invalid")
    else:
        expected_devices = {"web": "disabled", "desktop": "fallback_enabled"}
        for name, device_flow in expected_devices.items():
            client = clients.get(name)
            if (
                not isinstance(client, dict)
                or set(client) != _CLIENT_KEYS
                or client.get("client_type") != "public"
                or client.get("authorization_flow") != "authorization_code"
                or client.get("pkce_method") != "S256"
                or client.get("device_flow") != device_flow
            ):
                errors.append(f"OIDC {name} client decision is incompatible")
    return errors


def decision_errors(document: Any, *, expected_type: str | None = None) -> list[str]:
    if not isinstance(document, dict):
        return ["decision envelope top-level schema is invalid"]
    decision_type = document.get("decision_type")
    expected_keys = {
        "card_pci_boundary": _CARD_KEYS,
        "oidc_deployment_identity": _OIDC_KEYS,
    }.get(decision_type)
    if expected_keys is None or set(document) != expected_keys:
        return ["decision envelope top-level schema is invalid"]
    errors = _common_errors(document, expected_type)
    if decision_type == "card_pci_boundary":
        errors.extend(_card_errors(document))
    else:
        errors.extend(_oidc_errors(document))
    return errors


def runtime_alignment_errors(document: Any) -> list[str]:
    if decision_errors(document):
        return ["decision envelope must be valid before runtime alignment"]
    if document["decision_type"] == "card_pci_boundary":
        card_columns = set(Base.metadata.tables["cards"].columns.keys())
        if card_columns.intersection({"pan", "cvv", "cvc", "security_code"}):
            return ["platform database persists prohibited raw card fields"]
        if "cvv" in CardRevealResponse.model_fields:
            return ["card reveal API exposes CVV"]
        outbound = _sub2_card_payload(
            {
                "pan": "0" * 12,
                "expiry_month": 12,
                "expiry_year": 2030,
                "cvv": "0" * 3,
            }
        )
        if "cvv" in outbound:
            return ["Sub2 card projection emits CVV"]
        return []

    required_acr = document["acr_to_loa"]["required_acr"]
    if any(
        Settings.model_fields[field].default != required_acr
        for field in ("card_step_up_acr", "admin_role_change_acr")
    ):
        return ["runtime step-up ACR does not match the decision envelope"]
    try:
        realm = load_unique_json(
            KEYCLOAK_REALM,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ["Keycloak realm is unavailable"]
    authenticators = {
        execution.get("authenticator")
        for flow in realm.get("authenticationFlows", [])
        if isinstance(flow, dict)
        for execution in flow.get("authenticationExecutions", [])
        if isinstance(execution, dict)
    }
    methods = set(document["acr_to_loa"]["authentication_methods"])
    errors: list[str] = []
    if "otp" in methods and "auth-otp-form" not in authenticators:
        errors.append("Keycloak realm does not implement the decided OTP method")
    if "webauthn" in methods and not any(
        isinstance(value, str) and "webauthn" in value.casefold()
        for value in authenticators
    ):
        errors.append("Keycloak realm does not implement the decided WebAuthn method")
    clients = {
        item.get("clientId"): item
        for item in realm.get("clients", [])
        if isinstance(item, dict)
    }
    for decision_name, client_id in (
        ("web", "email-platform-web"),
        ("desktop", "email-platform-desktop"),
    ):
        client = clients.get(client_id)
        if (
            not isinstance(client, dict)
            or client.get("publicClient") is not True
            or client.get("standardFlowEnabled") is not True
            or client.get("attributes", {}).get("pkce.code.challenge.method") != "S256"
        ):
            errors.append(f"Keycloak {decision_name} client does not enforce public S256 PKCE")
            continue
        claims = {
            mapper.get("config", {}).get("claim.name")
            for mapper in client.get("protocolMappers", [])
            if isinstance(mapper, dict)
        }
        if not {"tenant_id", "device_id"}.issubset(claims):
            errors.append(
                f"Keycloak {decision_name} client lacks tenant/device claim mappings"
            )
        device_flow_enabled = (
            client.get("attributes", {}).get(
                "oauth2.device.authorization.grant.enabled"
            )
            == "true"
        )
        if device_flow_enabled != (decision_name == "desktop"):
            errors.append(
                f"Keycloak {decision_name} client device-flow setting is incompatible"
            )
    return errors


def _load(path: Path) -> Any:
    return load_unique_json(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-repository")
    check = commands.add_parser("check")
    check.add_argument("--input", required=True, type=Path)
    check.add_argument(
        "--expected-type",
        required=True,
        choices=("card_pci_boundary", "oidc_deployment_identity"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "verify-repository":
        try:
            documents = (
                (_load(CARD_PCI_DECISION), "card_pci_boundary"),
                (_load(OIDC_IDENTITY_DECISION), "oidc_deployment_identity"),
            )
        except (OSError, UnicodeError, json.JSONDecodeError):
            print("decision-envelopes-invalid", file=sys.stderr)
            return 1
        errors = [
            error
            for document, decision_type in documents
            for error in (
                decision_errors(document, expected_type=decision_type)
                + runtime_alignment_errors(document)
            )
        ]
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        print(
            "decision-envelopes-ok card=aligned oidc=aligned "
            "production_acceptance=false"
        )
        return 0
    try:
        document = _load(arguments.input)
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("decision-envelope-invalid", file=sys.stderr)
        return 1
    errors = decision_errors(document, expected_type=arguments.expected_type)
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    alignment = runtime_alignment_errors(document)
    if alignment:
        print("; ".join(alignment), file=sys.stderr)
        return 2
    print(
        f"decision-envelope-aligned type={arguments.expected_type} "
        "production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
