"""Validate one dedicated, inline, self-contained Kubernetes kubeconfig."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization
import yaml

try:
    from scripts.external_yaml import RepositoryYamlError, parse_unique_yaml
except ModuleNotFoundError:
    from external_yaml import RepositoryYamlError, parse_unique_yaml


MAX_KUBECONFIG_BYTES = 1024 * 1024
MAX_DECODED_CA_BYTES = 256 * 1024
MAX_DECODED_CLIENT_CERT_BYTES = 128 * 1024
MAX_DECODED_CLIENT_KEY_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 16 * 1024
MAX_YAML_NODES = 4096
MAX_YAML_DEPTH = 16
_REFERENCE_NAME = re.compile(r"^[A-Za-z0-9._:/@-]{1,128}$")
_DNS_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_NAMESPACE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_TOP_FIELDS = {
    "apiVersion", "kind", "preferences", "clusters", "users", "contexts",
    "current-context",
}
_CLUSTER_FIELDS = {"server", "certificate-authority-data"}
_CLUSTER_OPTIONAL_FIELDS = {"tls-server-name", "disable-compression"}
_CONTEXT_FIELDS = {"cluster", "user"}
_CONTEXT_OPTIONAL_FIELDS = {"namespace"}


class KubernetesKubeconfigIntakeError(ValueError):
    """The kubeconfig does not satisfy the dedicated self-contained contract."""


def _fail() -> None:
    raise KubernetesKubeconfigIntakeError("Kubernetes kubeconfig intake is invalid")


def _reject_yaml_indirection(text: str) -> None:
    try:
        events = yaml.parse(text, Loader=yaml.SafeLoader)
        for event in events:
            if (
                isinstance(event, yaml.events.AliasEvent)
                or getattr(event, "anchor", None) is not None
                or getattr(event, "tag", None) is not None
            ):
                _fail()
    except (yaml.YAMLError, RecursionError):
        _fail()


def _bounded_tree(value: object) -> None:
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > MAX_YAML_NODES or depth > MAX_YAML_DEPTH:
            _fail()
        if isinstance(item, dict):
            pending.extend((key, depth + 1) for key in item)
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > MAX_KUBECONFIG_BYTES:
                _fail()
        elif item is not None and type(item) not in {bool, int, float}:
            _fail()


def _closed(
    value: object,
    required: set[str],
    optional: frozenset[str] | set[str] = frozenset(),
) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or not required.issubset(value)
        or not set(value).issubset(required | optional)
    ):
        _fail()
    return value


def _named_entry(value: object, body_name: str) -> tuple[str, dict[str, object]]:
    entry = _closed(value, {"name", body_name})
    name = entry["name"]
    body = entry[body_name]
    if (
        not isinstance(name, str)
        or _REFERENCE_NAME.fullmatch(name) is None
        or not isinstance(body, dict)
    ):
        _fail()
    return name, body


def _decoded(value: object, *, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum * 2:
        _fail()
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        _fail()
    if not raw or len(raw) > maximum:
        _fail()
    canonical = base64.b64encode(raw).decode("ascii")
    if value != canonical:
        _fail()
    return raw


def _certificates(value: object, *, maximum: int) -> list[x509.Certificate]:
    raw = _decoded(value, maximum=maximum)
    try:
        certificates = x509.load_pem_x509_certificates(raw)
    except ValueError:
        _fail()
    if not certificates:
        _fail()
    return certificates


def _server(value: object) -> None:
    if not isinstance(value, str) or len(value) > 2048 or any(ord(char) < 0x21 for char in value):
        _fail()
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        _fail()
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.netloc
        or (port is not None and not 1 <= port <= 65535)
    ):
        _fail()


def _tls_server_name(value: object) -> None:
    if not isinstance(value, str) or not value or len(value) > 253:
        _fail()
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    if _DNS_NAME.fullmatch(value.casefold()) is None:
        _fail()


def _cluster(value: dict[str, object]) -> None:
    cluster = _closed(value, _CLUSTER_FIELDS, _CLUSTER_OPTIONAL_FIELDS)
    _server(cluster["server"])
    authorities = _certificates(
        cluster["certificate-authority-data"], maximum=MAX_DECODED_CA_BYTES
    )
    def is_ca(certificate: x509.Certificate) -> bool:
        try:
            return certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value.ca
        except x509.ExtensionNotFound:
            return False

    if not any(is_ca(certificate) for certificate in authorities):
        _fail()
    if "tls-server-name" in cluster:
        _tls_server_name(cluster["tls-server-name"])
    if "disable-compression" in cluster and type(cluster["disable-compression"]) is not bool:
        _fail()


def _public_key_bytes(value: object) -> bytes:
    return value.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _user(value: dict[str, object]) -> str:
    if set(value) == {"token"}:
        token = value["token"]
        if not isinstance(token, str):
            _fail()
        try:
            raw = token.encode("ascii")
        except UnicodeEncodeError:
            _fail()
        if not 32 <= len(raw) <= MAX_TOKEN_BYTES or any(byte < 0x21 or byte > 0x7E for byte in raw):
            _fail()
        return "bearer_token"
    if set(value) != {"client-certificate-data", "client-key-data"}:
        _fail()
    certificates = _certificates(
        value["client-certificate-data"], maximum=MAX_DECODED_CLIENT_CERT_BYTES
    )
    key_raw = _decoded(value["client-key-data"], maximum=MAX_DECODED_CLIENT_KEY_BYTES)
    try:
        private_key = serialization.load_pem_private_key(key_raw, password=None)
        matches = _public_key_bytes(certificates[0].public_key()) == _public_key_bytes(
            private_key.public_key()
        )
    except (TypeError, ValueError, AttributeError):
        _fail()
    if not matches:
        _fail()
    return "mutual_tls"


def validate_self_contained_kubeconfig(
    raw: bytes,
    *,
    expected_context: str,
    expected_namespace: str,
) -> str:
    """Return the raw snapshot digest after closed, secret-safe validation."""

    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > MAX_KUBECONFIG_BYTES
        or not isinstance(expected_context, str)
        or _REFERENCE_NAME.fullmatch(expected_context) is None
        or not isinstance(expected_namespace, str)
        or _NAMESPACE.fullmatch(expected_namespace) is None
    ):
        _fail()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail()
    _reject_yaml_indirection(text)
    try:
        value = parse_unique_yaml(text)
    except (RepositoryYamlError, yaml.YAMLError, RecursionError):
        _fail()
    _bounded_tree(value)
    config = _closed(value, _TOP_FIELDS)
    clusters = config["clusters"]
    users = config["users"]
    contexts = config["contexts"]
    if (
        config["apiVersion"] != "v1"
        or config["kind"] != "Config"
        or config["preferences"] != {}
        or not isinstance(clusters, list)
        or len(clusters) != 1
        or not isinstance(users, list)
        or len(users) != 1
        or not isinstance(contexts, list)
        or len(contexts) != 1
        or config["current-context"] != expected_context
    ):
        _fail()
    cluster_name, cluster = _named_entry(clusters[0], "cluster")
    user_name, user = _named_entry(users[0], "user")
    context_name, context = _named_entry(contexts[0], "context")
    context = _closed(context, _CONTEXT_FIELDS, _CONTEXT_OPTIONAL_FIELDS)
    if (
        context_name != expected_context
        or context["cluster"] != cluster_name
        or context["user"] != user_name
        or (
            "namespace" in context
            and context["namespace"] != expected_namespace
        )
    ):
        _fail()
    _cluster(cluster)
    _user(user)
    return hashlib.sha256(raw).hexdigest()
