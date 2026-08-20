"""Validate the Compose-managed non-root HTTPS edge contract."""

from __future__ import annotations

from pathlib import Path
import re
import sys
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
DOCKERFILE = ROOT / "infra" / "edge.Dockerfile"
RENDERER = ROOT / "infra" / "nginx" / "render-edge-config.sh"
TEMPLATE = ROOT / "infra" / "nginx" / "email-platform.conf.template"
ENV_EXAMPLE = ROOT / ".env.example"


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def load_assets() -> tuple[dict[str, Any], str, str, str, str]:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    if not isinstance(compose, dict):
        raise ValueError("docker-compose.yml must contain a mapping")
    return (
        compose,
        DOCKERFILE.read_text(encoding="utf-8"),
        RENDERER.read_text(encoding="utf-8"),
        TEMPLATE.read_text(encoding="utf-8"),
        ENV_EXAMPLE.read_text(encoding="utf-8"),
    )


def _published_ports(service: dict[str, Any]) -> set[int]:
    published: set[int] = set()
    for raw in _list(service.get("ports")):
        if isinstance(raw, dict):
            value = raw.get("published")
            if isinstance(value, int):
                published.add(value)
            elif isinstance(value, str) and value.isdigit():
                published.add(int(value))
            continue
        parts = str(raw).rsplit(":", 2)
        if len(parts) >= 2:
            value = parts[-2]
            if value.isdigit():
                published.add(int(value))
    return published


def validate_edge_assets(
    compose: dict[str, Any],
    dockerfile: str,
    renderer: str,
    template: str,
    env_example: str,
) -> list[str]:
    errors: list[str] = []
    services = _mapping(compose.get("services"))
    edge = _mapping(services.get("edge"))
    if not edge:
        return ["Compose is missing edge service"]

    build = _mapping(edge.get("build"))
    if build.get("context") != "." or build.get("dockerfile") != "infra/edge.Dockerfile":
        errors.append("edge must build infra/edge.Dockerfile from repository context")
    if edge.get("user") != "101:101":
        errors.append("edge must run as non-root UID/GID 101")
    if edge.get("read_only") is not True:
        errors.append("edge root filesystem must be read-only")
    if edge.get("cap_drop") != ["ALL"] or edge.get("cap_add"):
        errors.append("edge must drop all Linux capabilities and add none")
    if edge.get("security_opt") != ["no-new-privileges:true"]:
        errors.append("edge must set no-new-privileges:true")
    required_tmpfs = {"/tmp", "/etc/nginx/conf.d", "/var/run", "/var/cache/nginx"}
    tmpfs = {str(item) for item in _list(edge.get("tmpfs"))}
    if not required_tmpfs.issubset(tmpfs):
        errors.append("edge is missing required writable tmpfs paths")

    if {str(item) for item in _list(edge.get("ports"))} != {"80:8080", "443:8443"}:
        errors.append("edge must publish host 80/443 to unprivileged 8080/8443")
    for name, raw_service in services.items():
        service = _mapping(raw_service)
        if name != "edge" and _published_ports(service) & {80, 443}:
            errors.append(f"only edge may publish host ports 80/443: {name}")
    for name in ("api", "web", "keycloak"):
        if _list(_mapping(services.get(name)).get("ports")):
            errors.append(f"{name} must not publish a host port")

    mounts = {str(item) for item in _list(edge.get("volumes"))}
    required_mounts = {
        "PLATFORM_TLS_CERT_FILE": "/etc/nginx/tls/fullchain.pem:ro",
        "PLATFORM_TLS_KEY_FILE": "/etc/nginx/tls/privkey.pem:ro",
    }
    for variable, target in required_mounts.items():
        if not any(variable in mount and mount.endswith(f":{target}") for mount in mounts):
            errors.append(f"edge must mount {variable} at {target}")
    environment = _mapping(edge.get("environment"))
    if set(environment) != {"PLATFORM_DOMAIN"}:
        errors.append("edge environment may contain only PLATFORM_DOMAIN")

    dependencies = _mapping(edge.get("depends_on"))
    expected_dependencies = {
        "api": {"condition": "service_healthy"},
        "web": {"condition": "service_healthy"},
        "keycloak": {"condition": "service_healthy"},
    }
    if dependencies != expected_dependencies:
        errors.append("edge must wait for healthy api, web, and keycloak services")
    if not _mapping(_mapping(services.get("web")).get("healthcheck")):
        errors.append("web must define a healthcheck for edge startup ordering")
    if not _mapping(edge.get("healthcheck")):
        errors.append("edge must define a healthcheck")

    if not re.search(
        r"^FROM nginxinc/nginx-unprivileged:[0-9][^\s@]*@sha256:[0-9a-f]{64}$",
        dockerfile,
        re.MULTILINE,
    ):
        errors.append("edge image must pin an nginx-unprivileged version and digest")
    for required in (
        "USER 101:101",
        'ENTRYPOINT ["/usr/local/bin/render-edge-config"]',
        "COPY infra/nginx/email-platform.conf.template",
        "COPY infra/nginx/render-edge-config.sh",
    ):
        if required not in dockerfile:
            errors.append(f"edge Dockerfile is missing: {required}")

    if "envsubst" in renderer:
        errors.append("edge renderer must not perform broad environment substitution")
    for required in (
        'sed "s/\\${PLATFORM_DOMAIN}/${PLATFORM_DOMAIN}/g"',
        'nginx -t -q',
        'exec "$@"',
        'private_key=/etc/nginx/tls/privkey.pem',
        'certificate=/etc/nginx/tls/fullchain.pem',
    ):
        if required not in renderer:
            errors.append(f"edge renderer is missing: {required}")

    placeholders = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)\}", template))
    if placeholders != {"PLATFORM_DOMAIN"}:
        errors.append("Nginx template may substitute only PLATFORM_DOMAIN")
    rendered = template.replace("${PLATFORM_DOMAIN}", "platform.example.test")
    for variable in ("$host", "$request_uri", "$remote_addr", "$proxy_add_x_forwarded_for"):
        if variable not in rendered:
            errors.append(f"Nginx runtime variable was not preserved: {variable}")
    if re.search(r"\blisten\s+(?:\[::\]:)?(?:80|443)\b", template):
        errors.append("non-root edge must not bind privileged container ports")
    for required in (
        "listen 8080 default_server;",
        "listen 8443 ssl http2 default_server;",
        "server_name _;",
        "return 444;",
        "listen 8080;",
        "listen 8443 ssl http2;",
        "proxy_pass http://api:8000;",
        "proxy_pass http://web:8080;",
        "proxy_pass http://keycloak:8080;",
        "ssl_certificate     /etc/nginx/tls/fullchain.pem;",
        "ssl_certificate_key /etc/nginx/tls/privkey.pem;",
    ):
        if required not in template:
            errors.append(f"Nginx edge template is missing: {required}")
    server_names = re.findall(r"^\s*server_name\s+([^;]+);", template, re.MULTILINE)
    if server_names != [
        "_",
        "_",
        "${PLATFORM_DOMAIN}",
        "${PLATFORM_DOMAIN}",
        "identity.${PLATFORM_DOMAIN}",
        "identity.${PLATFORM_DOMAIN}",
    ]:
        errors.append("Nginx server names must fail closed before platform and identity hosts")
    if template.count("return 444;") != 2:
        errors.append("Nginx must reject unknown HTTP and HTTPS hosts with 444")

    for variable in ("PLATFORM_TLS_CERT_FILE=", "PLATFORM_TLS_KEY_FILE="):
        if variable not in env_example:
            errors.append(f".env.example is missing {variable[:-1]}")
    combined = "\n".join((dockerfile, renderer, template, env_example))
    if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", combined):
        errors.append("edge assets must never contain a private key")
    return errors


def main() -> int:
    try:
        errors = validate_edge_assets(*load_assets())
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"Edge asset load failed: {error}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("edge-assets-ok non-root-https-domain-rendering-and-tls-mounts-validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
