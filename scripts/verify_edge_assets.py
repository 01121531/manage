"""Validate the Compose-managed non-root HTTPS edge contract."""

from __future__ import annotations

from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import urlsplit

import yaml

try:
    from scripts.external_yaml import load_unique_yaml
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_yaml import load_unique_yaml
    from external_text import load_stable_text


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
DEV_COMPOSE = ROOT / "docker-compose.dev.yml"
DOCKERFILE = ROOT / "infra" / "edge.Dockerfile"
WEB_DOCKERFILE = ROOT / "infra" / "frontend.Dockerfile"
RENDERER = ROOT / "infra" / "nginx" / "render-edge-config.sh"
TEMPLATE = ROOT / "infra" / "nginx" / "email-platform.conf.template"
WEB_CONFIG = ROOT / "infra" / "nginx" / "web.conf"
WEB_VALIDATOR = ROOT / "infra" / "nginx" / "validate-web-tls.sh"
ENV_EXAMPLE = ROOT / ".env.example"


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def load_assets() -> tuple[dict[str, Any], dict[str, Any], str, str, str, str, str, str, str]:
    compose = load_unique_yaml(COMPOSE)
    dev_compose = load_unique_yaml(DEV_COMPOSE)
    if not isinstance(compose, dict) or not isinstance(dev_compose, dict):
        raise ValueError("production and development Compose files must contain mappings")
    return (
        compose,
        dev_compose,
        load_stable_text(DOCKERFILE),
        load_stable_text(RENDERER),
        load_stable_text(TEMPLATE),
        load_stable_text(ENV_EXAMPLE),
        load_stable_text(WEB_DOCKERFILE),
        load_stable_text(WEB_CONFIG),
        load_stable_text(WEB_VALIDATOR),
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


def _mounts(service: dict[str, Any]) -> dict[str, tuple[str, bool]]:
    mounts: dict[str, tuple[str, bool]] = {}
    for raw in _list(service.get("volumes")):
        if isinstance(raw, dict):
            target = raw.get("target")
            source = raw.get("source")
            if isinstance(target, str) and isinstance(source, str):
                mounts[target] = (source, raw.get("read_only") is True)
            continue
        parts = str(raw).rsplit(":", 2)
        if len(parts) >= 2:
            source, target = parts[0], parts[1]
            mounts[target] = (source, len(parts) == 3 and parts[2] == "ro")
    return mounts


def _raw_mount(service: dict[str, Any], target: str) -> object | None:
    matches: list[object] = []
    for raw in _list(service.get("volumes")):
        if isinstance(raw, dict) and raw.get("target") == target:
            matches.append(raw)
        elif isinstance(raw, str):
            parts = raw.rsplit(":", 2)
            if len(parts) >= 2 and parts[-2] == target:
                matches.append(raw)
    return matches[0] if len(matches) == 1 else None


def _balanced_blocks(text: str, pattern: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    for match in re.finditer(pattern, text):
        start = match.end()
        depth = 1
        position = start
        while position < len(text) and depth:
            if text[position] == "{":
                depth += 1
            elif text[position] == "}":
                depth -= 1
            position += 1
        label = match.group(1).strip() if match.lastindex else ""
        blocks.append((label, text[start : position - 1]))
    return blocks


def _location_entries(text: str) -> list[tuple[str, str]]:
    return _balanced_blocks(text, r"location\s+([^\{]+)\{")


def _location_blocks(text: str) -> list[str]:
    return [body for _, body in _location_entries(text)]


def _server_blocks(text: str) -> list[str]:
    return [body for _, body in _balanced_blocks(text, r"\b(server)\s*\{")]


def validate_edge_assets(
    compose: dict[str, Any],
    dev_compose: dict[str, Any],
    dockerfile: str,
    renderer: str,
    template: str,
    env_example: str,
    web_dockerfile: str,
    web_config: str,
    web_validator: str,
) -> list[str]:
    errors: list[str] = []
    services = _mapping(compose.get("services"))
    edge = _mapping(services.get("edge"))
    if not edge:
        return ["Compose is missing edge service"]

    if "build" in edge:
        errors.append("production edge must not contain a build definition")
    dev_edge = _mapping(_mapping(dev_compose.get("services")).get("edge"))
    dev_build = _mapping(dev_edge.get("build"))
    if dev_build.get("context") != "." or dev_build.get("dockerfile") != "infra/edge.Dockerfile":
        errors.append("development edge must build infra/edge.Dockerfile from repository context")
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

    edge_mounts = _mounts(edge)
    web = _mapping(services.get("web"))
    web_mounts = _mounts(web)
    public_tls_mounts = {
        "/etc/nginx/tls/fullchain.pem": (
            "${PLATFORM_TLS_CERT_FILE:?set PLATFORM_TLS_CERT_FILE in .env}",
            "edge public TLS certificate",
        ),
        "/etc/nginx/tls/privkey.pem": (
            "${PLATFORM_TLS_KEY_FILE:?set PLATFORM_TLS_KEY_FILE in .env}",
            "edge public TLS private key",
        ),
    }
    for target, (expected_source, label) in public_tls_mounts.items():
        raw_mount = _raw_mount(edge, target)
        if not isinstance(raw_mount, dict) or raw_mount.get("type") != "bind":
            errors.append(f"{label} at {target} must use a fail-closed structured bind")
            continue
        if raw_mount.get("source") != expected_source:
            errors.append(f"{label} at {target} must use the exact required env source")
        if raw_mount.get("read_only") is not True:
            errors.append(f"{label} mount must be read-only")
        bind = _mapping(raw_mount.get("bind"))
        if bind.get("create_host_path") is not False:
            errors.append(f"{label} at {target} must set create_host_path=false")

    required_edge_mounts = {"/run/secrets/internal-tls/ca.crt": "internal TLS CA"}
    for target, label in required_edge_mounts.items():
        mount = edge_mounts.get(target)
        if mount is None:
            errors.append(f"edge must mount {label} at {target}")
        elif not mount[1]:
            errors.append(f"edge {label} mount must be read-only")
    required_web_mounts = {
        "/run/secrets/internal-tls/tls.crt": "web TLS certificate",
        "/run/secrets/internal-tls/tls.key": "web TLS private key",
    }
    for target, label in required_web_mounts.items():
        mount = web_mounts.get(target)
        if mount is None:
            errors.append(f"web must mount {label} at {target}")
        elif not mount[1]:
            errors.append(f"web {label} mount must be read-only")
    edge_key = edge_mounts.get("/etc/nginx/tls/privkey.pem")
    web_key = web_mounts.get("/run/secrets/internal-tls/tls.key")
    if edge_key and web_key and edge_key[0] == web_key[0]:
        errors.append("edge and web must not share a TLS private key")
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
        'internal_ca=/run/secrets/internal-tls/ca.crt',
        'if [ -w "$private_key" ]',
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

    body_size_directives = [
        item.strip()
        for item in re.findall(
            r"^\s*client_max_body_size\s+[^;]+;",
            rendered,
            re.MULTILINE,
        )
    ]
    expected_body_size = "client_max_body_size 2m;"
    platform_https_start = rendered.find("listen 8443 ssl http2;")
    api_location_start = rendered.find("location /api/ {", platform_https_start)
    body_size_start = rendered.find(expected_body_size, platform_https_start)
    if body_size_directives != [expected_body_size] or not (
        platform_https_start < body_size_start < api_location_start
    ):
        errors.append(
            "platform HTTPS API request body limit must be exactly 2m at server scope"
        )

    expected_zones = (
        "limit_req_zone $binary_remote_addr zone=platform_api:10m rate=10r/s;",
        "limit_req_zone $binary_remote_addr zone=platform_identity:10m rate=10r/s;",
    )
    zone_directives = [
        item.strip()
        for item in re.findall(
            r"^\s*limit_req_zone\s+[^;]+;",
            rendered,
            re.MULTILINE,
        )
    ]
    first_server = rendered.find("server {")
    zone_starts = [rendered.find(zone) for zone in expected_zones]
    if zone_directives != list(expected_zones) or not all(
        0 <= start < first_server for start in zone_starts
    ):
        errors.append(
            "edge rate limit zones must isolate the reviewed API and identity policies"
        )

    expected_limit_status = "limit_req_status 429;"
    limit_status_directives = [
        item.strip()
        for item in re.findall(
            r"^\s*limit_req_status\s+[^;]+;",
            rendered,
            re.MULTILINE,
        )
    ]
    limit_status_start = rendered.find(expected_limit_status)
    if limit_status_directives != [expected_limit_status] or not (
        0 <= limit_status_start < first_server
    ):
        errors.append("edge rate limit rejections must use HTTP 429")

    expected_api_limit = "limit_req zone=platform_api burst=20 nodelay;"
    expected_identity_limit = (
        "limit_req zone=platform_identity burst=20 nodelay;"
    )
    limit_directives = [
        item.strip()
        for item in re.findall(
            r"^\s*limit_req\s+[^;]+;",
            rendered,
            re.MULTILINE,
        )
    ]
    api_rate_blocks = [
        body
        for label, body in _location_entries(rendered)
        if label == "/api/"
        and "proxy_pass https://active_api;" in body
    ]
    identity_rate_blocks = [
        block
        for block in _location_blocks(rendered)
        if "proxy_pass https://keycloak:8443;" in block
    ]
    if (
        limit_directives != [expected_api_limit, expected_identity_limit]
        or len(api_rate_blocks) != 1
        or len(identity_rate_blocks) != 1
        or api_rate_blocks[0].count(expected_api_limit) != 1
        or identity_rate_blocks[0].count(expected_identity_limit) != 1
    ):
        errors.append(
            "API and identity proxy locations must use the reviewed edge rate limit"
        )

    if re.search(r"^\s*limit_req_dry_run\b", rendered, re.MULTILINE):
        errors.append("edge rate limit dry run is forbidden")
    if re.search(
        r"^\s*(?:set_real_ip_from|real_ip_header|real_ip_recursive)\b"
        r"|^\s*listen\b[^;]*\bproxy_protocol\b",
        rendered,
        re.MULTILINE,
    ):
        errors.append(
            "edge client IP trust requires a separately reviewed proxy contract"
        )

    expected_error_pages = [
        "error_page 413 = @api_request_too_large;",
        "error_page 429 = @api_rate_limited;",
        "error_page 429 = @identity_rate_limited;",
    ]
    error_page_directives = [
        item.strip()
        for item in re.findall(
            r"^\s*error_page\s+[^;]+;",
            rendered,
            re.MULTILINE,
        )
    ]
    safe_error_invalid = error_page_directives != expected_error_pages
    if len(api_rate_blocks) == 1:
        safe_error_invalid = safe_error_invalid or any(
            api_rate_blocks[0].count(directive) != 1
            for directive in expected_error_pages[:2]
        )
    if len(identity_rate_blocks) == 1:
        safe_error_invalid = (
            safe_error_invalid
            or identity_rate_blocks[0].count(expected_error_pages[2]) != 1
        )

    server_blocks = _server_blocks(rendered)
    platform_https_servers = [
        body
        for body in server_blocks
        if "listen 8443 ssl http2;" in body
        and "server_name platform.example.test;" in body
    ]
    identity_https_servers = [
        body
        for body in server_blocks
        if "listen 8443 ssl http2;" in body
        and "server_name identity.platform.example.test;" in body
    ]
    if len(platform_https_servers) != 1 or len(identity_https_servers) != 1:
        safe_error_invalid = True

    safe_headers = (
        'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        'add_header X-Content-Type-Options "nosniff" always;',
        'add_header X-Frame-Options "DENY" always;',
        'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        'add_header Content-Security-Policy "default-src \'none\'; frame-ancestors \'none\'; base-uri \'none\'" always;',
    )
    hsts_header = safe_headers[0]
    strict_csp_header = safe_headers[-1]
    web_csp_header = (
        'add_header Content-Security-Policy "default-src \'self\'; '
        "connect-src 'self' https://identity.platform.example.test; "
        "img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
        "form-action 'self' https://identity.platform.example.test\" always;"
    )
    identity_csp_header = (
        'add_header Content-Security-Policy "default-src \'self\' '
        "'unsafe-inline' 'unsafe-eval' data: blob:; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'\" always;"
    )

    normal_response_invalid = False
    normal_response_contract = (
        (
            platform_https_servers,
            (
                ("/api/", strict_csp_header),
                ("= /healthz", strict_csp_header),
                ("= /readyz", strict_csp_header),
                ("= /releasez", strict_csp_header),
                ("/", web_csp_header),
            ),
        ),
        (identity_https_servers, (("/", identity_csp_header),)),
    )
    for servers, locations in normal_response_contract:
        entries = _location_entries(servers[0]) if len(servers) == 1 else []
        for label, csp_header in locations:
            bodies = [body for entry_label, body in entries if entry_label == label]
            if len(bodies) != 1 or any(
                bodies[0].count(header) != 1
                for header in (hsts_header, csp_header)
            ):
                normal_response_invalid = True
    if normal_response_invalid:
        errors.append(
            "Edge normal responses must retain the exact HSTS and CSP headers"
        )

    handlers = (
        (
            platform_https_servers,
            "@api_request_too_large",
            "return 413 '{\"error\":{\"code\":\"request_too_large\",\"message\":\"Request body too large\",\"recovery_hint\":\"Reduce the request body to 2 MiB or less and retry.\",\"trace_id\":\"$request_id\"}}';",
            False,
            True,
        ),
        (
            platform_https_servers,
            "@api_rate_limited",
            "return 429 '{\"error\":{\"code\":\"rate_limited\",\"message\":\"Too many requests\",\"recovery_hint\":\"Retry after the number of seconds in Retry-After.\",\"trace_id\":\"$request_id\"}}';",
            True,
            True,
        ),
        (
            identity_https_servers,
            "@identity_rate_limited",
            "return 429 '{\"error\":\"rate_limited\",\"error_description\":\"Too many requests; retry after 1 second.\"}';",
            True,
            False,
        ),
    )
    if rendered.count('\"trace_id\":\"$request_id\"') != 3:
        safe_error_invalid = True
    for servers, label, return_directive, requires_retry_after, requires_trace in handlers:
        entries = _location_entries(servers[0]) if len(servers) == 1 else []
        bodies = [body for entry_label, body in entries if entry_label == label]
        if len(bodies) != 1:
            safe_error_invalid = True
            continue
        body = bodies[0]
        required = ("default_type application/json;", return_directive, *safe_headers)
        if any(body.count(directive) != 1 for directive in required):
            safe_error_invalid = True
        retry_after = 'add_header Retry-After "1" always;'
        if body.count(retry_after) != (1 if requires_retry_after else 0):
            safe_error_invalid = True
        trace_header = 'add_header X-Trace-Id "$request_id" always;'
        if body.count(trace_header) != (1 if requires_trace else 0):
            safe_error_invalid = True
        return_lines = [
            line.strip() for line in body.splitlines() if line.strip().startswith("return ")
        ]
        return_variables = (
            set(re.findall(r"\$[A-Za-z0-9_]+", return_lines[0]))
            if len(return_lines) == 1
            else set()
        )
        expected_variables = {"$request_id"} if requires_trace else set()
        if len(return_lines) != 1 or return_variables != expected_variables:
            safe_error_invalid = True
        if re.search(r"\b(?:proxy_pass|rewrite|try_files)\b", body):
            safe_error_invalid = True
    if (
        "proxy_intercept_errors on;" in rendered
        or "recursive_error_pages on;" in rendered
    ):
        safe_error_invalid = True
    if safe_error_invalid:
        errors.append(
            "Edge-generated 413/429 responses must use the fixed safe edge error contract"
        )

    expected_upstreams = {"active_api", "active_web", "keycloak"}
    upstream_contract = {
        "active_api": (None, "$active_api_tls_name"),
        "active_web": (None, "$active_web_tls_name"),
        "keycloak": (8443, "keycloak"),
    }
    found_upstreams: set[str] = set()
    for block in _location_blocks(template):
        proxy_passes = re.findall(r"\bproxy_pass\s+([^;]+);", block)
        for proxy_pass in proxy_passes:
            parsed = urlsplit(proxy_pass)
            upstream = parsed.hostname or ""
            expected_port, tls_name = upstream_contract.get(upstream, (-1, ""))
            if parsed.scheme != "https" or parsed.port != expected_port:
                errors.append(f"Nginx upstream must use HTTPS on 8443: {proxy_pass}")
                continue
            found_upstreams.add(upstream)
            required_tls = (
                "proxy_ssl_trusted_certificate /run/secrets/internal-tls/ca.crt;",
                "proxy_ssl_server_name on;",
                f"proxy_ssl_name {tls_name};",
                "proxy_ssl_verify on;",
                "proxy_ssl_verify_depth 2;",
                "proxy_ssl_session_reuse on;",
                "proxy_ssl_protocols TLSv1.2 TLSv1.3;",
            )
            for directive in required_tls:
                if directive not in block:
                    errors.append(f"{upstream} upstream TLS is missing: {directive}")
    if found_upstreams != expected_upstreams:
        errors.append(
            "Nginx must proxy only to the canonical HTTPS API/Web pair and keycloak"
        )
    for name, services in (
        ("blue.conf", ("server api:8443;", "server web:8443;", "default api;", "default web;")),
        ("green.conf", ("server api-green:8443;", "server web-green:8443;", "default api-green;", "default web-green;")),
    ):
        path = ROOT / "infra" / "nginx" / "slots" / name
        try:
            route = load_stable_text(path)
        except OSError:
            errors.append(f"canonical edge route is missing: {name}")
            continue
        if any(item not in route for item in services) or "${" in route:
            errors.append(f"canonical edge route is invalid: {name}")
    if "proxy_ssl_verify off;" in template:
        errors.append("Nginx upstream certificate verification must never be disabled")

    for required in (
        "listen 8443 ssl;",
        "listen [::]:8443 ssl;",
        "server_name web;",
        "ssl_certificate /run/secrets/internal-tls/tls.crt;",
        "ssl_certificate_key /run/secrets/internal-tls/tls.key;",
        "ssl_protocols TLSv1.2 TLSv1.3;",
        "location = /healthz {",
    ):
        if required not in web_config:
            errors.append(f"web Nginx TLS config is missing: {required}")
    if re.search(r"\blisten\s+(?:\[::\]:)?8080\b", web_config):
        errors.append("web Nginx must not expose a plaintext listener")
    for required in (
        "COPY infra/nginx/validate-web-tls.sh /docker-entrypoint.d/10-validate-web-tls.sh",
        "USER 101:101",
        "EXPOSE 8443",
    ):
        if required not in web_dockerfile:
            errors.append(f"web Dockerfile is missing: {required}")
    for required in (
        "certificate=/run/secrets/internal-tls/tls.crt",
        "private_key=/run/secrets/internal-tls/tls.key",
        'if [ -w "$private_key" ]',
    ):
        if required not in web_validator:
            errors.append(f"web TLS validator is missing: {required}")

    for variable in ("PLATFORM_TLS_CERT_FILE=", "PLATFORM_TLS_KEY_FILE="):
        if variable not in env_example:
            errors.append(f".env.example is missing {variable[:-1]}")
    combined = "\n".join(
        (dockerfile, renderer, template, env_example, web_dockerfile, web_config, web_validator)
    )
    if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", combined):
        errors.append("edge assets must never contain a private key")
    return errors


def main() -> int:
    try:
        errors = validate_edge_assets(*load_assets())
    except (OSError, ValueError, yaml.YAMLError):
        print("Edge asset load failed", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("edge-assets-ok non-root-https-domain-rendering-and-tls-mounts-validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
