$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    python -m compileall -q platform infra platform_client.py platform_login_dialog.py platform_desktop.py app_version.py update_client.py app.py
    if ($LASTEXITCODE -ne 0) { throw "Python compile failed." }

    python -m unittest discover -s platform/tests -p "test_*.py" -v
    if ($LASTEXITCODE -ne 0) { throw "Platform tests failed." }

    python -m unittest discover -s tests -p "test_*.py" -v
    if ($LASTEXITCODE -ne 0) { throw "Desktop/client tests failed." }

    python scripts/verify_compose_env.py
    if ($LASTEXITCODE -ne 0) { throw "Compose env verification failed." }

    python scripts/verify_service_boundaries.py
    if ($LASTEXITCODE -ne 0) { throw "Service boundary verification failed." }

    python scripts/verify_vault_isolation.py
    if ($LASTEXITCODE -ne 0) { throw "Vault isolation verification failed." }

    python scripts/verify_desktop_package.py
    if ($LASTEXITCODE -ne 0) { throw "Desktop package boundary verification failed." }

    python scripts/verify_ci_workflow.py
    if ($LASTEXITCODE -ne 0) { throw "CI workflow verification failed." }

    python scripts/verify_release_workflow.py
    if ($LASTEXITCODE -ne 0) { throw "Release workflow verification failed." }

    python scripts/verify_container_hardening.py
    if ($LASTEXITCODE -ne 0) { throw "Container hardening verification failed." }

    python scripts/verify_backup_tools.py
    if ($LASTEXITCODE -ne 0) { throw "Backup tooling verification failed." }

    python scripts/verify_nginx_headers.py
    if ($LASTEXITCODE -ne 0) { throw "Nginx header verification failed." }

    python scripts/verify_keycloak_realm.py
    if ($LASTEXITCODE -ne 0) { throw "Keycloak realm verification failed." }

    python scripts/verify_monitoring_assets.py
    if ($LASTEXITCODE -ne 0) { throw "Monitoring asset verification failed." }

    python scripts/verify_release_manifest.py
    if ($LASTEXITCODE -ne 0) { throw "Release manifest verification failed." }

    python scripts/verify_runbooks.py
    if ($LASTEXITCODE -ne 0) { throw "Runbook verification failed." }

    python scripts/verify_signoff_template.py
    if ($LASTEXITCODE -ne 0) { throw "Signoff template verification failed." }

    python scripts/verify_security_workflow.py
    if ($LASTEXITCODE -ne 0) { throw "Security workflow verification failed." }

    python scripts/secret_scan.py
    if ($LASTEXITCODE -ne 0) { throw "Secret scan failed." }

    alembic -x db_url="postgresql+psycopg://placeholder:placeholder@localhost:5432/email_platform" upgrade head --sql | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Alembic SQL generation failed." }

    Push-Location frontend
    try {
        npm run check:api
        if ($LASTEXITCODE -ne 0) { throw "Generated OpenAPI client is stale." }

        npm run build
        if ($LASTEXITCODE -ne 0) { throw "Frontend build failed." }
    }
    finally {
        Pop-Location
    }

    Write-Host "Quality gate passed."
}
finally {
    Pop-Location
}
