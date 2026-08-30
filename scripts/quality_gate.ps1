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

    $phase6Commit = (git rev-parse HEAD).Trim()
    if ([string]::IsNullOrWhiteSpace($env:PHASE6_EVIDENCE_OUTPUT)) {
        $phase6Evidence = Join-Path `
            ([System.IO.Path]::GetTempPath()) `
            ("phase6-ci-rehearsal-{0}-{1}.json" -f $phase6Commit, [guid]::NewGuid().ToString("N"))
    }
    else {
        $phase6Evidence = $env:PHASE6_EVIDENCE_OUTPUT
    }
    python scripts/phase6_rehearsal.py run --output $phase6Evidence --commit $phase6Commit
    if ($LASTEXITCODE -ne 0) { throw "Phase 6 CI rehearsal failed." }
    python scripts/phase6_rehearsal.py verify --input $phase6Evidence --expected-commit $phase6Commit
    if ($LASTEXITCODE -ne 0) { throw "Phase 6 CI rehearsal evidence verification failed." }

    python scripts/verify_compose_env.py
    if ($LASTEXITCODE -ne 0) { throw "Compose env verification failed." }

    python scripts/verify_runtime_secrets.py
    if ($LASTEXITCODE -ne 0) { throw "Runtime secret-file verification failed." }

    python scripts/verify_service_boundaries.py
    if ($LASTEXITCODE -ne 0) { throw "Service boundary verification failed." }

    python scripts/verify_kubernetes_portability.py
    if ($LASTEXITCODE -ne 0) { throw "Kubernetes portability verification failed." }

    python scripts/verify_http_error_boundary.py
    if ($LASTEXITCODE -ne 0) { throw "HTTP error boundary verification failed." }

    python scripts/verify_vault_isolation.py
    if ($LASTEXITCODE -ne 0) { throw "Vault isolation verification failed." }

    python scripts/verify_vault_broker_contract.py
    if ($LASTEXITCODE -ne 0) { throw "Vault broker contract verification failed." }

    python scripts/verify_desktop_package.py
    if ($LASTEXITCODE -ne 0) { throw "Desktop package boundary verification failed." }

    python scripts/verify_migration_compatibility.py
    if ($LASTEXITCODE -ne 0) { throw "Migration rolling-compatibility verification failed." }

    python scripts/verify_ci_workflow.py
    if ($LASTEXITCODE -ne 0) { throw "CI workflow verification failed." }

    python scripts/verify_release_workflow.py
    if ($LASTEXITCODE -ne 0) { throw "Release workflow verification failed." }

    python scripts/verify_container_hardening.py
    if ($LASTEXITCODE -ne 0) { throw "Container hardening verification failed." }

    python scripts/verify_container_logging.py
    if ($LASTEXITCODE -ne 0) { throw "Container logging verification failed." }

    python scripts/verify_backup_tools.py
    if ($LASTEXITCODE -ne 0) { throw "Backup tooling verification failed." }

    python scripts/verify_rollback_assets.py
    if ($LASTEXITCODE -ne 0) { throw "Rollback asset verification failed." }

    python scripts/verify_deploy_release.py
    if ($LASTEXITCODE -ne 0) { throw "Immutable forward-deployment verification failed." }

    python scripts/verify_rolling_release.py
    if ($LASTEXITCODE -ne 0) { throw "Web/API rolling-release verification failed." }

    python scripts/verify_release_execution_causality.py
    if ($LASTEXITCODE -ne 0) { throw "Release execution causality verification failed." }

    python scripts/target_intake_generation_context_trust.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Target-intake generation-context handoff contract verification failed." }

    python scripts/verify_target_intake_generation_context_trust.py
    if ($LASTEXITCODE -ne 0) { throw "Target-intake generation-context handoff static verification failed." }

    python scripts/target_intake_runtime_attestation_trust.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Target-intake runtime-attestation handoff contract verification failed." }

    python scripts/verify_target_intake_runtime_attestation_trust.py
    if ($LASTEXITCODE -ne 0) { throw "Target-intake runtime-attestation handoff static verification failed." }

    python scripts/target_intake_runtime_attestation_intake.py verify-repository-fixture
    if ($LASTEXITCODE -ne 0) { throw "Target-intake configured runtime-attestation fixture verification failed." }

    python scripts/verify_target_intake_runtime_attestation_intake.py
    if ($LASTEXITCODE -ne 0) { throw "Target-intake configured runtime-attestation intake static verification failed." }

    python scripts/target_intake_runtime_attestation_provider_fixture.py
    if ($LASTEXITCODE -ne 0) { throw "Target-intake provider raw-evidence fixture verification failed." }

    python scripts/verify_target_intake_runtime_attestation_provider_adapter.py
    if ($LASTEXITCODE -ne 0) { throw "Target-intake provider raw-evidence static verification failed." }

    python scripts/target_intake_runtime_attestation_external_evidence.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Target-intake external runtime-attestation evidence policy verification failed." }

    python scripts/verify_target_intake_runtime_attestation_external_evidence.py
    if ($LASTEXITCODE -ne 0) { throw "Target-intake external runtime-attestation evidence static verification failed." }

    python scripts/target_intake_runtime_attestation_provider_selection.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Target-intake runtime-attestation provider selection verification failed." }

    python scripts/verify_target_intake_runtime_attestation_provider_selection.py
    if ($LASTEXITCODE -ne 0) { throw "Target-intake runtime-attestation provider selection static verification failed." }

    python scripts/verify_target_intake_runtime_attestation_release_handoff.py
    if ($LASTEXITCODE -ne 0) { throw "Target-intake runtime-attestation release handoff static verification failed." }

    python scripts/verify_target_intake_snapshot_launcher.py
    if ($LASTEXITCODE -ne 0) { throw "Target-intake clean source snapshot launch verification failed." }

    python scripts/verify_training_assets.py
    if ($LASTEXITCODE -ne 0) { throw "Role-training asset verification failed." }

    python scripts/verify_phase6_evidence_outputs.py
    if ($LASTEXITCODE -ne 0) { throw "Phase 6 evidence output verification failed." }

    python scripts/verify_nginx_headers.py
    if ($LASTEXITCODE -ne 0) { throw "Nginx header verification failed." }

    python scripts/verify_nginx_logging.py
    if ($LASTEXITCODE -ne 0) { throw "Nginx logging verification failed." }

    python scripts/verify_edge_assets.py
    if ($LASTEXITCODE -ne 0) { throw "HTTPS edge verification failed." }

    python scripts/verify_internal_tls.py
    if ($LASTEXITCODE -ne 0) { throw "Internal TLS verification failed." }

    python scripts/verify_tls_rotation_executor.py
    if ($LASTEXITCODE -ne 0) { throw "TLS rotation executor verification failed." }

    python scripts/private_secret_crash_evidence.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Private secret crash evidence repository contract verification failed." }

    python scripts/verify_private_secret_crash_evidence.py
    if ($LASTEXITCODE -ne 0) { throw "Private secret crash evidence static verification failed." }

    python scripts/private_secret_github_attestation.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Private secret GitHub attestation repository contract verification failed." }

    python scripts/private_secret_target_provenance.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Private secret target provenance repository contract verification failed." }

    python scripts/verify_private_secret_provenance.py
    if ($LASTEXITCODE -ne 0) { throw "Private secret provenance static verification failed." }

    python scripts/private_secret_github_rest_collection.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Private secret GitHub REST collection repository contract verification failed." }

    python scripts/private_secret_worm_collection.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Private secret WORM collection repository contract verification failed." }

    python scripts/verify_private_secret_collection.py
    if ($LASTEXITCODE -ne 0) { throw "Private secret external collection static verification failed." }

    python scripts/private_secret_collection_review_decision.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Private secret collection review repository contract verification failed." }

    python scripts/verify_private_secret_collection_review.py
    if ($LASTEXITCODE -ne 0) { throw "Private secret collection review static verification failed." }

    python scripts/private_secret_collection_archive_receipt.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Private secret collection archive repository contract verification failed." }

    python scripts/verify_private_secret_collection_archive.py
    if ($LASTEXITCODE -ne 0) { throw "Private secret collection archive static verification failed." }

    python scripts/verify_private_secret_collector_deployment.py
    if ($LASTEXITCODE -ne 0) { throw "Private secret collector deployment static verification failed." }

    python scripts/verify_tls_rotation_handoff.py
    if ($LASTEXITCODE -ne 0) { throw "TLS rotation handoff verification failed." }

    python scripts/verify_tls_rotation_artifacts.py
    if ($LASTEXITCODE -ne 0) { throw "TLS rotation artifact verification failed." }

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

    python scripts/verify_phase_acceptance_matrix.py
    if ($LASTEXITCODE -ne 0) { throw "Phase acceptance matrix verification failed." }

    python scripts/verify_plan_completion.py
    if ($LASTEXITCODE -ne 0) { throw "Plan completion audit failed." }

    python scripts/verify_plan_requirements.py
    if ($LASTEXITCODE -ne 0) { throw "Plan requirement inventory verification failed." }

    python scripts/target_intake_preflight.py verify-requirements
    if ($LASTEXITCODE -ne 0) { throw "Target intake requirement verification failed." }

    python scripts/target_phase_artifacts.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Target phase artifact verification failed." }

    python scripts/provider_contract_conformance.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Provider contract verification failed." }

    python scripts/decision_envelope_validation.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Decision envelope verification failed." }

    python scripts/phase0_boundary_approval.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Phase 0 boundary approval verification failed." }

    python scripts/target_platform_inventory.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Target platform inventory verification failed." }

    python scripts/sub2_execution_evidence.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Sub2 execution evidence index verification failed." }

    python scripts/vault_egress_evidence.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Vault/egress evidence index verification failed." }

    python scripts/phase6_pilot_inputs.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Phase 6 pilot input inventory verification failed." }

    python scripts/phase6_pilot_evidence.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Phase 6 pilot evidence index verification failed." }

    python scripts/phase6_operations_evidence.py verify-repository
    if ($LASTEXITCODE -ne 0) { throw "Phase 6 operations evidence index verification failed." }

    python scripts/verify_chapter13_defaults.py
    if ($LASTEXITCODE -ne 0) { throw "Chapter 13 default verification failed." }

    python scripts/verify_chapter14_mvi.py
    if ($LASTEXITCODE -ne 0) { throw "Chapter 14 MVI contract verification failed." }

    python scripts/verify_security_workflow.py
    if ($LASTEXITCODE -ne 0) { throw "Security workflow verification failed." }

    python scripts/verify_container_supply_chain.py
    if ($LASTEXITCODE -ne 0) { throw "Container supply-chain verification failed." }

    python scripts/secret_scan.py
    if ($LASTEXITCODE -ne 0) { throw "Secret scan failed." }

    alembic -x db_url="postgresql+psycopg://placeholder:placeholder@localhost:5432/email_platform" upgrade head --sql | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Alembic SQL generation failed." }

    Push-Location frontend
    try {
        npm run test:unit
        if ($LASTEXITCODE -ne 0) { throw "Frontend unit tests failed." }

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
