$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Push-Location $PSScriptRoot
try {
    # Keep this script ASCII-only so Windows PowerShell 5 does not depend on
    # the machine's legacy code page when reading a UTF-8 file without a BOM.
    $exeName = -join [char[]](0x90AE, 0x7BB1, 0x9A8C, 0x8BC1, 0x7801, 0x52A9, 0x624B)
    $buildName = $exeName
    $releaseDir = Join-Path $PSScriptRoot "release\windows"
    $workDir = Join-Path $PSScriptRoot "build\platform"
    New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
    New-Item -ItemType Directory -Force -Path $workDir | Out-Null
    $suffix = 0
    while ($true) {
        $targetPath = Join-Path $releaseDir "$buildName.exe"
        $targetInUse = @(Get-Process | Where-Object {
            try { $_.Path -eq $targetPath } catch { $false }
        }).Count -gt 0
        if (-not $targetInUse) {
            break
        }
        $suffix += 1
        $buildName = if ($suffix -eq 1) { "$exeName-new" } else { "$exeName-new$suffix" }
        Write-Warning "The existing app is running; trying $buildName.exe instead."
    }

    python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) {
        throw "Tests failed; EXE was not built."
    }

    # Validate the platform API contract as well as the desktop-only suite.
    # Install platform/requirements.txt before using this build script.
    python -m unittest discover -s platform/tests -v
    if ($LASTEXITCODE -ne 0) {
        throw "Platform tests failed; EXE was not built."
    }

    python -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --windowed `
        --distpath $releaseDir `
        --workpath $workDir `
        --specpath $workDir `
        --exclude-module legacy_app `
        --exclude-module admin_oauth `
        --exclude-module oauth_dialog `
        --name $buildName `
        app.py
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller build failed."
    }

    python scripts/verify_desktop_package.py --exe $targetPath
    if ($LASTEXITCODE -ne 0) {
        throw "Packaged EXE contains a forbidden legacy dependency."
    }

    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $targetPath).Hash.ToLowerInvariant()
    $hashPath = "$targetPath.sha256"
    Set-Content -LiteralPath $hashPath -Encoding UTF8 -Value "$hash  $buildName.exe"

    Write-Host "Build complete: $targetPath"
    Write-Host "SHA-256 manifest: $hashPath"
}
finally {
    Pop-Location
}
