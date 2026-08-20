$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$proxyUrl = "https://email111.6ltd.ltd/api/v1/stream"
$testPayload = @{
    email = "diagnostic@example.invalid"
    password = "invalid-test-only"
    clientId = ""
    refreshToken = ""
    search = ""
    days = 30
} | ConvertTo-Json -Compress

$headerFile = [System.IO.Path]::GetTempFileName()
$bodyFile = [System.IO.Path]::GetTempFileName()
try {
    & curl.exe `
        --silent `
        --show-error `
        --max-time 20 `
        --dump-header $headerFile `
        --output $bodyFile `
        --request POST `
        $proxyUrl `
        --header "Accept: application/json, text/plain, */*" `
        --header "Content-Type: application/json" `
        --header "Origin: https://mail.054120.xyz" `
        --header "Referer: https://mail.054120.xyz/" `
        --data-raw $testPayload
    if ($LASTEXITCODE -ne 0) {
        throw "HTTPS request failed. Check DNS, the certificate, and Nginx."
    }

    $headers = Get-Content -LiteralPath $headerFile -Raw
    $body = Get-Content -LiteralPath $bodyFile -Raw
    $statusMatch = [regex]::Matches($headers, "HTTP/\S+\s+(\d{3})")
    if ($statusMatch.Count -eq 0) {
        throw "The proxy returned no HTTP status."
    }
    $status = [int]$statusMatch[$statusMatch.Count - 1].Groups[1].Value

    if ($headers -match "(?im)^X-Vercel-Mitigated:\s*deny\s*$") {
        throw "Vercel denied the reverse proxy. Allow the proxy egress IP in the upstream Vercel project before using this domain."
    }
    if ($status -in 301, 302, 307, 308) {
        throw "The proxy still redirects (HTTP $status). Check Host, SNI, and proxy_redirect."
    }
    if ($status -ne 200) {
        throw "The proxy returned HTTP $status. Response: $body"
    }

    try {
        $null = $body | ConvertFrom-Json
    }
    catch {
        throw "The endpoint returned HTTP 200 but the body is not JSON."
    }

    Write-Host "Proxy verification passed: HTTPS is valid, there is no redirect, and the API returned JSON."
}
finally {
    Remove-Item -LiteralPath $headerFile, $bodyFile -Force -ErrorAction SilentlyContinue
}
