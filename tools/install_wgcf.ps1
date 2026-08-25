$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$Bin = Join-Path $Root 'bin'
New-Item -ItemType Directory -Force -Path $Bin | Out-Null
$Out = Join-Path $Bin 'wgcf.exe'

Write-Host 'Consultando release atual do wgcf...' -ForegroundColor Cyan
$headers = @{ 'User-Agent' = 'ApplicationSplitRouting-build' }
$release = Invoke-RestMethod -Headers $headers -Uri 'https://api.github.com/repos/ViRb3/wgcf/releases/latest'
$asset = $release.assets |
    Where-Object { $_.name -match '^wgcf_[0-9.]+_windows_amd64(?:\.exe)?$' } |
    Select-Object -First 1
if (-not $asset) {
    throw 'Não encontrei o asset Windows amd64 do wgcf na release atual.'
}

$tmp = Join-Path $env:TEMP $asset.name
Invoke-WebRequest -Headers $headers -Uri $asset.browser_download_url -OutFile $tmp

$checksums = $release.assets | Where-Object { $_.name -eq 'checksums.txt' } | Select-Object -First 1
if ($checksums) {
    $checksumFile = Join-Path $env:TEMP 'wgcf-checksums.txt'
    Invoke-WebRequest -Headers $headers -Uri $checksums.browser_download_url -OutFile $checksumFile
    $line = Get-Content $checksumFile | Where-Object { $_ -match [regex]::Escape($asset.name) } | Select-Object -First 1
    if ($line) {
        $expected = ($line -split '\s+')[0].Trim().ToLower()
        $actual = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $expected) {
            throw "SHA256 do wgcf inválido. esperado=$expected obtido=$actual"
        }
    }
}

Copy-Item $tmp $Out -Force
Write-Host "wgcf instalado em $Out ($($release.tag_name))" -ForegroundColor Green
