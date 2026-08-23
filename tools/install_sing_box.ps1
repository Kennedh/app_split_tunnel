$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root 'bin'
New-Item -ItemType Directory -Force -Path $bin | Out-Null
$url = 'https://github.com/SagerNet/sing-box/releases/download/v1.13.15/sing-box-1.13.15-windows-amd64.zip'
$zip = Join-Path $env:TEMP 'sing-box.zip'
$tmp = Join-Path $env:TEMP 'sing-box-extract'
Invoke-WebRequest -Uri $url -OutFile $zip
$expected = '599b296f6e57511d36d2a6f3011aed1a86fa98418578bbb06bd6dc241b5d8877'
$actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) { throw "SHA256 inválido: $actual" }
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive -Path $zip -DestinationPath $tmp -Force
$exe = Get-ChildItem -Path $tmp -Filter 'sing-box.exe' -Recurse | Select-Object -First 1
if (-not $exe) { throw 'sing-box.exe não foi encontrado no ZIP.' }
Copy-Item $exe.FullName (Join-Path $bin 'sing-box.exe') -Force
Write-Host "Instalado em $bin\sing-box.exe"
