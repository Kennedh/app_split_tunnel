$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "[1/5] Verificando Python..." -ForegroundColor Cyan
python --version

if (-not (Test-Path ".\bin\sing-box.exe")) {
    Write-Host "[2/5] sing-box.exe ausente; instalando binario oficial..." -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File ".\tools\install_sing_box.ps1"
} else {
    Write-Host "[2/5] sing-box.exe encontrado." -ForegroundColor Green
}

if (-not (Test-Path ".\bin\wgcf.exe")) {
    Write-Host "[3/5] wgcf.exe ausente; instalando gerador de perfil WARP..." -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File ".\tools\install_wgcf.ps1"
} else {
    Write-Host "[3/5] wgcf.exe encontrado." -ForegroundColor Green
}

Write-Host "[4/5] Instalando dependencias de build..." -ForegroundColor Cyan
python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt
python -m pip install "pyinstaller>=6.10,<7"

Write-Host "[5/5] Gerando executavel single-file..." -ForegroundColor Cyan
python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --console `
    --name "ApplicationSplitRouting" `
    --add-binary ".\bin\sing-box.exe;bin" `
    --add-binary ".\bin\wgcf.exe;bin" `
    --collect-all rich `
    .\main.py

if (-not (Test-Path ".\dist\ApplicationSplitRouting.exe")) {
    throw "Build terminou sem gerar dist\ApplicationSplitRouting.exe"
}

Write-Host "" 
Write-Host "Build concluido:" -ForegroundColor Green
Write-Host "  $ProjectRoot\dist\ApplicationSplitRouting.exe" -ForegroundColor White
Write-Host "" 
Write-Host "O executavel cria uma pasta runtime ao lado dele quando houver permissao." -ForegroundColor DarkGray
