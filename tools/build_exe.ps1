$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

Write-Host "[1/4] Verificando Python..." -ForegroundColor Cyan
python --version

if (-not (Test-Path ".\bin\sing-box.exe")) {
    Write-Host "[2/4] sing-box.exe ausente; instalando binario oficial..." -ForegroundColor Cyan
    & powershell -ExecutionPolicy Bypass -File ".\tools\install_sing_box.ps1"
} else {
    Write-Host "[2/4] sing-box.exe encontrado." -ForegroundColor Green
}

Write-Host "[3/4] Instalando dependencias de build..." -ForegroundColor Cyan
python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt
python -m pip install "pyinstaller>=6.10,<7"

Write-Host "[4/4] Gerando executavel single-file..." -ForegroundColor Cyan
python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --console `
    --name "ApplicationSplitRouting" `
    --add-binary ".\bin\sing-box.exe;bin" `
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
