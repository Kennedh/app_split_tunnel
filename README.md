# Windows Application-Level Split Routing

Utilitário experimental de roteamento seletivo para aplicações Chromium/Electron. Uma pequena allowlist de acesso/sessão pode usar um relay SOCKS5, enquanto todo o restante continua `DIRECT` no Windows.

## Arquitetura

```text
Aplicação alvo
  ├─ pequena allowlist -> PAC -> SOCKS local -> relay SOCKS5
  └─ qualquer outro destino -> DIRECT -> Windows -> Internet
```

Não existe TUN, alteração da rota default ou captura de UDP.

## Cache em três níveis

A inicialização evita trabalho desnecessário:

```text
1. working_proxies.json
   ↓ revalida apenas os últimos relays aprovados
   ↓ se houver relay válido, inicia imediatamente

2. scanned_proxies.txt
   ↓ usa os IP:PORT coletados anteriormente
   ↓ não baixa listas públicas

3. fontes públicas
   ↓ somente se o inventário local não produzir relay válido
   ↓ salva um novo scanned_proxies.txt
```

Arquivos persistentes:

```text
runtime/working_proxies.json
runtime/scanned_proxies.txt
runtime/scanned_proxies.meta.json
```

`scanned_proxies.txt` contém **somente `IP:PORT`, um por linha**. Assim é fácil visualizar, copiar ou substituir o inventário.

### Forçar verificações

Retestar o inventário local ignorando os relays atualmente aprovados:

```powershell
ApplicationSplitRouting.exe --force-scan
```

Baixar novamente todas as listas públicas:

```powershell
ApplicationSplitRouting.exe --force-refresh
```

No uso normal não é necessário passar nenhuma dessas opções.

## Janela inicial de relay

Por padrão, a allowlist pode usar o relay somente durante os primeiros 25 segundos. Depois disso, novas requisições passam a ser `DIRECT`.

```powershell
ApplicationSplitRouting.exe --proxy-window 15
```

Para manter a allowlist no relay durante toda a execução:

```powershell
ApplicationSplitRouting.exe --proxy-window 0
```

## Gerar o EXE

Requisitos para **compilar**: Windows 10/11 64-bit e Python 3.11+.

Dê duplo clique em:

```text
build_exe.bat
```

ou execute:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\build_exe.ps1
```

O script:

1. instala/verifica `sing-box.exe`;
2. instala as dependências Python e PyInstaller;
3. embute `sing-box.exe` no pacote;
4. gera um executável single-file em:

```text
dist\ApplicationSplitRouting.exe
```

O executável não precisa de Python instalado na máquina onde será usado.

### Dados ao lado do EXE

Na versão compilada, o programa tenta criar:

```text
runtime\
```

na mesma pasta do `.exe`. Se a pasta não for gravável, usa automaticamente `%LOCALAPPDATA%\ApplicationSplitRouting\runtime`.

## Execução pelo código-fonte

```powershell
python -m pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File .\tools\install_sing_box.ps1
python main.py
```

Executável alvo manual:

```powershell
ApplicationSplitRouting.exe --app "C:\Caminho\Aplicacao\app.exe"
```

## Checker

Antes de considerar um relay utilizável, o checker valida:

1. handshake SOCKS5;
2. `CONNECT` nos destinos necessários;
3. TLS/HTTPS fim a fim com cadeia e hostname confiáveis.

Relays públicos podem expirar a qualquer momento. Por isso o cache de relays ativos é sempre revalidado antes de ser reutilizado.

## Segurança e comportamento

O projeto não instala certificados, não desativa validação TLS e não realiza MITM. Todo hostname não explicitamente permitido pela PAC é `DIRECT`.

> Feche todas as instâncias da aplicação alvo antes de iniciar. Aplicações Chromium/Electron normalmente leem as opções PAC no processo principal.

## Build opcional pelo GitHub Actions

O repositório também inclui `.github/workflows/build-windows.yml`. Ao executar manualmente o workflow **Build Windows EXE** em um runner Windows, o artefato `ApplicationSplitRouting-windows-x64` é gerado automaticamente.
