# Windows Application-Level Split Routing

Utilitário experimental de roteamento seletivo para aplicações Chromium/Electron. Uma pequena allowlist de acesso/sessão pode usar um relay SOCKS5, enquanto todo o restante continua `DIRECT` no Windows.

## Arquitetura

```text
Aplicação alvo
  ├─ pequena allowlist -> PAC -> SOCKS local -> relay SOCKS5
  └─ qualquer outro destino -> DIRECT -> Windows -> Internet
```

No modo padrão não existe TUN, alteração da rota default ou captura de UDP. A v13 adiciona um modo experimental opcional e estreito para RTC/UDP de screen-share.

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
runtime/working_udp_proxies.json
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


## Inspector opcional de mídia em tempo real

A versão inclui um observador **somente leitura** para aplicações que expõem metadados RTC na saída do processo. Ele não captura, descriptografa nem altera pacotes. Quando o programa inicia a aplicação com `--rtc-inspect`, a saída é espelhada para o terminal e analisada em tempo real; uma cópia também é salva em `runtime/target_stdout.log`. O objetivo é registrar:

```text
sessões RTC separadas por contexto (`default`, `stream`, etc.)
endpoint remoto UDP de cada sessão
endpoint local de cada sessão
SSRC de áudio
SSRC/RTX de vídeo
transições de vídeo inactive -> active
detecção de captura de desktop em uma sessão `stream` separada
```

Integrado à execução normal:

```powershell
ApplicationSplitRouting.exe --rtc-inspect
```

Ou somente o inspector, com a aplicação já aberta:

```powershell
ApplicationSplitRouting.exe --rtc-inspect-only
```

O modo `--rtc-inspect-only` usa o arquivo de log disponível como fallback. Para clientes que escrevem `Connection(default)`/`Connection(stream)` apenas no stdout, o modo integrado `--rtc-inspect` é mais confiável.

Os resultados ficam em:

```text
runtime/target_stdout.log
runtime/rtc_session.json
runtime/rtc_split_candidate.json
```

### Teste para identificar uma transmissão de tela

1. entre em uma sessão RTC com câmera desligada;
2. aguarde o inspector registrar a sessão `default`;
3. inicie o compartilhamento de tela;
4. verifique se surge uma sessão `stream` com endpoint UDP local/remoto próprio;
5. confira `runtime/rtc_split_candidate.json`.

Quando a aplicação cria `Connection(stream)` em um UDP 5-tuple diferente da sessão `default`, o candidato passa a registrar esse endpoint inteiro. Esse é um limite de roteamento muito melhor que separar pacotes por SSRC.

## v13 experimental: screen-share por SOCKS5-UDP

A opção abaixo habilita um segundo caminho **somente para teste**:

```powershell
ApplicationSplitRouting.exe --tunnel-screen
```

Esse modo exige Terminal/PowerShell executado **como Administrador**, pois cria uma interface TUN estreita. A inicialização web continua usando PAC/TCP como antes. O fluxo experimental é:

```text
startup/control -> PAC -> SOCKS5 TCP
voz/default     -> TUN estreito -> DIRECT
screen-share    -> TUN estreito -> SOCKS5 UDP ASSOCIATE
outros destinos -> DIRECT
```

O programa primeiro procura um relay que passe por `UDP ASSOCIATE` e por uma pequena consulta DNS via UDP. O resultado fica em:

```text
runtime/working_udp_proxies.json
```

Depois, entre primeiro na sessão de voz e **aguarde** a mensagem:

```text
RTC SCREEN TUNNEL ARMADO
```

Somente então inicie o compartilhamento. O programa usa a porta UDP local já conhecida da sessão `default` como exceção `DIRECT`; outros UDPs da aplicação alvo dentro do CIDR RTC estreito são enviados ao relay SOCKS5-UDP. O estado fica em:

```text
runtime/screen_tunnel_status.json
runtime/sing-box-rtc-tun.json
runtime/sing-box-rtc-tun.log
```

Por padrão o CIDR é derivado como `/16` do endpoint RTC de voz. É possível sobrescrever para diagnóstico:

```powershell
ApplicationSplitRouting.exe --tunnel-screen --screen-route-cidr "104.29.0.0/16"
```

Também é possível testar um relay conhecido:

```powershell
ApplicationSplitRouting.exe --tunnel-screen --udp-proxy "IP:PORT"
```

### Limitações do experimento

- SOCKS5 público com UDP funcional é muito mais raro que SOCKS5 com `CONNECT` TCP.
- Um relay pode suportar `UDP ASSOCIATE` e ainda ter banda insuficiente para vídeo em alta resolução.
- O modo estreito intercepta apenas o CIDR RTC calculado; se uma sessão `stream` for criada fora dele, o terminal informa que provavelmente ficou `DIRECT`.
- A rota da voz continua com egress direto, mas os pacotes para o CIDR RTC passam pelo TUN local antes da decisão; portanto pode existir pequena sobrecarga local.
- Esse modo é propositalmente separado do comportamento padrão para que falhas em proxies UDP não prejudiquem o split TCP já estável.

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

na mesma pasta do `.exe`. O aplicativo não usa fallback em `%LOCALAPPDATA%`: se a pasta não permitir gravação, ele informa o erro para manter o pacote totalmente portátil.


## Encerramento do relay com o aplicativo

No Windows, o processo `sing-box` é colocado em um **Job Object** com `KILL_ON_JOB_CLOSE`. Portanto ele é encerrado não apenas no fluxo normal de saída, mas também quando a janela/terminal que executa `ApplicationSplitRouting.exe` é fechada e o processo principal termina abruptamente. Isso evita deixar `sing-box.exe` órfão no Gerenciador de Tarefas.

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

## Triagem rápida de inventários grandes

Listas públicas muito grandes podem conter mais de 100 mil entradas mortas. A triagem não agenda mais todo o inventário de uma vez. Ela embaralha os IPs e trabalha em lotes de até 4.000, interrompendo assim que o pool necessário é encontrado.

As fontes menores são consultadas primeiro. Feeds com dezenas de milhares de entradas são fallback e só são baixados se as fontes prioritárias não produzirem nem o mínimo de relays válidos.

Exemplo de progresso:

```text
Inventário lote 1: testando 1-4000 de 115419 IPs...
Fase 1: ...
Fase 2: ...
Fase 3: ...
Inventário acumulado: 2/2 relay(s) válido(s).
```

Assim um inventário grande continua útil como cache sem obrigar cada inicialização a esperar pela lista inteira.

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

## Proxy inventory resilience

Compiled builds are fully portable: `runtime` is always created beside the
executable, including when the EXE is inside a repository `dist` directory.
Copying the EXE together with its `runtime` folder preserves the harvested
inventory and last known-good relays.

The checker probes SOCKS5 CONNECT using the destination hostname first and then
falls back to IPv4. This mirrors the application-level SOCKS path more closely
and avoids rejecting relays that only work correctly with domain-name CONNECT.

## Runtime portátil

Em builds compilados, todos os dados persistentes ficam sempre ao lado do executável:

```text
ApplicationSplitRouting.exe
runtime/
  working_proxies.json
  working_udp_proxies.json
  scanned_proxies.txt
  scanned_proxies.meta.json
  rtc_session.json
  rtc_split_candidate.json
```

Isso também vale quando o executável está em `dist/`. Para distribuir o programa, basta copiar o `.exe`; a pasta `runtime/` é criada automaticamente na primeira execução. Para levar junto o inventário/cache já existente, copie também a pasta `runtime/`.

### v13.1: correção da separação de voz

A v13 original tentava manter a voz DIRECT usando a porta UDP local observada no log. Em um TUN do sing-box, porém, o pacote já pode aparecer com endereço/porta sintéticos da interface virtual antes das regras de rota. Isso fazia a exceção por `source_port` falhar e permitia que a voz também entrasse no outbound SOCKS5-UDP.

Na v13.1 a proteção da voz é feita antes do TUN: o IP remoto exato da sessão `Connection(default)` é adicionado a `route_exclude_address` como `/32`. Assim o tráfego de voz não chega à interface TUN. O restante do bloco RTC continua elegível para o proxy UDP. Se `Connection(stream)` cair no mesmo IP remoto da voz, a versão falha de forma segura e deixa esse stream DIRECT, avisando que esse caso exige um backend de 5-tuple/WinDivert.

A seleção de proxy UDP também rejeita relays que passam `UDP ASSOCIATE` mas são claramente lentos demais no probe. O terminal agora mostra `setup`, `UDP RTT` e `total` separadamente.
