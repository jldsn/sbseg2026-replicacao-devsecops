# Pilotos e validação dinâmica

## Candidatas e cobertura de ferramentas

| Alvo | Stack e referência técnica | Resultado |
|---|---|---|
| DVWA | PHP e MariaDB. Imagem Debian histórica, matriz com 13 casos em escopo. | Análise histórica reproduzida e três testes dirigidos em instância local descartável. |
| Juice Shop 19.0.0 | Node.js, Express e Angular. Catálogo de desafios e código da versão. | Selecionada. Semgrep, Checkov Dockerfile, Trivy Image, Trivy FS e ZAP executados. |
| WebGoat 2025.3 | Java e Spring Boot. Catálogo de lições e código tagueados. | Selecionada. Mesmas frentes do piloto, com regras SAST para Java. |
| NodeGoat | Node.js e MongoDB. Exercícios OWASP e Docker Compose. | Reserva. O código e os artefatos de contêiner existem. A coleta precisaria de configuração própria. |
| crAPI | Aplicação de treinamento de segurança de APIs, com serviços e Compose. | Reserva. A cobertura envolve vários serviços, inventário de rotas e autenticação. |

Fontes das candidatas. [DVWA](https://github.com/digininja/DVWA), [Juice Shop](https://github.com/juice-shop/juice-shop/releases/tag/v19.0.0), [WebGoat](https://github.com/WebGoat/WebGoat/releases/tag/v2025.3), [NodeGoat](https://github.com/OWASP/NodeGoat), [crAPI](https://owasp.org/projects/crapi).

| Scanner | Juice Shop | WebGoat |
|---|---|---|
| Semgrep 1.185.0 | 58 regras executadas, 457 arquivos, 16 achados | 95 regras executadas, 260 arquivos, 53 achados |
| Checkov 3.4.5 | 2 reprovações em 279 verificações no Dockerfile | 0 reprovações em 31 verificações no Dockerfile |
| Trivy Container 0.69.3 | 448 ocorrências, 104 em pacotes de sistema | 825 ocorrências, 674 em pacotes de sistema |
| Trivy FS 0.69.3 | Execução concluída sem artefato de dependências reconhecido | 41 ocorrências no POM. Há aviso de versões de dependências sem resolução offline |
| ZAP 2.17.0 passivo | 103 URLs, 432 instâncias de alerta, 6 tipos | 19 URLs, 33 instâncias de alerta, 8 tipos |
| ZAP 2.17.0 ativo | 1 indicador de SQL Injection no parâmetro q da busca. Confiança Low, com código da rota inspecionado | 0 alertas na rota de login e nas duas regras ativadas |

Os números usam unidades de saída distintas. As quantidades de Trivy são ocorrências por alvo/pacote, não agregações por CVE única. O Checkov analisou Dockerfile, diferente do Terraform e Kubernetes do histórico da DVWA. Os relatórios `pilotos_scanners.csv`, `pilotos_politicas.csv`, `pilotos_limiares.csv` e `pilotos_cobertura.csv` detalham os resultados. No Juice Shop, o lockfile de dependências da raiz está ausente no checkout; um backup versionado em `ftp/` fica fora do reconhecimento do scanner. A imagem analisada tem componentes identificados.

### Versões que controlam a reprodução

| Componente | Origem fixada |
|---|---|
| Artefato DVWA | `5b18244126350d1a6a4bf39e7a34701af9190563` |
| Imagem DVWA | `vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7` |
| Código Juice Shop | v19.0.0, `36870cbbdfe7864698e1adf644c7bf772f67ebb7` |
| Imagem Juice Shop amd64 | `bkimminich/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58` |
| Código WebGoat | v2025.3, `c3ed45a733377bc7313b93f57ff518254d81380f` |
| Imagem WebGoat amd64 | `webgoat/webgoat@sha256:6ebbadd5a440af0970049a8261e1d79914009fb9537b36b8081633913b9684ea` |
| Regras Semgrep | [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules), commit `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2` |
| Runtimes DAST | Node 24.22.1, Temurin 23.0.2 para WebGoat, OpenJDK 21 para ZAP |
| Banco Trivy | `evidence/trivy-db.json` e `evidence/trivy-java-db.json` com data de atualização e download |

## Reexecução dos scanners

Os relatórios já foram coletados. A reanálise numérica usa os arquivos existentes e roda com `python3 etapa-02/scripts/resumir_pilotos.py`. Recolete apenas se quiser verificar uma configuração específica. Fixe as versões, registre datas, parâmetros, logs e hashes. Use diretórios de saída distintos para guardar a execução de referência.

Exemplos abaixo assumem as variáveis `OUT` (pasta própria para a coleta), `REGRAS` (checkout do conjunto Semgrep), `JUICE` e `GOAT` (checkouts nas versões da tabela). CLI e dependências das ferramentas são instaladas separadamente.

~~~bash
(
  cd "$JUICE"
  semgrep scan --oss-only --metrics=off --disable-version-check --jobs 2 \
    --no-rewrite-rule-ids --json-output "$OUT/juice-shop-semgrep.json" \
    --config "$REGRAS/javascript/express/security" \
    --config "$REGRAS/javascript/browser/security" \
    --config "$REGRAS/typescript/angular/security" \
    routes lib models frontend/src
  BC_SKIP_MAPPING=true checkov --file Dockerfile --framework dockerfile \
    --skip-download --soft-fail --output json > "$OUT/juice-shop-checkov.json"
)
(
  cd "$GOAT"
  semgrep scan --oss-only --metrics=off --disable-version-check --jobs 2 \
    --no-rewrite-rule-ids --json-output "$OUT/webgoat-semgrep.json" \
    --config "$REGRAS/java/lang/security" \
    --config "$REGRAS/java/spring/security" \
    --config "$REGRAS/java/servlets/security" src/main/java
  BC_SKIP_MAPPING=true checkov --file Dockerfile --framework dockerfile \
    --skip-download --soft-fail --output json > "$OUT/webgoat-checkov.json"
)
trivy image --download-db-only
trivy image --download-java-db-only
trivy fs --skip-db-update --skip-java-db-update --offline-scan --scanners vuln \
  --format json --output "$OUT/juice-shop-fs.json" "$JUICE"
trivy fs --skip-db-update --skip-java-db-update --offline-scan --scanners vuln \
  --format json --output "$OUT/webgoat-fs.json" "$GOAT"
trivy image --image-src remote --platform linux/amd64 --skip-db-update \
  --skip-java-db-update --offline-scan --scanners vuln --format json \
  --output "$OUT/juice-shop-image.json" \
  bkimminich/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58
trivy image --image-src remote --platform linux/amd64 --skip-db-update \
  --skip-java-db-update --offline-scan --scanners vuln --format json \
  --output "$OUT/webgoat-image.json" \
  webgoat/webgoat@sha256:6ebbadd5a440af0970049a8261e1d79914009fb9537b36b8081633913b9684ea
~~~

Um banco de CVEs atualizado pode produzir novos números. Os hashes e os relatórios já coletados permitem recalcular os mesmos resultados do pacote.

Para o ZAP local, baixe os releases oficiais para Linux e extraia o Juice Shop Node 24 e o ZAP em pastas próprias. O WebGoat usa o JAR do release com Java 23. Execute cada piloto com namespace de rede somente loopback. Em WSL, a disponibilidade de namespaces depende da configuração de kernel.

~~~bash
unshare --user --map-root-user --mount --pid --fork --net --kill-child \
  python3 etapa-02/scripts/piloto_dast.py juice-shop \
  --release "$JUICE_RELEASE" --runtime "$(command -v node)" \
  --zap "$ZAP_DIR" --out "$OUT/zap" --work "$OUT/runtime-juice"

unshare --user --map-root-user --mount --pid --fork --net --kill-child \
  python3 etapa-02/scripts/piloto_dast.py webgoat \
  --release "$GOAT_JAR" --runtime "$JAVA23" \
  --zap "$ZAP_DIR" --out "$OUT/zap" --work "$OUT/runtime-goat"
~~~

O passivo usa spider de até um minuto e espera a fila de alertas. O ativo limita o teste às regras ZAP 40012 e 40018, com teto de um minuto, no parâmetro da busca do Juice Shop e na rota de login do WebGoat. Os dois aplicativos responderam HTTP 200 no healthcheck. Documentação. [ZAP API](https://www.zaproxy.org/docs/api/).

## DVWA P4 · Evidência dirigida

A avaliação usou o digest histórico da imagem DVWA, com seus arquivos PHP e MariaDB, dentro de um namespace Linux sem acesso externo. O ambiente local serviu o PHP 7.0 com seu servidor de desenvolvimento, após reset do banco descartável. A coleta histórica usava GKE e Apache. No laboratório, o nível de segurança confirmado por cookie era `low`.

| Caso | Observação | Estado |
|---|---|---|
| CSRF | A requisição GET com sessão, Referer distinto e sem token mudou a senha da conta descartável. O controle sem sessão redirecionou para login. A nova senha funcionou, a anterior falhou e foi restaurada. | Confirmada no protocolo HTTP |
| Weak Session IDs | Doze respostas HTTP 200 produziram o cookie de treinamento `dvwaSession` com os valores consecutivos 1 a 12. A evidência delimita-se a esse cookie. | Confirmada |
| Open HTTP Redirect | Duas rotas candidatas retornaram 404 no digest ensaiado. Consultamos a árvore da imagem e não localizamos o módulo nessas rotas. | Inconclusiva |

A P3\* (antes chamada P4-A; hoje lida como o Deploy Gate do artigo executado), aplicada aos laudos, simulou 2 decisões novas de Deploy, totalizando 58 decisões e cobertura de 10/13. A P4-B usa a nota CVSS v3.1 calculada do vetor registrado em `validacoes.csv` para cada caso confirmado. Com os vetores principais (CSRF 8,1 e Weak Session IDs 5,3) ficou em 57 e 9/13. Com os alternativos (6,5 e 9,1) também ficou em 57 e 9/13, mas fechando o outro caso. O resultado de P4-A é uma simulação de portão com entradas obtidas em teste real. Um teste com navegador real pode refinar a verificação de envio de cookies no CSRF. A fila agora inclui Exposed MySQL (`nao_executada`, ver `protocolo.md`), e o máximo condicional com as quatro lacunas confirmadas é 60 bloqueios e 12/13.

A versão empacotada contém laudo HTTP com status, indicadores e hash. Para repetir a decisão a partir dessa evidência na raiz que contém `etapa-02/`.

~~~bash
python3 etapa-02/scripts/politica_p4.py \
  --validacoes etapa-02/pilotos/p4-dvwa/validacoes.csv
~~~

Para recriar o teste interativo em WSL com Docker disponível, use uma instância descartável e limite a publicação ao loopback. Em outro terminal, abra `http://127.0.0.1:18080/setup.php`, crie o banco de laboratório e configure o nível Low na interface autenticada.

~~~bash
docker run --rm --name dvwa-etapa02-lab -p 127.0.0.1:18080:80 \
  vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7
~~~

Depois execute o teste com a conta descartável. O CLI pede a senha de forma interativa e salva somente o laudo verificável. Use outra pasta para a nova saída.

~~~bash
python3 etapa-02/scripts/validar_dvwa_http.py --base http://127.0.0.1:18080 \
  --configuracao 'DVWA digest dae203fe, Docker local, Apache, low' \
  --out nova-coleta/dvwa-http.json
docker stop dvwa-etapa02-lab
~~~

## TeaStore e Juice Shop P4 · evidência dirigida

O TeaStore 1.4.2 e o Juice Shop 19.0.0 passaram pela análise completa de P1–P3, sensibilidade e fila da P4 (`scripts/analise_alvos.py`, ver `docs/protocolo.md`). A confirmação dirigida (etapa equivalente ao `validar_dvwa_http.py`) só foi executada no Juice Shop nesta máquina, porque o TeaStore exige subir 7 microsserviços via Docker/Kubernetes.

**Juice Shop, instância local descartável.** Baixado o release oficial `juice-shop-19.0.0_node24_darwin_x64.zip` (hash conferido contra o `.md5` publicado no GitHub), executado com Node.js 24.22.1 **arm64** — os módulos nativos do pacote (`sqlite3`, `libxmljs2`, `iltorb`) são compilados para arm64 apesar do nome `_x64` do arquivo, então o Node x64 sob Rosetta falha ao carregá-los. O servidor foi restrito a `127.0.0.1:18080` por um módulo de pré-carregamento (`NODE_OPTIONS=--require loopback.js`) que força todo `net.Server.listen` a vincular em loopback, confirmado com `lsof`.

`scripts/validar_juice_shop.py` testa só o caso `js-exposed-metrics`: uma requisição GET em `/metrics`, sem autenticação, cujo sucesso é conferido tanto pela resposta (formato Prometheus, HTTP 200) quanto por um oráculo independente — o placar oficial de desafios da própria aplicação (`/api/Challenges?key=exposedMetricsChallenge`), que muda de não resolvido para resolvido só quando a rota é de fato exercitada. O laudo fica em `pilotos/p4-juice-shop/juice-http.json`, com hash conferido em `pilotos/p4-juice-shop/validacoes.csv`.

**Por que `js-rce-b2b` não foi testado.** A fila da P4 também inclui a execução de código no endpoint `/b2b/v2/orders` (desafio oficial `rceChallenge`). O teste que os próprios mantenedores do Juice Shop usam para esse desafio é enviar um payload que produz um laço não controlado dentro do avaliador da rota, de propósito, até estourar o tempo limite — ou seja, confirmar esse caso significa reproduzir um ataque de negação de serviço contra o processo-alvo, mesmo numa instância local descartável. O grupo decidiu não automatizar esse teste; o caso fica como `nao_executada` em `validacoes.csv`, apoiado só na evidência estática (Semgrep sinalizando `routes/b2bOrder.ts` com `unsafe-dynamic-method`) e na evidência indireta do Trivy. Os dois casos de XSS (`js-dom-xss`, `js-reflected-xss`) exigem um navegador real e ficam como verificação manual pendente.

~~~bash
# Instância local (Node arm64 — ver nota acima sobre a arquitetura dos módulos nativos)
unzip juice-shop-19.0.0_node24_darwin_x64.zip -d app
PORT=18080 NODE_OPTIONS="--require loopback.js" node app/juice-shop_19.0.0/build/app.js &

python3 etapa-02/scripts/validar_juice_shop.py --base http://127.0.0.1:18080 \
  --configuracao 'Juice Shop 19.0.0, release oficial, Node 24.22.1 arm64, loopback' \
  --out etapa-02/pilotos/p4-juice-shop/juice-http.json
~~~

**TeaStore 1.4.2, Deploy Gate local (2026-11-22).** Os 7 serviços e o ZAP 2.17.0 rodam em Docker (colima, aarch64) pelo `ambientes/teastore/docker-compose.yaml`: o compose de referência do projeto com as imagens fixadas por digest, o webui publicado só em `127.0.0.1:18081`, o banco sem porta publicada e o ZAP em modo daemon na mesma rede (`127.0.0.1:18090`). `scripts/zap_passivo_docker.py` repete a parte passiva do piloto do Juice Shop (spider + fila passiva, sem escaneamento ativo) e grava `pilotos/zap/teastore-passivo.json` (29 URLs, 532 alertas) e `teastore-resumo.json` (com SHA-256).

**`ts-db-reset-unauth` confirmado pelo spider.** O spider, sem cabeçalho `Cookie`, submeteu o formulário público de `/database` (`categories=5&products=100&users=100&orders=5&confirm=Confirm`, valores padrão) para `/dataBaseAction`. A resposta foi `302 Location: /status`, que só ocorre no ramo que chama `persistence/generatedb`, e o log do webui registrou `DB is re-generating` (`pilotos/p4-teastore/webui-log-dataBaseAction.txt`). Laudo em `pilotos/p4-teastore/teastore-http.json`, hash em `validacoes.csv`. O ZAP não emitiu alerta para esse caso: a confirmação vem do efeito observado, não de uma regra do scanner. O pedido foi POST; `AbstractUIServlet.handlePOSTRequest` (linhas 271–273) delega para `handleGETRequest`, e o `DataBaseActionServlet` não a sobrescreve, então GET e POST seguem o mesmo ramo. Os campos HTTP do laudo foram transcritos da mensagem 172 pela API do ZAP antes de derrubar os contêineres; a mensagem bruta não foi salva. Como o spider regenerou o banco no meio da varredura, os totais de URLs e alertas (29 e 532) podem variar entre execuções.

~~~bash
docker compose -f etapa-02/ambientes/teastore/docker-compose.yaml -p teastore up -d
# aguarde /tools.descartes.teastore.webui/status mostrar todos os serviços
python3 etapa-02/scripts/zap_passivo_docker.py teastore \
  --alvo http://webui:8080/tools.descartes.teastore.webui/ --base http://webui:8080 \
  --out etapa-02/pilotos/zap --spider-min 2
python3 etapa-02/scripts/analise_alvos.py
docker compose -p teastore down
~~~

**Pendências do TeaStore.** `ts-output-encoding` (XSS armazenado) exige enviar um payload de script pelo checkout e abrir `/profile` no navegador: fica para verificação manual. `ts-tls-trust-all` só roda com `USE_HTTPS=true`, ausente da implantação de referência, e fica `nao_executada`.

## P4 orientada a ações · como reproduzir

Protocolo e resultados em `docs/p4-acoes.md`. Mesmos contêineres da seção seguinte (DVWA, Juice
Shop com o hook de módulos e TeaStore com ZAP). O artefato dos autores fornece os relatórios
Trivy e Semgrep da DVWA.

~~~bash
cd etapa-02
AUTORES=../../sbseg2026-deteccao-direta-indireta   # clone do artefato, commit 5b18244
python3 scripts/contexto_execucao.py --imagem --autores "$AUTORES" \
  --spider-dvwa "http://$DV/" \
  --spider-teastore "http://webui:8080/tools.descartes.teastore.webui/" \
  --spider-juice-shop "http://$JS:3000/"
python3 scripts/politica_acoes.py --autores "$AUTORES"
bash scripts/trivy_vex.sh            # Trivy 0.69.3 com e sem VEX (saída em ~/.cache/trivy-p4)
python3 scripts/validar_vex_trivy.py
python3 scripts/verificar_s5.py
# reprodutibilidade: repita a coleta com contêineres novos, copie o CSV para
# results/contexto_imagem_coleta2.csv e compare
python3 scripts/comparar_coletas.py
SBSEG_AUTORES="$AUTORES" python3 -m unittest discover -s tests
~~~

Com Python 3.10 ou superior. Sem `SBSEG_AUTORES`, os testes da DVWA em `test_acoes.py` são pulados.

## P4 com contexto de execução (versão anterior) · como reproduzir a coleta

Protocolo e resultados em `docs/p4-contexto.md`. Requer Docker; as imagens amd64 rodam
emuladas em Mac com Apple Silicon (colima com Rosetta). Tudo fica em `127.0.0.1`.

~~~bash
cd etapa-02
# DVWA (mesmo digest do artefato dos autores) e Juice Shop com o hook de módulos Node
docker run -d --name dvwa-r --platform linux/amd64 -p 127.0.0.1:18083:80 \
  vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7
docker run -d --name juice-r --platform linux/amd64 -p 127.0.0.1:18082:3000 \
  -e NODE_OPTIONS=--require=/hook/hook-modulos.js -v "$PWD/ambientes/contexto:/hook:ro" \
  bkimminich/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58
# TeaStore (7 serviços) + ZAP; espere /status sem serviços Offline
docker compose -f ambientes/teastore/docker-compose.yaml -p teastore up -d
# o ZAP precisa alcançar a DVWA e o Juice Shop na rede padrão para o spider (S3)
docker network connect bridge teastore-zap-1
DV=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' dvwa-r)
JS=$(docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' juice-r)
# o artefato dos autores fornece o relatório Trivy da DVWA
python3 scripts/contexto_execucao.py --autores ../../sbseg2026-deteccao-direta-indireta \
  --spider-dvwa "http://$DV/" \
  --spider-teastore "http://webui:8080/tools.descartes.teastore.webui/" \
  --spider-juice-shop "http://$JS:3000/"
python3 scripts/politica_contexto.py
~~~

**Observação S4 (fluxo autenticado no Juice Shop), manual.** Com o Juice Shop ainda em
execução: criar uma conta de teste local por `POST /api/Users/`, registrar uma resposta de
segurança por `POST /api/SecurityAnswers/`, entrar por `POST /rest/user/login` e fazer
`GET /dataerasure/` com o cookie `token`. Depois, copiar a lista de módulos carregados
(`docker cp juice-r:/tmp/p4-modulos.txt -`) para
`pilotos/contexto/juice-shop--juice-r--s4-autenticado.txt`. `politica_contexto.py` lê esse
arquivo. Não use credenciais reais.

Ao terminar: `docker rm -f dvwa-r juice-r` e `docker compose -p teastore down`.

**Auditoria manual.** `scripts/amostra_auditoria.py` sorteia os 20 pares (semente fixa) e
preserva os julgamentos já registrados em `results/auditoria_amostra.csv`.

