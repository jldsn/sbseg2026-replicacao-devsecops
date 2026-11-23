# P4 com contexto de execução: protocolo registrado antes do cálculo

> **Versão anterior (22/11/2026).** Substituída pela P4 orientada a ações
> ([`p4-acoes.md`](p4-acoes.md)). Uma revisão crítica mostrou que esta versão contava por
> pacote dpkg, e não por vulnerabilidade (os "8 evitados" da DVWA são 1 CVE de 9), só filtrava
> os indiretos (que dependem da matriz) e não mudava nenhuma decisão nem superava a regra
> "P3 + indiretos ≥ 9". Mantida como registro.

**Registrado em 22/11/2026, depois de um piloto qualitativo e antes de qualquer resultado
numérico.** Substitui a P4 de "confirmação dirigida" como proposta do grupo. O motivo está em
`p4-avaliacao.md` e resumido abaixo.

## 1. Por que a P4 anterior não é uma melhoria

1. **Já estava no artigo.** O Deploy Gate do artigo bloqueia "exploração confirmada" por DAST
   ou "testes customizados", e o teste de credenciais dos autores já é um achado direto que
   bloqueia na P3. Uma confirmação da P4 antiga é só mais um teste customizado na P3.
2. **O sinal que abria a fila não tinha informação.** A fila abria com CVEs de bibliotecas do
   sistema que só coincidiam no CWE (gnupg com CWE-352 para o CSRF da DVWA; curl com CWE-306
   para o reset do TeaStore). O teste confirmava o caso da matriz, nunca o CVE.
3. **Dependia da matriz de referência**, que um pipeline real não tem.

Os testes executados continuam válidos, mas como **o Deploy Gate do artigo efetivamente
executado** (chamado aqui de P3\*), e não como uma política nova.

## 2. A mudança de arquitetura

O artigo trata todo achado indireto do mesmo jeito: informativo no Build. Ele mesmo diz que o
componente "pode nunca ser invocado" e deixa como trabalho futuro "incorporar características
dos achados como refinamento intraclasse".

Proposta: **um coletor de contexto de execução no portão de Deploy.** Com a aplicação
implantada em homologação, o coletor registra quais pacotes os processos da aplicação de fato
carregaram (bibliotecas mapeadas em memória, arquivos abertos, executáveis em execução e, em
Node.js, os módulos carregados). Cada achado indireto do Build é reclassificado:

- **indireto em uso**: o pacote vulnerável está carregado pela aplicação em execução;
- **indireto latente**: o pacote está na imagem, mas não foi carregado.

**P4 (contexto de execução) = P3\* + bloqueio, no Deploy, dos achados indiretos em uso com
nota ≥ 7.** Os latentes continuam informativos, como na P3.

A decisão sai do Build (estático) e passa para o Deploy (com o contexto da implantação), e
o coletor não usa a matriz de referência: depende só do relatório do scanner e da observação do
contêiner. *Ressalva:* nesta avaliação, quais CVEs contam como "indiretos" ainda vem da
classificação do artigo, que depende da matriz (coincidência de CWE). Num pipeline sem matriz,
o coletor se aplicaria a todos os achados de imagem.

## 3. Coleta (definida antes)

- Alvos: DVWA (mesma imagem e digest do artefato dos autores), TeaStore 1.4.2 (7 serviços) e
  Juice Shop 19.0.0, todos locais em `127.0.0.1`.
- Duas observações por alvo: S1 logo após a aplicação responder e S2 depois de tráfego benigno
  (GET nas páginas públicas, sem payload de ataque). Pacote em uso = carregado em S1 ou S2.
  A diferença entre S1 e S2 é reportada como medida de estabilidade.
- Mapeamento arquivo → pacote: banco do dpkg do próprio contêiner (Debian/Ubuntu); caminho do
  `.jar` (Java); caminho do executável (binários Go); caminho do módulo em `node_modules`
  (Node.js, por um hook de `require` injetado só no contêiner de teste).

## 4. Métricas e critérios (definidos antes)

Por alvo: achados indiretos com nota ≥ 7 (os que a P2 bloqueia e a P3 não); quantos estão em
uso e quantos latentes; bloqueios e cobertura bruta de P2, P3, P3\* e P4.

- **Critério de utilidade do coletor:** a fração em uso entre os indiretos ≥ 7 fica entre 10%
  e 90% em pelo menos 2 dos 3 alvos. Fora disso o coletor não discrimina, e a P4 se reduz à P2
  ou à P3.
- **Critério de estabilidade:** S1 e S2 classificam igual pelo menos 90% dos indiretos ≥ 7.
- **Leitura do resultado:** reportar quantos bloqueios da P2 recaem sobre pacotes latentes
  (bloqueios que a P4 evita com evidência) e quantos casos da matriz a P4 cobre a mais que a
  P3\*. A cobertura obtida via indireto em uso continua sendo coincidência de CWE e será
  reportada como tal.

## 5. Limites conhecidos antes da coleta

- Carregado não é o mesmo que a função vulnerável ser alcançada; é um filtro necessário, não
  suficiente.
- Bibliotecas carregadas só sob certos fluxos podem aparecer como latentes (falso negativo).
  O tráfego benigno reduz, mas não elimina, esse risco.
- As imagens são amd64 e rodam emuladas (Rosetta) nesta máquina; o carregamento de bibliotecas
  não depende da arquitetura.

## Resultados

*Preenchido depois da coleta. Fontes: `results/contexto_execucao.csv` (uma linha por achado
indireto), `results/p4_contexto_resumo.csv`, `results/p4_contexto_politicas.csv` e as
observações brutas em `pilotos/contexto/`. Scripts: `scripts/contexto_execucao.py` e
`scripts/politica_contexto.py`.*

Terminologia: usamos **carregado / não carregado**, e não "em uso / latente". Carregado quer
dizer que algum processo mapeou a biblioteca, abriu o arquivo ou executou o binário; não quer
dizer que a função vulnerável foi chamada. A DVWA, por exemplo, carrega `libpq5` (PostgreSQL)
sem usar PostgreSQL.

### Critérios registrados

| Critério | DVWA | TeaStore | Juice Shop | Resultado |
|---|---|---|---|---|
| Fração carregada entre os indiretos ≥ 7 (definição registrada, S1 ou S2) | 67% | 18% | 74% | **Passa** (3 de 3 entre 10% e 90%) |
| Mesma fração com a definição final (S1 a S4 e inicialização) | 67% | 22% | 100% | **Passa** (2 de 3; no Juice Shop o coletor não filtra nada, o que é correto: tudo é carregado) |
| S1 e S2 classificam igual (coleta limpa, contêineres novos) | 24/24 | 122/123 (99%) | 19/19 | **Passa** (todos ≥ 90%) |

### Resultado principal: quantos bloqueios indiretos da P2 recaem sobre pacotes não carregados

Com a definição final (S1 a S3, inicialização e fluxo autenticado; ver desvios):

| Alvo | Indiretos ≥ 7 (bloqueados pela P2) | Não carregados | Pares (pacote, CVE) distintos não carregados |
|---|---:|---:|---:|
| DVWA | 24 | 8 (33%) | 8 de 24 |
| TeaStore | 123 | **96 (78%)** | 34 de 43 (79%) |
| Juice Shop | 19 | **0 (0%)** | 0 de 19 |

As duas pontas mostram um erro diferente das políticas do artigo:

- **No TeaStore, a P2 bloqueia demais.** 96 dos 123 bloqueios indiretos são de pacotes que
  nenhum processo carrega (`curl`, `libcurl`, `perl`, `openssl` CLI, `libexpat`, pacotes do
  `gnupg` no banco). Isso é 37% de todos os bloqueios da P2 no alvo. **Ressalva importante:**
  o build do TeaStore continua bloqueado na P3 e na P4 pelos agregados de SO por imagem (21
  bloqueios diretos: fim de suporte, pacotes com correção e demais CVEs, por máximo). Os 96 são
  decisões de bloqueio a menos atribuídas a casos da aplicação, não a diferença entre um build
  quebrado e um build que passa.
- **No Juice Shop, a P3 bloqueia de menos.** Os 19 achados indiretos graves estão em
  bibliotecas carregadas pela aplicação (por exemplo, as fugas de sandbox do `vm2`, que é
  carregado). A P3 transforma todos em registro informativo.
- **A DVWA fica no meio:** um terço dos indiretos está em pacotes não carregados.

A suposição do artigo, de que o componente indireto "pode nunca ser invocado", é verdadeira em
grau muito diferente conforme a composição da imagem: forte numa imagem de uso geral com
microsserviços Java, fraca numa aplicação Node cujas dependências vulneráveis são bibliotecas
da própria aplicação. **Uma regra uniforme para todos os indiretos, seja a da P2 ou a da P3,
erra em pelo menos um dos dois cenários.**

### O critério não é um limiar disfarçado

| Alvo | Carregados entre indiretos com nota 7–8,9 | Carregados entre indiretos com nota ≥ 9 |
|---|---:|---:|
| DVWA | 15 de 22 | 1 de 2 |
| TeaStore | 26 de 116 | 1 de 7 |
| Juice Shop | 9 de 9 | 10 de 10 |

No TeaStore, os indiretos mais graves estão, na maioria, em pacotes não carregados. Um ajuste de
limiar não reproduz a seleção do coletor.

### Políticas (bloqueios · cobertura bruta da matriz)

| Política | DVWA | TeaStore | Juice Shop |
|---|---|---|---|
| P2 | 80 · 11/13 | 262 · 7/14 | 28 · 7/14 |
| P3 | 56 · 8/13 | 139 · 4/14 | 9 · 3/14 |
| P3\* (Deploy Gate do artigo executado) | 58 · 10/13 | 140 · 5/14 | 10 · 4/14 |
| **P4 (contexto de execução)** | **74 · 11/13** | **167 · 7/14** | **29 · 7/14** |
| P4 com a definição registrada (S1/S2) | 74 · 11/13 | 162 · 6/14 | 24 · 5/14 |
| P3 + carregados (sem os testes da P3\*) | 72 · 10/13 | 166 · 6/14 | 28 · 7/14 |
| A2 · P3 + indiretos ≥ 9 | 58 · 8/13 | 146 · 6/14 | 19 · 4/14 |

A P3\* soma um bloqueio por caso confirmado pelos testes customizados, supondo nota ≥ 7 para
cada confirmação, como o proxy 7,5 que o artigo dá ao seu teste customizado. Por isso, no
Juice Shop, a P4 (29) passa a P2 (28): são os 19 indiretos carregados mais a confirmação de
`js-exposed-metrics`.

**Comparação justa com as alternativas de limiar.** A1 a A3 não têm os testes da P3\*, então a
comparação justa é com "P3 + carregados". Nela, **a A2 domina no TeaStore** (146 · 6/14 contra
166 · 6/14); na DVWA e no Juice Shop nenhuma alternativa domina
(`p4_contexto_resumo.csv`). Ou seja: em contagem de bloqueios e cobertura da matriz, a P4 não é
melhor que um limiar mais alto no TeaStore. A diferença entre as duas está em **quais** achados
bloqueiam (item seguinte e auditoria), não nesses números.

**Por que a cobertura não é a manchete.** Os casos que a P4 cobre a mais que a P3\* vêm de
coincidência de CWE, como na P2: `dvwa-exposed-mysql` por um CVE do PHP; `ts-tls-trust-all`
por `libssl`, `libthrift` e `okhttp` carregados, embora o trecho trust-all não rode na
implantação de referência; `js-rce-b2b` por `vm2` e `lodash`, embora a rota B2B use `node:vm`
e `notevil`, não o `vm2`. A cobertura da matriz mede o quanto os CWEs coincidem, não se a
falha do caso foi detectada. O que a P4 decide com evidência é **quais achados indiretos
merecem bloqueio**, e o coletor que decide isso não usa a matriz.

### Desvios do protocolo e verificações posteriores

- **Inicialização (pós-registro).** O snapshot não vê processos de vida curta. O coletor passou
  a ler o Entrypoint e o Cmd das imagens e os scripts que eles chamam. Achado: o `gosu`
  (binário Go do banco do TeaStore, 5 achados `stdlib`) roda na inicialização. Ele foi
  reclassificado como carregado. `curl`, `perl` e `openssl` não aparecem nos scripts de
  inicialização (`start.sh`, `catalina.sh`, `docker-entrypoint.sh`).
- **Spider do ZAP, S3 (pós-registro).** Tráfego benigno mais amplo (29, 29 e 95 URLs). Não
  mudou nenhuma classificação.
- **Fluxo autenticado no Juice Shop, S4 (pós-registro, verificação manual).** O `handlebars`
  aparecia como não carregado. O Juice Shop usa `hbs` como motor de views, mas só o carrega ao
  renderizar uma página. Depois do login de uma conta de teste local e de um GET em
  `/dataerasure/`, `hbs` e `handlebars` foram carregados (evidência em
  `pilotos/contexto/juice-shop--juice-r--s4-autenticado.txt`). Isso mudou o Juice Shop de 5
  achados não carregados para 0. **É um falso negativo real do coletor**: carregamento
  preguiçoso em fluxos autenticados escapa da observação sem login.
- **Comparabilidade da DVWA.** Nosso contêiner roda o `/main.sh` da imagem, que sobe MySQL e Apache juntos. O manifesto dos autores (`k8s/dvwa.yaml`, recuperado do relatório do Checkov deles) não sobrescreve o comando, então o contêiner `dvwa-app` deles também roda o `/main.sh`: a observação é comparável.
- **Dependência do tráfego e do aquecimento no TeaStore.** As bibliotecas Java `libthrift` e
  `okhttp` carregam sob demanda. Na primeira coleta, 9 dos 27 achados carregados só apareceram
  depois do tráfego (S1 = S2 em 114/123). Na coleta limpa que está no repositório, a própria
  verificação de prontidão (GET em `/status`, que chama os outros serviços) já os carregava
  (122/123). O critério de estabilidade passa nas duas, mas em parte porque os pacotes de sistema
  nunca carregados dominam o denominador. A classificação final (27 carregados) foi idêntica
  nas três coletas feitas.
- **Tráfego autenticado só no Juice Shop.** Na DVWA e no TeaStore não houve navegação com
  login; bibliotecas carregadas só em fluxos autenticados nesses alvos apareceriam como não
  carregadas. A auditoria manual (`p4-auditoria.md`) não encontrou nenhum caso assim na amostra.

### Consequência para a arquitetura

Como o coletor pode deixar de ver uma biblioteca carregada só em fluxos raros (o caso do
`handlebars`), **um achado "não carregado" não é descartado**: continua informativo, como na
P3, e é reavaliado pelo **Runtime Watch**, o quarto estágio do artigo, que hoje não tem papel
na simulação. Se a telemetria de produção registrar o carregamento, o achado passa a bloquear
o próximo deploy. Isso dá ao Runtime Watch a função de realimentação que o artigo previu e
deixou como trabalho futuro.

### Conclusão

**O avanço desta etapa não é um número de bloqueios; é transformar uma suposição do artigo em
uma medida.** O artigo trata todo achado indireto como informativo porque o componente "pode
nunca ser invocado". Medimos isso em três aplicações. A fração não carregada vai de 78%
(TeaStore) a 0% (Juice Shop). Logo, a regra uniforme da P3 é adequada para um alvo e errada
para outro. A P4 substitui a regra uniforme por uma decisão por achado, tomada no Deploy, com
evidência do contêiner implantado, por um coletor que não usa a matriz de referência.

Em números de bloqueios e cobertura, a P4 não supera um limiar mais alto no TeaStore, e o build
do TeaStore continua bloqueado pelos agregados de imagem. O ganho está na qualidade da decisão
sobre os indiretos, que a auditoria manual sustenta do lado "não carregado" (10 de 10).

**Limites:** carregado não é explorável; o coletor tem falso negativo em fluxos autenticados
(mitigado pela realimentação do Runtime Watch); a amostra são três aplicações.

**Auditoria manual ([`p4-auditoria.md`](p4-auditoria.md), critérios registrados antes do
sorteio):** em 20 pares sorteados, os 10 "não carregados" foram confirmados como não usados
pela implantação (IC 95%: 69% a 100%); entre os 10 "carregados", 2 são aplicáveis, as fugas de
sandbox do `vm2` alcançáveis pelo chatbot do Juice Shop, justamente os que a P3 silenciaria.
