# P4 orientada a ações, com contexto de execução: protocolo registrado antes

**Registrado em 22/11/2026, antes de calcular qualquer resultado desta versão.** Substitui a
"P4 com contexto de execução" de `p4-contexto.md` como proposta do grupo. Aquela versão fica
como registro da etapa anterior.

## 1. Por que mudar de novo

Uma revisão crítica da versão anterior, feita sobre os próprios dados do repositório, apontou:

1. **Nenhuma decisão de deploy muda.** P2, P3 e a P4 anterior bloqueiam os três alvos. A única
   diferença era uma contagem de unidades.
2. **A contagem era por pacote dpkg, não por vulnerabilidade.** Na DVWA, os "8 bloqueios evitados"
   correspondem a 1 CVE de 9, porque o mesmo CVE continua bloqueando por um pacote irmão
   carregado (`openssl`/`libssl1.1`, `libldap-common`/`libldap-2.4-2`). No TeaStore, as 96
   unidades correspondem a 6 CVEs de 15.
3. **O único acerto auditado é capturado por um limiar simples.** As duas fugas de sandbox do
   `vm2` têm nota 10,0, e a regra "P3 + indiretos ≥ 9" já as bloqueia.
4. **Dependia da matriz.** Só os achados "indiretos" eram filtrados, e quem é indireto vem da
   coincidência de CWE com a matriz de referência, que um pipeline real não tem.
5. **A métrica "bloqueios" é dominada por artefato de contagem.** 100 dos 139 bloqueios da P3 no
   TeaStore vêm de uma única regra do Semgrep (`detected-bcrypt-hash`), que dispara uma vez por
   linha do dump `setupData.sql`. Contar unidades não diz quanto trabalho o time tem.

**Transparência:** durante essa revisão foram vistas contagens exploratórias que antecipam parte
dos resultados (os números do item 2 e uma contagem grosseira de grupos por ferramenta e regra,
por exemplo 139 unidades → cerca de 39 grupos na P3 do TeaStore). A definição abaixo foi fixada
depois disso, e os critérios foram escritos para não depender desses números.

## 2. Pergunta prática

**"O que o time precisa fazer para liberar o deploy?"** A P4 responde com uma lista de **ações de
correção**, e não com uma contagem de achados, e usa o contexto de execução para tirar da lista,
com justificativa registrada, as vulnerabilidades de imagem que a implantação não executa.

## 3. Definição da P4

1. **Escopo sem matriz.** Todo registro do Trivy de imagem (Trivy Image no TeaStore e no Juice
   Shop, Trivy Container na DVWA) com nota ≥ 7, de qualquer classe (direta, indireta ou sem
   matriz). A classe direta/indireta deixa de ser usada para decidir.
2. **Filtro de execução, por vulnerabilidade.** Um registro (pacote, CVE) é **carregado** se o
   coletor observou o pacote em uso (S1, S2, S3, scripts de inicialização e, no Juice Shop, o fluxo
   autenticado S4, com as mesmas regras de `contexto_execucao.py`). Um CVE **bloqueia** se pelo
   menos um pacote afetado por ele, na mesma imagem, está carregado. Se nenhum está, o CVE sai do
   bloqueio com uma declaração OpenVEX `not_affected`, justificativa
   `vulnerable_code_not_in_execute_path`, e fica para reavaliação pelo Runtime Watch.
3. **Fim de suporte do SO não é filtrado.** O agregado de SO em fim de suporte (EOSL) continua
   bloqueando como na P3: é um fato do ciclo de vida da imagem, não uma vulnerabilidade de pacote.
4. **O resto é a P3\*.** Achados de aplicação (Semgrep, Trivy FS, Checkov, ZAP, teste de
   credenciais) seguem a regra da P3, e as confirmações do Deploy Gate executado somam como na P3\*.
5. **Unidade de decisão = ação de correção**, definida abaixo, e aplicada igualmente a **todas**
   as políticas comparadas.

## 4. Ações de correção (definição única para todas as políticas)

Uma ação é a mudança mínima que tira um conjunto de unidades bloqueadas do bloqueio:

| Origem | Chave da ação | Leitura |
|---|---|---|
| Registro de imagem (pacote de SO) | (imagem base, pacote fonte) | atualizar o pacote fonte para a maior versão corrigida entre os CVEs; "sem correção" se algum CVE não tiver |
| Registro de imagem (jar, npm, binário Go) | (ecossistema, pacote) | atualizar ou substituir a dependência |
| Agregado EOSL | (família e versão do SO) | migrar a imagem base |
| Agregado de pacotes com correção ou de demais CVEs | uma ação por registro membro com nota ≥ 7, pela regra acima | é o que zera o máximo do agregado |
| Semgrep | (regra, arquivo) | corrigir o padrão no arquivo |
| Trivy FS | (ecossistema, pacote) | atualizar a dependência |
| Demais (Checkov, ZAP, teste de credenciais, confirmação) | a própria unidade | uma correção |

"Imagem base" = família e versão do SO da imagem (Debian 10.10, Ubuntu 18.04, Debian 12.11,
Debian 9.5), porque as imagens do TeaStore compartilham a mesma base e uma correção na base vale
para todas. "Pacote fonte" = campo `Source` do banco do dpkg do contêiner (por exemplo `curl`,
`libcurl4` e `libcurl3-gnutls` saem do mesmo fonte `curl`); sem esse campo, o próprio pacote.

## 5. Políticas comparadas

| Política | Imagem | Demais |
|---|---|---|
| P2 | todos os registros e agregados ≥ 7 | todos ≥ 7 |
| P3 | sem indiretos | sem indiretos |
| P3\* | como P3 | P3 + confirmações |
| A2 | P3 + indiretos ≥ 9 | como P3 |
| **Escopo sem coletor (ablação)** | todos os registros ≥ 7, EOSL como agregado, sem filtro | como P3\* |
| **P4** | registros ≥ 7 carregados, EOSL como agregado | como P3\* |

A ablação é a P4 sem o coletor: mesmo escopo, mesma unidade de ação. A diferença entre as duas é
o efeito do coletor e nada mais. A diferença entre P3 em unidades e P3 em ações é o efeito da
mudança de unidade, e **não é atribuída à P4**.

## 6. Métricas (por alvo e política)

- **Ações para liberar o deploy** (total e por tipo: migrar SO, pacote de imagem, Semgrep, outros).
- **CVEs de imagem bloqueantes distintos** (fora o agregado EOSL).
- **CVEs justificados por VEX** (só P4).
- **Unidades bloqueadas** (métrica do artigo, para continuidade) e **cobertura da matriz**
  (contexto; a obtida por coincidência de CWE continua sendo coincidência).

## 7. Critérios registrados

- **S1 — o coletor é útil:** a P4 tira do bloqueio pelo menos 20% dos CVEs de imagem distintos
  com nota ≥ 7 da ablação em pelo menos 2 dos 3 alvos.
- **S2 — o coletor reduz trabalho:** a P4 exige menos ações de pacote de imagem que a ablação em
  pelo menos 2 dos 3 alvos. (Refinamento da proposta aprovada, que comparava com "P3 com ações":
  a P3 tem escopo diferente, então a comparação que isola o coletor é com a ablação. A comparação
  com P3 e A2 é reportada como descrição.)
- **S3 — sem perda:** a P4 cobre todos os casos da matriz que a P3\* cobre.
- **S4 — funciona num scanner real:** rodando o Trivy oficial com e sem o VEX gerado, numa imagem
  do TeaStore e na do Juice Shop, o conjunto suprimido é exatamente o conjunto de pares
  (pacote, CVE) declarados no VEX presentes no relatório, e nenhum outro. (O banco do Trivy de hoje
  difere do da coleta; por isso o critério compara com e sem VEX na mesma execução.)
- **S5 — falso negativo, verificação mecânica:** para cada pacote não carregado, checar (a) se
  algum executável dele aparece em Healthcheck, Entrypoint, Cmd, scripts de inicialização, cron da
  imagem ou sondas do manifesto de referência, e (b) se o nome de alguma biblioteca dele (soname)
  aparece como texto dentro de um binário ou biblioteca carregado, o que indicaria carregamento sob
  demanda (`dlopen`). Cada ocorrência é um falso negativo potencial, listado e examinado. O critério
  passa com zero falsos negativos confirmados. Esta checagem substitui o segundo avaliador, que o
  grupo não tem; o julgamento de aplicabilidade continua declarado como de avaliador único.

**Leitura se falhar.** Se S1 ou S2 falharem, o resultado é reportado como falha do coletor e a
redução de trabalho fica atribuída só à mudança de unidade. Se S3 falhar, os casos perdidos são
listados. Se S4 falhar, a P4 fica como simulação, não como integração.

## 8. Limites conhecidos antes

- Carregado não é explorável: o lado "carregado" continua com ruído (8 de 10 não aplicáveis na
  auditoria anterior). A P4 não resolve isso.
- A decisão de deploy deve continuar "bloqueado" nos três alvos (Semgrep, achados diretos de
  aplicação e SO em fim de suporte). O ganho que se procura é em trabalho para liberar e em quais
  itens o compõem, não na mudança do veredito.
- Agrupar por (regra, arquivo) pode juntar falhas distintas no mesmo arquivo: uma ação, não uma
  falha. A cobertura da matriz é reportada para mostrar que nenhum caso some.
- Trivy FS (dependências da aplicação no repositório) fica fora do filtro nesta versão.
- O coletor observa sem login na DVWA e no TeaStore (falso negativo possível em fluxos autenticados).

## Resultados

*Preenchido depois do cálculo. Fontes: `results/contexto_imagem.csv` (um registro do Trivy de
imagem por linha: 1.575 na DVWA, 3.858 no TeaStore, 448 no Juice Shop), `results/p4_acoes.csv`
(cada ação, por política), `results/p4_acoes_resumo.csv`, `results/p4_vex_trivy.csv`,
`results/p4_s5.csv`, observações brutas e VEX (um arquivo por imagem) em `pilotos/contexto-acoes/`.
Scripts: `contexto_execucao.py --imagem`, `politica_acoes.py`, `trivy_vex.sh`,
`validar_vex_trivy.py`, `verificar_s5.py`. Testes: `tests/test_acoes.py` (a DVWA exige a variável
`SBSEG_AUTORES` com o clone do artefato dos autores; sem ela, os testes da DVWA são pulados).*

### Resumo honesto, antes dos números

1. **Dois critérios registrados falharam.** O S1 (magnitude por CVE) passou só no TeaStore, e o
   S5 (falso negativo) achou um erro real do coletor. Uma revisão posterior achou mais dois
   problemas, que o S5 não detectaria (seção "Correções pós-registro").
2. **A redução de trabalho fica quase toda dentro de uma migração que a própria lista exige.** DVWA
   e TeaStore rodam sobre SO em fim de suporte, e a P4 mantém "migrar a imagem base" como ação
   obrigatória. Atualizar pacotes de SO numa base que vai ser trocada não é trabalho separado.
   Descontando essas ações absorvidas, **o coletor não muda o trabalho na DVWA nem no TeaStore**
   (35 → 35 e 17 → 17). A redução de trabalho medida fica num alvo só, o Juice Shop (47 → 41).
3. **O que o coletor entrega de fato é triagem com evidência**, consumida por um scanner real: de
   18% a 44% dos CVEs de imagem com nota ≥ 7 saem do bloqueio com declaração VEX. Nas 2 imagens em
   que testamos (de 9), o Trivy oficial suprime exatamente esses.
4. **Achado exploratório, fora da P4:** medida em ações de correção e com o agregado do Trivy pelo
   máximo, como no artigo, a P3 exige o mesmo trabalho que a P2. Com a média, isso deixa de valer.

### Ações para liberar o deploy

| Política | DVWA | TeaStore | Juice Shop |
|---|---|---|---|
| P2 | 87 ações (33 não absorvidas) · 11/13 | 81 (16) · 7/14 | 46 (46) · 7/14 |
| P3 | 87 (33) · 8/13 | 81 (16) · 4/14 | 46 (46) · 3/14 |
| P3\* | 89 (35) · 10/13 | 82 (17) · 5/14 | 47 (47) · 4/14 |
| A2 (P3 + indiretos ≥ 9) | 87 (33) · 8/13 | 81 (16) · 6/14 | 46 (46) · 4/14 |
| Escopo sem coletor (ablação) | 89 (35) · 11/13 | 82 (17) · 7/14 | 47 (47) · 7/14 |
| P4 com a definição registrada | 74 (35) · 11/13 | 36 (17) · 7/14 | 41 (41) · 7/14 |
| **P4** | **74 (35) · 11/13** | **42 (17) · 7/14** | **41 (41) · 7/14** |
| *Unidades bloqueadas (artigo): P2 → P3* | *80 → 56* | *262 → 139* | *28 → 9* |

"Não absorvidas" = ações que sobram quando se desconta a atualização de pacotes de SO numa imagem
base que a mesma lista manda migrar. O Juice Shop roda sobre Debian 12, ainda com suporte, então
nada é absorvido.

### O que o coletor muda (ablação → P4)

| | DVWA | TeaStore | Juice Shop |
|---|---|---|---|
| CVEs de imagem distintos com nota ≥ 7 fora do bloqueio | 250 → 203 (−18,8%) | 287 → 161 (**−43,9%**) | 144 → 118 (−18,1%) |
| Ações de pacote e dependência de imagem (critério S2) | 54 → 39 | 77 → 37 | 39 → 33 |
| Ações totais | 89 → 74 | 82 → 42 | 47 → 41 |
| **Ações não absorvidas pela migração de SO** | **35 → 35** | **17 → 17** | **47 → 41 (−13%)** |
| Pares (CVE, pacote) declarados no VEX, somando as imagens | 78 | 1.273 | 38 |

**Leitura.** O número que mede trabalho poupado é a última linha de ações. Na DVWA e no TeaStore,
todas as ações que o coletor remove são atualizações de pacotes de SO numa base em fim de suporte.
Depois da migração, os CVEs mudam e a classificação precisa ser refeita. Nesses dois alvos, o valor
do coletor é de **triagem**: dizer, com evidência, quais dos alertas graves de hoje não estão no
caminho de execução (no TeaStore, 44% dos CVEs distintos), o que importa enquanto a migração não
sai. No Juice Shop, as 6 ações a menos são reais: 5 dependências npm (`diff`, `ip-address`,
`lodash.set`, `tar`, `tar-fs`) e o `openssl` do SO. O Node traz o OpenSSL embutido e não carrega a
`libssl3` do Debian.

**Comparada com a P3\*** (o artigo com os testes do Deploy executados), a P4 não pede mais
trabalho não absorvido em nenhum alvo (35 contra 35, 17 contra 17, 41 contra 47). **Comparada com
a P2 e a P3 do artigo**, pede 2 e 1 ações não absorvidas a mais na DVWA e no TeaStore (35 contra 33,
17 contra 16): são as confirmações dos testes, herdadas da P3\*, que também trazem casos a mais.

**A cobertura não é mérito do coletor.** A P4 cobre 11, 7 e 7 casos, os mesmos da ablação. A
cobertura vem do escopo (todos os CVEs de imagem, inclusive os que o artigo chama de indiretos), e
não do filtro. A parte que vem dos indiretos é coincidência de CWE: contexto, não evidência.

**Lista concreta, TeaStore.** Para liberar o deploy pela P4, o time precisa migrar as duas imagens
base fora de suporte (Debian 10 e Ubuntu 18.04), atualizar 12 dependências da aplicação (por
exemplo `jackson-databind`, `libthrift`, `amqp-client`, `tomcat-coyote`, `log4j`), remover a chave
privada versionada e o dump com hashes bcrypt, e corrigir o reset do banco sem autenticação.
Enquanto a migração não acontece, 25 pacotes fonte de SO carregados ficam na lista. `curl`,
`perl`, `gnupg`, `expat`, Heimdal e as demais ferramentas que nenhum processo executa saem dela,
com declaração VEX. **No Juice Shop**, as 43 ocorrências do `vm2` com nota ≥ 7 viram uma ação só,
atualizar o `vm2`. O Trivy lista versões corrigidas para quase todos os CVEs (até a 3.12.2); só um
não tem correção listada, e por isso a ação aparece marcada como "sem correção" em
`results/p4_acoes.csv`.

### Achado exploratório — em ações, a P3 do artigo não reduz trabalho

*Não estava entre as perguntas registradas e depende da definição de ação da seção 4. Fica como
exploratório.* Em ações, **P2, P3 e A2 exigem o mesmo trabalho nos três alvos** (87, 81 e 46). A P3
deixa de bloquear as unidades indiretas, mas os mesmos CVEs continuam dentro do agregado de
"pacotes com correção" de cada imagem, que bloqueia pelo máximo. Para tirar o agregado do bloqueio,
é preciso corrigir todos os seus membros com nota ≥ 7, inclusive os indiretos. No TeaStore, 100 das
139 unidades da P3 viram **uma** ação (`detected-bcrypt-hash` em `setupData.sql`).

O alcance do achado é limitado. Ele mostra que a redução de 30% a 68% da P3 é de **alertas
bloqueantes a triar**, que é o que o artigo conta, e não de **trabalho de correção**. A redução de
alertas pode ter valor próprio (menos ruído para quem triagem), e o artigo não afirma redução de
trabalho.

**O achado depende da agregação do Trivy.** Ele vale com o agregado pelo máximo, que é a regra do
artigo. Com a média (variação já calculada em `results/alvos_trivy_agregacao.csv` e
`results/sensibilidade_trivy_agregacao.csv`), os agregados de imagem deixam de bloquear na P3 nos três
alvos (o Build da P3 cai de 3, 21 e 2 bloqueios para 0), enquanto a P2 continua bloqueando os
indiretos individuais. Aí a P2 passa a exigir mais ações que a P3. Por isso o achado não entra nas
conclusões principais.

### Critérios registrados

| Critério | Resultado |
|---|---|
| S1: ≥ 20% dos CVEs de imagem distintos fora do bloqueio em ≥ 2 de 3 alvos | **Falha.** Só o TeaStore passa (43,9%); DVWA 18,8% e Juice Shop 18,1% |
| S2: menos ações de pacote de imagem que a ablação em ≥ 2 de 3 alvos | **Passa como registrado** nos 3 (54 → 39, 77 → 37, 39 → 33). Descontada a migração de SO (desconto definido depois do registro), só o Juice Shop reduz |
| S3: nenhum caso da P3\* perdido | **Passa** nos 3 |
| S4: o Trivy oficial suprime exatamente o que o VEX declara | **Passa.** Trivy 0.69.3 (imagem fixada por digest), com e sem VEX na mesma execução: TeaStore webui, 181 de 550 achados suprimidos, todos declarados e nenhum a mais; Juice Shop, 38 de 363. Testado em 2 das 9 imagens; as outras 6 do TeaStore e a da DVWA não passaram pelo Trivy com VEX |
| S5: zero falsos negativos confirmados | **Falha** na definição registrada (abaixo) |

### Correções pós-registro (todas reportadas; a P4-reg mostra o efeito)

1. **Interpretador e executáveis da inicialização (achado pelo S5).** O contêiner de banco do
   TeaStore inicia pelo `docker-entrypoint.sh` (`#!/bin/bash`), e o bash linka `libtinfo.so.5`. O
   bash roda na inicialização e faz `exec` do `mysqld`, então o snapshot não o vê. A regra
   registrada só procurava executáveis citados nos scripts, e não as bibliotecas que eles carregam.
   Com isso, o VEX registrado declarava 3 CVEs do ncurses como fora do caminho de execução. A
   correção conta como carregados o interpretador (linha `#!`), os executáveis citados nos scripts
   de inicialização e as bibliotecas que eles carregam (`ldd` dentro do contêiner). Efeito: TeaStore
   36 → 42 ações (todas absorvíveis pela migração de SO) e 155 → 161 CVEs. Essa correção cobre a
   classe "executável de inicialização", e não só o caso achado.
2. **Imagem distroless (achado na revisão, não pelo S5).** O Juice Shop é distroless, e o dpkg dessa
   imagem guarda a lista de arquivos em `status.d/*.md5sums`, e não em `info/*.list`. O coletor não
   lia esse formato, então nenhum pacote de SO do Juice Shop aparecia carregado, nem `libstdc++6` e
   `libgcc-s1`, que o Node mapeia em memória. Isso é um erro de implementação da regra registrada,
   não uma mudança de definição, e foi corrigido nas duas variantes. Efeito no Juice Shop: na versão
   com o erro (commit `dfa0319`), 40 ações e 116 CVEs; corrigido, 41 e 118. **O S5 não detectaria
   esse erro**, porque depende do mesmo mapa arquivo → pacote.
3. **Um VEX por imagem.** A primeira versão declarava por PURL para o alvo inteiro, mas o mesmo
   pacote pode estar carregado num serviço e não em outro. Agora há uma declaração por imagem, e a
   simulação e o VEX coincidem par a par (teste `test_vex_e_exatamente_o_que_sai_do_bloqueio`).

**Verificação S5, resultado final** (`results/p4_s5.csv`, avaliador único): 21 indícios
examinados. Os 7 de `libtinfo` (1 no banco, 6 nos serviços Java) são falsos negativos confirmados,
resolvidos pela correção 1. Os outros 14 foram julgados improváveis ou não-indícios, com a
justificativa em cada linha: `libidn2`, citado pela glibc (só por `dlopen` para nomes
internacionalizados); `libsepol`, pela libselinux; uma coincidência de nome com `libgmp.so`; e, no
Juice Shop, `require` estático dos 6 módulos npm não carregados, todos de ferramentas de
instalação, build ou desenvolvimento (`node-gyp`, `prebuild-install`, `grunt`, o script `rsn`, os
agentes de proxy `socks`), sem nenhum arquivo importador carregado.

**Reprodutibilidade** (`scripts/comparar_coletas.py`, `results/p4_reprodutibilidade.csv`). Os
registros são pareados pela referência exata ao relatório (aplicação, relatório, resultado, índice),
e não por (pacote, CVE), que é ambíguo quando o mesmo par aparece em várias imagens.

- **Contêineres novos.** Depois da revisão, todos os contêineres foram recriados e a coleta foi
  refeita (`results/contexto_imagem_coleta2.csv`, observações em `pilotos/contexto-acoes-coleta2/`).
  A classificação final é **idêntica nos 5.881 registros**, nas duas definições (registrada e
  corrigida). Os instantâneos individuais variam: no TeaStore, 35 ou 36 registros de até 11 bibliotecas
  Java (`libthrift`, `jackson-databind` e outras) mudam entre S1, S2 e S3. O Java abre e fecha os
  `.jar` sob demanda: no serviço `auth`, a `libthrift` só apareceu depois do tráfego; no
  `persistence`, só antes dele. A união S1 a S3, que é o que a P4 usa, não mudou. Um instantâneo só
  não seria estável.
- **Versão anterior.** O arquivo da versão anterior (`results/contexto_execucao.csv`, outra sessão,
  outros contêineres) tem 268 unidades indiretas; 2 são do Trivy FS, fora do escopo da P4 atual. As
  outras 266 (DVWA 48, TeaStore 185, Juice Shop 33) têm a mesma classificação.
- Antes disso, a coleta tinha sido repetida quatro vezes com os mesmos contêineres, e a P4 com a
  definição registrada deu as mesmas 74 e 36 ações na DVWA e no TeaStore em todas.

### O que não muda

- **O veredito de deploy continua "bloqueado" nos três alvos**, em todas as políticas.
- Carregado não é explorável. Na auditoria anterior, 8 de 10 pares carregados não eram aplicáveis.
- O coletor observa sem login na DVWA e no TeaStore, e o Trivy FS fica fora do filtro.

### Conclusão

O que esta versão sustenta com evidência:

1. **Triagem de imagem verificável.** O coletor tira do bloqueio, com declaração VEX, de 18% a 44%
   dos CVEs de imagem com nota ≥ 7. Nas 2 imagens testadas, o Trivy oficial consome essas
   declarações sem diferença. É a parte implantável da proposta: não depende da matriz e se integra
   ao scanner que o pipeline já usa.
2. **Redução de trabalho num alvo só.** No Juice Shop, que roda sobre SO com suporte, são 6 ações a
   menos (−13%). Na DVWA e no TeaStore, a migração obrigatória do SO absorve toda a redução.
3. **Achado exploratório sobre o artigo.** Em ações de correção e com o agregado do Trivy pelo
   máximo, P2 e P3 são iguais nos três alvos. Com a média, não.

A cobertura igual à da P2 não está nessa lista: ela vem do escopo, e a ablação sem coletor já a tem.

O que não se sustenta: uma "redução de 17% a 55% do trabalho" (a versão anterior deste texto)
conta como trabalho separado atualizações que a migração de SO absorve, e o critério de magnitude
(S1) falhou em dois alvos.
