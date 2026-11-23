# Registro de mudanças em relação ao repositório original do grupo

Este documento lista **tudo o que mudou** no branch `etapa-02-conclusao` em relação ao
`main` do repositório do grupo (`jldsn/sbseg2026-replicacao-devsecops`, commit `fa32bd1`,
"Adicionar resultados e evidências da Etapa 02"). Ele serve para revisar o Pull Request
antes do merge. Se este documento e o `git diff` divergirem, vale o `git diff`:

```bash
git diff --stat fa32bd1 etapa-02-conclusao
```

As mudanças foram feitas com um assistente de IA (Claude) em 22/11/2026, em sessões
supervisionadas por Ayrton. Cada commit termina com a linha `Co-Authored-By: Claude`.

## 1. O que **não** mudou

Isto é o que garante que a reprodução original continua de pé:

| Item | Situação |
|---|---|
| `etapa-01/` (reprodução das Tabelas 3, 4 e 5 do artigo) | **Intocado** |
| `etapa-02/scripts/analise_dvwa.py` (P1–P3 sobre a DVWA) | **Intocado** |
| `etapa-02/scripts/resumir_pilotos.py`, `piloto_dast.py`, `validar_dvwa_http.py` | **Intocados** |
| `etapa-02/results/baseline.csv` e os números P1/P2/P3 da DVWA (5/80/56, cobertura 3/13, 11/13, 8/13) | **Intocados** |
| Artefato original dos autores (Machado, Cordeiro e Jandre) | Nunca foi alterado. É clonado à parte, fora deste repositório |
| Laudos HTTP já existentes (`pilotos/p4-dvwa/dvwa-http.json`) | Intocados (o hash continua o mesmo) |

## 2. Commits, em ordem

| Commit | O que fez |
|---|---|
| `9efc0ba` | Sensibilidade de **todas** as notas proxy; P4 ampliada (Exposed MySQL na fila, P4-B por vetor CVSS) |
| `ec3359b` | TeaStore 1.4.2 e Juice Shop 19.0.0: coletas e matriz de 14 casos cada |
| `b2680f5` | P4 ligada aos laudos dos novos alvos, regra de escopo única, checagem de robustez, `js-exposed-metrics` confirmado |
| `43c915d` | Documentos `avancos.md` e `limitacoes-assistente.md` |
| `66ba136` | Rotas DAST do TeaStore registradas **antes** da coleta do ZAP |
| `6a1ba50` | Deploy Gate do TeaStore (ZAP passivo em Docker) e confirmação de `ts-db-reset-unauth` |
| `5cd289c` | Política de uso revalidada nas fontes oficiais; registro de impacto do que não é automatizável |
| `62a8e0b` | Ajustes no registro de impacto; vetor CVSS da P4-B marcado como pendente de ratificação |
| `b6b0c50` | Este documento (`mudancas.md`) |
| `38e6b56` | Protocolo de avaliação da P4 registrado **antes** de calcular (`docs/p4-avaliacao.md`) |
| `0f47772` | P4 comparada com alternativas simples (`scripts/comparar_politicas.py`) |
| `848ce2f` | Catálogo de testes benignos com controles negativos (`scripts/p4_catalogo.py`) |
| `deeda78` | P4-A vira a P4 proposta; P4-B passa a análise de sensibilidade; resultados propagados para os docs |
| `fbd6e9a` | README da raiz com a avaliação da P4 |
| `ce28de8` | Revisão da avaliação: ablação comparável (A4c), laudo do TeaStore congelado, conclusão reescrita |
| `e53635e` | Protocolo da P4 com contexto de execução registrado antes dos resultados |
| `e7721a2` | Coletor de contexto de execução, avaliação da nova P4, P4 anterior rebaixada a P3\*, docs |
| `0e14cf3` | Critérios e sorteio da auditoria manual registrados antes |
| `6a45dfc` | Resultados da auditoria manual (`results/auditoria_amostra.csv`) |
| (último) | Revisão final: coleta refeita em contêineres novos, comparação justa com as alternativas (P3 + carregados), ressalvas sobre agregados de imagem e matriz, instruções de reprodução, sorteio que preserva julgamentos |

## 3. Mudanças em código já existente (atenção na revisão)

### 3.1 `scripts/politica_p4.py` — **muda um resultado da DVWA**

| Antes (`fa32bd1`) | Agora | Efeito |
|---|---|---|
| A fila da P4 aceitava só casos com sinal **apenas indireto** | Também entram casos que P2 bloqueava e P3 deixa de bloquear (`motivo = perda_p2_p3`) | `dvwa-exposed-mysql` entra na fila (12 sinais indiretos, 11 diretos). Ele continua `nao_executada` |
| P4-B usava `score_confirmacao` digitado à mão no laudo, que estava vazio | P4-B calcula a nota CVSS v3.1 a partir do **vetor** registrado no laudo (`vetor_cvss_confirmacao`), com o novo `scripts/cvss31.py`; se alguém digitar uma nota que diverge do vetor, o script recusa | **P4-B da DVWA passa de 56 decisões e 8/13 para 57 e 9/13** (`dvwa-csrf` agora tem nota ≥ 7) |
| Duas variantes (P4-A, P4-B) | Três variantes: nova **P4-B-alt**, com um vetor alternativo, para medir quanto o resultado depende da escolha do vetor | P4-B-alt: 57 e 9/13, mas bloqueando `dvwa-weak-session-ids` em vez de `dvwa-csrf` |
| Limiar 7 repetido no código | Constante `LIMIAR = 7` | Sem efeito no resultado |
| Saída sem referência à P2 | `p4_resultados.csv` ganhou `referencia_p2_bloqueios` e `referencia_p2_cobertura` | Facilita comparar P4 com P2 |

P4-A da DVWA **não mudou** (58 decisões, 10/13).

### 3.2 Formato dos laudos de validação

`data/templates/validacoes_p4.csv` e `pilotos/p4-dvwa/validacoes.csv` ganharam duas
colunas no fim: `vetor_cvss_confirmacao` e `vetor_cvss_alternativo`, além da linha
`dvwa-exposed-mysql` (`nao_executada`). As linhas e os hashes que já existiam não mudaram.
Os **vetores escolhidos para CSRF e Weak Session IDs são propostas** e precisam ser
ratificados pelo grupo (ver `protocolo.md`, "Decisões para o grupo").

### 3.3 `tests/test_analise.py`

Eram 6 testes; agora são 15 (9 em `test_analise.py`, 3 em `test_comparacao.py` e 3 em `test_contexto.py`). O teste da fila foi atualizado para o novo formato (inclui
`dvwa-exposed-mysql` e o motivo). Os três testes novos cobrem o cálculo do CVSS 3.1 com
vetores de referência, a P4-B-alt e os grupos de notas proxy e o tornado. Para rodar,
use Python 3.10 ou superior (o código usa `float | None`):

```bash
python3 -m unittest discover -s etapa-02/tests -v
```

### 3.4 `scripts/gerar_figuras.py`

Duas funções novas, `tornado()` e `distribuicao_monte_carlo()`, que geram
`figures/dvwa_tornado_proxies.{png,pdf}` e `figures/dvwa_monte_carlo_reducao.{png,pdf}`.
As figuras que já existiam não mudaram.

### 3.5 Resultados da DVWA regenerados

`results/p4_fila.csv` e `results/p4_resultados.csv` mudaram de formato e de conteúdo pelos
motivos da seção 3.1. `evidence/p4_execucao.log` registra a nova execução.

## 4. Arquivos novos

### 4.1 Scripts

| Arquivo | Para que serve |
|---|---|
| `scripts/cvss31.py` | Nota base CVSS v3.1 a partir do vetor (implementação da especificação, testada) |
| `scripts/sensibilidade_proxies.py` | Varia cada nota proxy arbitrária da DVWA (Semgrep ERROR/WARNING, Checkov, ZAP Baseline, teste de credenciais), isoladamente (tornado) e em conjunto (Monte Carlo, 10.000 amostras) |
| `scripts/analise_alvos.py` | Aplica o modelo direto/indireto, P1–P3, limiares, sensibilidade, agregação do Trivy e fila da P4 ao TeaStore e ao Juice Shop |
| `scripts/validar_juice_shop.py` | Teste **passivo** do Juice Shop: um GET em `/metrics`, conferido pelo placar oficial de desafios da aplicação |
| `scripts/contexto_execucao.py` | Coletor de contexto de execução: bibliotecas mapeadas, arquivos abertos, scripts de inicialização e módulos Node carregados, por contêiner; classifica cada achado indireto como carregado ou não |
| `scripts/amostra_auditoria.py` | Sorteio estratificado da auditoria manual (semente fixa) |
| `scripts/politica_contexto.py` | Avalia a P4 com contexto de execução contra P2, P3, P3\* e as alternativas de limiar |
| `ambientes/contexto/hook-modulos.js` | Hook de observação de módulos Node, injetado só no contêiner de teste |
| `scripts/comparar_politicas.py` | Compara a P4 com P3 limiar 6, P3 + indiretos ≥ 9, P2 limiar 8 e a fila bloqueada sem teste; métricas de cobertura bruta e sustentada; confere antes que reproduz os números publicados |
| `scripts/p4_catalogo.py` | Catálogo de testes benignos da P4, escolhidos pelo CWE, com controle negativo por modelo |
| `scripts/zap_passivo_docker.py` | ZAP **só passivo** (spider + regras passivas) contra um alvo em Docker; roda em macOS, ao contrário de `piloto_dast.py`, que exige `unshare` do Linux |

### 4.2 Ambiente

| Arquivo | Para que serve |
|---|---|
| `ambientes/teastore/docker-compose.yaml` | Compose de referência do TeaStore 1.4.2 com três mudanças: imagens fixadas por digest, portas publicadas só em `127.0.0.1` (o banco não é publicado) e um serviço ZAP 2.17.0 em modo daemon |

### 4.3 Dados de entrada

| Arquivo | Conteúdo |
|---|---|
| `data/ground_truth/teastore.csv` | Matriz de 14 casos do TeaStore, montada por revisão de código |
| `data/ground_truth/juice-shop.csv` | Matriz de 14 casos do Juice Shop, a partir dos desafios oficiais anotados no código (`vuln-code-snippet`) |
| `coletas/teastore/` | Semgrep, Checkov (Kubernetes + Dockerfiles), Trivy FS e Trivy Image das 7 imagens |
| `coletas/juice-shop/` | Semgrep com todas as regras de segurança JS/TS e a lista de regras usadas |
| `evidence/trivy-db-teastore.json`, `evidence/verificacao_extensao.log` | Versão da base do Trivy e log de verificação da extensão |

**Ressalva de circularidade (já registrada em `protocolo.md`):** os CWEs de alguns casos
foram ajustados depois das primeiras coletas. As rotas DAST de `ts-cookie-flags`
(`/loginAction`) e `ts-output-encoding` (`/profile`) foram fixadas em commit próprio
(`66ba136`) **antes** do ZAP rodar, e a rota de `ts-csrf` não foi corrigida depois de ver
que o ZAP alerta em `/login`.

### 4.4 Evidência dinâmica (P4)

Novos da P4 orientada a ações: `scripts/politica_acoes.py`, `scripts/trivy_vex.sh`, `scripts/validar_vex_trivy.py`, `scripts/verificar_s5.py`, modo `--imagem` de `scripts/contexto_execucao.py` (com leitura do dpkg distroless e das bibliotecas da inicialização), `results/contexto_imagem.csv`, `results/p4_acoes.csv`, `results/p4_acoes_resumo.csv`, `results/p4_vex_trivy.csv`, `results/p4_s5.csv`, `pilotos/contexto-acoes/` (observações, dados da verificação S5 e VEX por imagem) e `tests/test_acoes.py`. Reprodutibilidade com contêineres novos: `scripts/comparar_coletas.py`, `results/contexto_imagem_coleta2.csv`, `results/p4_reprodutibilidade.csv` e `pilotos/contexto-acoes-coleta2/`.

Novos da P4 com contexto (versão anterior): `results/contexto_execucao.csv`, `results/p4_contexto_politicas.csv`, `results/p4_contexto_resumo.csv`, `results/auditoria_amostra.csv`, `pilotos/contexto/` (observações brutas S1–S3 de cada contêiner e S4 autenticado do Juice Shop) e `tests/test_contexto.py`.

Novos também: `pilotos/p4-catalogo/` (saída do catálogo, regravada a cada execução), `pilotos/p4-teastore/catalogo-teastore.json` (cópia congelada usada como laudo), `tests/test_comparacao.py` (3 testes; o total passou de 9 para 12) e `results/p4_comparacao.csv`, `p4_dominancia.csv` e `p4_funil.csv`.


| Arquivo | Conteúdo |
|---|---|
| `pilotos/p4-juice-shop/` | Laudo de `js-exposed-metrics` (confirmado) e `validacoes.csv`; `js-rce-b2b`, `js-dom-xss` e `js-reflected-xss` ficam `nao_executada` |
| `pilotos/p4-teastore/` | Laudo de `ts-db-reset-unauth` (confirmado: o spider do ZAP, sem login, regenerou o banco), log do webui e `validacoes.csv` |
| `pilotos/zap/teastore-passivo.json`, `teastore-resumo.json` | Coleta passiva do ZAP no TeaStore (29 URLs, 532 alertas, SHA-256 no resumo) |

### 4.5 Resultados novos

`results/alvos_*.csv` (políticas, cobertura, composição, limiares, tornado, Monte Carlo,
agregação e composição do Trivy, fila e resultados da P4, cenários condicionais, robustez
com só o CWE primário), `results/sensibilidade_*.csv` da DVWA e
`results/p4_cenarios_condicionais.csv`. Todos são gerados pelos scripts acima.

### 4.6 Documentação

| Arquivo | Mudança |
|---|---|
| `README.md` (raiz) | Tabela de resultados da Etapa 02 com sensibilidade, P4-B e os dois alvos novos |
| `etapa-02/README.md` | Resultados de TeaStore, Juice Shop, notas proxy e P4 |
| `docs/protocolo.md` | Metodologia e resultados dos alvos novos, regra de escopo, ressalvas e decisões pendentes para o grupo |
| `docs/pilotos.md` | Instâncias locais do Juice Shop e do TeaStore, com os comandos |
| `docs/esquema.md` | Esquema dos arquivos `alvos_*` |
| `docs/avancos.md` (novo) | Painel do que está pronto e do que falta |
| `docs/limitacoes-assistente.md` (novo) | O que o assistente pode ou não automatizar, com fontes oficiais e o impacto de cada pendência |
| `docs/mudancas.md` (novo) | Este documento |
| `docs/p4-auditoria.md` (novo) | Auditoria manual estratificada do coletor (critérios registrados antes do sorteio) |
| `docs/p4-acoes.md` (novo) | Protocolo e resultados da P4 orientada a ações (proposta atual) |
| `docs/p4-contexto.md` (novo, substituído) | Protocolo e resultados da P4 com contexto só sobre indiretos |
| `docs/p4-avaliacao.md` (novo, substituído) | Protocolo da avaliação da P4, registrado antes de calcular, e resultados |

## 5. Números que mudaram

| Resultado | Antes (`fa32bd1`) | Agora |
|---|---|---|
| DVWA P1/P2/P3 | 5 / 80 / 56 | **igual** |
| DVWA P3\* (antes P4-A, depois "P4") | 58, 10/13 | **igual** |
| DVWA P4 com contexto de execução (versão anterior) | não existia | 74, 11/13; 8 de 24 indiretos ≥ 7 sobre pacotes não carregados (1 CVE de 9) |
| P4 orientada a ações (atual) | não existia | ações sem coletor → P4: DVWA 89 → 74, TeaStore 82 → 42, Juice Shop 47 → 41; não absorvidas pela migração de SO: 35 → 35, 17 → 17, 47 → 41; CVEs de imagem graves com VEX: 18,8%, 43,9%, 18,1% |
| DVWA P4-B (agora só sensibilidade) | 56, 8/13 | 57, 9/13 (nota calculada do vetor) |
| DVWA P4-B-alt | não existia | 57, 9/13 |
| Pilotos | Juice Shop e WebGoat com 3 casos | WebGoat continua como apêndice; Juice Shop passou a ter 14 casos |
| TeaStore | não existia | 729 unidades; P2 262, 7/14; P3 139, 4/14; P3\* 140, 5/14; P4 com contexto (versão anterior) 167, 7/14 (96 de 123 indiretos ≥ 7 não carregados) |
| Juice Shop (14 casos) | não existia | 83 unidades; P2 28, 7/14; P3 9, 3/14; P3\* 10, 4/14; P4 com contexto (versão anterior) 29, 7/14 (0 de 19 não carregados) |

## 6. O que fica para o grupo decidir antes do merge

1. Ratificar os vetores CVSS propostos (DVWA: CSRF e Weak Session IDs; TeaStore:
   `ts-db-reset-unauth`). Eles decidem os números da P4-B.
2. Aceitar ou não a regra de escopo única (exclui testes e bibliotecas vendorizadas).
3. Revisar a ressalva de circularidade da matriz.
4. Fazer as confirmações manuais de XSS, se quiserem (ver `limitacoes-assistente.md`, seção 8).
