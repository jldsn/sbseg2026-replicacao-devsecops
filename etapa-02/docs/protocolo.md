# Protocolo e resultados da Etapa 02

## Pergunta e métricas

Quanto a cobertura bloqueante e o volume de bloqueios mudam quando variamos a nota proxy, o limiar e a granularidade? Uma confirmação HTTP dirigida consegue suprir lacunas de evidência direta úteis para a P4?

Uma ocorrência é um registro de um scanner. Uma unidade de avaliação é o objeto que recebe uma decisão, inclusive um agregado quando previsto. A contagem de bloqueios soma unidades que disparariam a regra no seu estágio, sem interromper a avaliação nos estágios seguintes. Mede decisões simuladas sobre relatórios completos. A cobertura bloqueante é a quantidade de IDs de vulnerabilidade com pelo menos uma unidade bloqueada, dividida pelo número de IDs no escopo. A cobertura de detecção usa qualquer sinal. A cobertura direta usa pelo menos uma associação direta. As três métricas ficam separadas. Mede-se cobertura da referência delimitada. Precisão, recall global, tempos de triagem e redução de risco requerem validação adicional.

## Conjuntos e políticas originais

- Relatórios históricos da DVWA em nível baixo, artefato dos autores no commit `5b18244126350d1a6a4bf39e7a34701af9190563`. Foram processadas 1.750 ocorrências brutas, 1.575 de Trivy Container. O baseline tem 226 unidades, das quais 58 diretas, 48 indiretas e 120 sem matriz.
- A matriz contém 13 IDs no escopo. Outdated OS e Outdated Packages compartilham CWE-1104 e têm IDs e critérios estruturais distintos. A classe global é direta se houver pelo menos um vínculo direto. Se todos os vínculos forem indiretos, a classe global é indireta. A cobertura considera os vínculos da unidade bloqueada, com deduplicação pelo ID da vulnerabilidade.
- P1 é uniforme com limiar 9. P2 é uniforme com limiar 7. P3 usa limiar 7 e elegibilidade para diretas e sem matriz. Os limites são inclusivos. O script original trata ausência de score como zero para a decisão. São preservadas as regras específicas de associação dos autores.
- O baseline foi executado com a suíte dos autores e conferido com a referência publicada e com a evidência da Etapa 01 do grupo. Os CSVs foram derivados dos mesmos JSONs pelo novo script, usando os carregadores e a classificação auditados.

## Cenários

| Estudo | Condição | Linhas |
|---|---|---:|
| Proxy principal | Semgrep ERROR 5, 6, 7, 7,5, 8, 9 e 10. P1, P2, P3 nas regras originais | 21 |
| Proxy secundário | Semgrep WARNING 5, 6, 7, 8 e 9. ERROR em 7,5 e regras originais | 15 |
| Limiar | Uniforme e progressiva sob o mesmo limiar 5, 6, 7, 8 ou 9. ERROR em 7,5 | 10 |
| Grade | Nota ERROR × limiar comum × duas regras | 70 |
| Agregação original | Máximo, média e mediana em cada um dos três grupos, para P1, P2 e P3 | 9 |
| Trivy individual | As 1.575 ocorrências entram em Build individualmente e os três agregados saem | 3 |
| Leitura alternativa de ZAP Active | Nível textual convertido pelo mesmo mapa usado no Baseline | 3 |
| Aplicações-piloto | Regras originais e limiares comuns de 5 a 9 em cada recorte de três casos | 26 |

Proxy e limiar são variáveis independentes. Mudar a nota no pós-processamento pode mover achados através de um limiar, sem alterar o relatório ou a detecção do scanner. Os 51 achados ERROR estão no Commit. P2 e P3 só ganham esses 51 bloqueios quando a nota alcança 7. P1 os ganha quando alcança 9. Em P3, os casos com cobertura bloqueante passam de quatro para oito quando a nota cruza 7.

A perda de cobertura da progressiva em relação à uniforme é de 3, 4, 3, 2 e 1 vulnerabilidades, respectivamente entre os limiares 5 e 9 na DVWA. Os limiares 6 e 7 dão os mesmos 56 bloqueios e 8/13 na progressiva, enquanto a uniforme cai de 103 e 12/13 para 80 e 11/13. O grupo precisa definir a margem aceitável de perda antes de extrapolar a comparação. Os dados atuais sustentam uma análise descritiva.

## Verificações que afetam a interpretação

**IDs da diferença P2–P3.** Na base dos autores, com limiar 7, os três IDs cobertos só por P2 são CSRF, Weak Session IDs e Exposed MySQL. Open HTTP Redirect tem oito sinais indiretos, todos abaixo de 7, e permanece sem bloqueio em P2 e P3. A Seção 6.4 do artigo lista Open HTTP Redirect nessa diferença. A nova análise preserva o baseline numérico e apresenta a divergência por ID. Exposed MySQL tem sinais diretos abaixo do limiar e sinais indiretos que acionam P2.

**Agregação.** O grupo Outdated OS usa todas as 1.575 ocorrências quando há contexto EOSL. O grupo Outdated Packages usa as 1.380 com versão corrigida informada. O terceiro usa as 1.527 sem correspondência de CWE com a aplicação. Há sobreposição e as contagens de membros dos grupos têm finalidades próprias. Cada uma das três unidades conta uma vez por política. Valores ausentes são excluídos das estatísticas. Os máximos são todos 9,8. As médias ficam pouco abaixo de 7. Ao usar média, P3 passa de 56 para 53 e de 8/13 para 6/13. Com mediana, P3 permanece no baseline e P1 perde as duas coberturas estruturais. O cálculo usa a precisão completa da média.

**Todas as ocorrências individuais.** Esse cenário muda a unidade de contagem, chegando a 1.750 unidades. A cobertura estrutural dos dois agregados antigos deixa de ser representada. A associação das ocorrências do container fica restrita a CWEs APP. Os bloqueios são 272, 891 e 867 para P1, P2 e P3. As coberturas bloqueantes da matriz original são 1/13, 9/13 e 6/13, com dois casos estruturais indisponíveis nesse cenário. A contagem de bloqueios e o denominador de unidades precisam ser lidos em conjunto.

**Leitura do ZAP ativo na DVWA.** O JSON histórico traz categorias de risco em texto. O código original tenta converter `risk` em inteiro e as 14 unidades ativas ficam sem score. A variação diagnóstica converte High, Medium, Low e Informational para 7,5, 5,0, 3,0 e 0,0. P2 e P3 ganham um bloqueio no Deploy, sem alteração na cobertura bloqueante de nenhuma das três políticas. A versão histórica e a variação ficam em saídas distintas.

## Sensibilidade de todas as notas proxy

O script `scripts/sensibilidade_proxies.py` lê apenas `data/normalized/dvwa.json` e varia todos os mapeamentos arbitrários do script original, não só o Semgrep. Cada grupo muda inteiro, como mudaria o mapa de severidade.

| Grupo | Unidades | Nota base | Origem da nota |
|---|---:|---:|---|
| Semgrep ERROR | 51 | 7,5 | Rótulo do scanner, mapa fixo |
| Semgrep WARNING | 26 | 5,0 | Rótulo do scanner, mapa fixo |
| Checkov | 63 | 5,0 | **Nenhuma.** O JSON bruto traz `severity: null` nas 63 reprovações e o código aplica `MEDIUM` por padrão |
| ZAP Baseline Medium | 5 | 5,0 | `riskcode` 2, mapa fixo |
| ZAP Baseline Low | 7 | 3,0 | `riskcode` 1, mapa fixo |
| Brute Force e Default Credentials | 2 | 7,5 | Valor fixo no código do teste customizado |

Saídas. `sensibilidade_proxies_individuais.csv` (cada grupo de 3 a 10, P1–P3), `sensibilidade_tornado.csv` (cada grupo em base − 2 e base + 2, os demais fixos), `sensibilidade_monte_carlo_resumo.csv` e `sensibilidade_monte_carlo_distribuicao.csv` (10.000 sorteios independentes por cenário, semente 20261122). Gráficos `figures/dvwa_tornado_proxies` e `figures/dvwa_monte_carlo_reducao`.

**Resultados.**

- Checkov é a maior nota arbitrária em volume. Em 7, P2 vai de 80 para 143 bloqueios e P3 de 56 para 119, com a cobertura de P3 passando de 8 para 9/13 (Exposed MySQL). A redução de P3 frente a P2 cai para 24/143 = 17%.
- Com o teste de credenciais abaixo de 7, P3 perde Brute Force e Default Credentials e fica em 6/13.
- A redução de 30% do artigo é um ponto de uma faixa. Variando uma nota por vez em ± 2, ela vai de 17% (Checkov em 7) a 83% (Semgrep ERROR em 5,5).
- Na variação conjunta com todas as notas em base ± 2, 62% das amostras ficam em 30–31% e 38% em 83–89%. Só os dois grupos de base 7,5 (Semgrep ERROR e teste de credenciais) cruzam o corte 7 com probabilidade positiva. O pico de 89% (P2 27, P3 3) ocorre quando ambos ficam abaixo de 7. Os grupos de base 5 só alcançam 7 no extremo da faixa; cerca de 0,2% dos sorteios caíram exatamente em 7,00 após o arredondamento e produzem os valores isolados de 17% a 29%, que são artefato de borda.
- Com todas as notas entre 1 e 10, a redução vai de 13% a 89%, com mediana 30%, e só 24% das amostras ficam entre 25% e 35%.
- A distribuição é bimodal porque os 51 alertas ERROR cruzam o corte 7 juntos.
- O resultado qualitativo resiste. Em todas as 20.000 amostras, P3 bloqueia menos que P2 e perde de 2 a 5 casos de cobertura bloqueante. O que não resiste é a magnitude.

A amplitude ± 2 e a faixa 1–10 são escolhas do grupo. Os sorteios são independentes entre grupos e não impõem ERROR ≥ WARNING.

## Política P4 proposta

> **Atualização (22/11/2026):** a proposta do grupo passou a ser a **P4 orientada a ações, com contexto de execução** ([`p4-acoes.md`](p4-acoes.md)); a versão intermediária, só sobre indiretos, está em [`p4-contexto.md`](p4-contexto.md). A política descrita nesta seção (confirmação dirigida) é mantida como registro e passa a ser lida como **P3\***: o Deploy Gate do artigo efetivamente executado, com testes customizados benignos.

1. Rodar a P2 e a P3 com limiar 7 sobre as unidades originais.
2. Entra na fila de teste dirigido todo ID sem bloqueio em P3 que atenda a um dos critérios. **apenas_indireta**: só há sinais indiretos (critério da primeira versão). **perda_p2_p3**: o ID é bloqueado em P2 e deixa de ser em P3, mesmo havendo sinal direto abaixo do limiar. Na DVWA, a fila tem CSRF, Weak Session IDs e Open HTTP Redirect pelo primeiro critério e Exposed MySQL pelo segundo. Com isso, toda perda de cobertura de P2 para P3 passa pela fila.
3. Guardar o estado `confirmada`, `nao_confirmada`, `inconclusiva` ou `nao_executada`, com configuração, referência e hash da evidência quando houver teste. Uma execução inconclusiva permanece visível para triagem.
4. **P4 (proposta, antes chamada P4-A).** Somar uma decisão de bloqueio no Deploy por confirmação nova, vinculada ao ID da matriz. **Análise de sensibilidade, não variante da proposta — P4-B.** Exigir também nota CVSS v3.1 do caso confirmado igual ou superior a 7. A nota sai do vetor registrado em `validacoes.csv` (`scripts/cvss31.py`), não da CVE de origem. **P4-B-alt** repete a P4-B com um vetor alternativo, para medir a dependência da escolha do vetor.
5. A confirmação é feita por um catálogo de testes benignos escolhidos pelo CWE (`scripts/p4_catalogo.py`), cada um com controle negativo; XSS e testes com efeito de DoS ficam fora. Em implantação real, definir o catálogo de testes por versão, tempo limite, responsáveis e comportamento diante de indisponibilidade. O simulador modela decisões de portão. A integração com um pipeline operacional é uma tarefa posterior.

**Vetores propostos (a ratificar pelo grupo).**

| Caso | Vetor principal | Nota | Vetor alternativo | Nota |
|---|---|---:|---|---:|
| CSRF | `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`. A troca forjada define uma senha conhecida pelo atacante, o que leva à tomada da conta | 8,1 | `C:N/I:H/A:N`. Conta só a alteração demonstrada | 6,5 |
| Weak Session IDs | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`. A evidência se limita ao cookie de treino `dvwaSession`, que não autentica | 5,3 | `C:H/I:H/A:N`. Trata o cookie como identificador de sessão real | 9,1 |

**Resultados na DVWA.** P3 56 e 8/13. P4-A 58 e 10/13 (CSRF e Weak Session IDs). P4-B 57 e 9/13 (CSRF). P4-B-alt 57 e 9/13 (Weak Session IDs). Com os dois vetores, P4-B acrescenta um caso, mas um caso diferente em cada vetor, então a escolha do vetor decide qual lacuna é fechada. P2 tem 80 e 11/13 como referência. O máximo condicional da P4-A, com as quatro lacunas confirmadas, é 60 bloqueios e 12/13, acima da cobertura de P2 com 20 bloqueios a menos (`results/p4_cenarios_condicionais.csv`).

**P4 contra alternativas simples (protocolo registrado antes, `docs/p4-avaliacao.md`).** A P4 recupera 4 dos 10 casos que a P3 perde com 2,4% dos bloqueios extras que a P2 exigiria. Em cobertura bruta, nenhum ajuste simples de limiar (P3 com limiar 6, P3 + indiretos ≥ 9, P2 com limiar 8) a domina na DVWA e no Juice Shop; no TeaStore, a P2 com limiar 8 a domina (82 e 5/14 contra 140 e 5/14), trocando casos com evidência direta por casos só indiretos. O que os ajustes de limiar não fazem é bloquear com evidência de que a falha existe no sistema implantado: a P3 + indiretos ≥ 9 "cobre" `ts-tls-trust-all`, que não roda na implantação de referência. A regra registrada (nenhuma alternativa domina a P4 em cobertura sustentada) se cumpre, mas é quase garantida pela definição da métrica e não é a evidência principal. Um catálogo de testes benignos com controles negativos (`scripts/p4_catalogo.py`) confirma automaticamente 4 dos 11 casos da fila (36%). Detalhes, tabela completa e desvios: `docs/p4-avaliacao.md`.

**Pendências da fila.**

- **Exposed MySQL (`nao_executada`).** Os 11 sinais "diretos" do artigo vêm do Checkov: `CKV_K8S_29/30/31/38` (contexto de segurança e token de service account nos Deployments `mysql` e `dvwa-app`), `CKV_GCP_21` (labels do cluster) e `CKV_GCP_62` (log de acesso a buckets). Nenhuma dessas verificações testa a exposição do MySQL, o que enfraquece a classificação direta desse caso. O teste comportamental é tentar conexão TCP e autenticação na porta 3306 de fora da fronteira da aplicação. Ele exige reproduzir o Service do manifesto `k8s/mysql.yaml` dos autores, que não foi publicado no artefato. Um `docker run` local que publica só a porta 80 daria `nao_confirmada` por construção, sem informação sobre o ambiente do artigo.
- **Open HTTP Redirect (`inconclusiva`).** O relatório Semgrep dos autores contém caminhos `vulnerabilities/open_redirect`, `api`, `bac` e `cryptography`, módulos do código atual da DVWA. Na imagem histórica testada, as duas rotas de redirecionamento sondadas responderam HTTP 404 (as demais não foram sondadas). Isso indica que o SAST do artigo pode ter analisado uma versão do código diferente da imagem implantada. Para fechar o caso, listar a árvore da imagem fixada: `docker run --rm --entrypoint ls vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7 /var/www/html/vulnerabilities`. Se o módulo não existir, registrar `nao_confirmada` com esse laudo.

## Outras aplicações

O recorte em Juice Shop e WebGoat foi definido com casos localizáveis no código de cada release. A matriz exploratória tem três entradas por alvo. A classificação de SAST exige o arquivo do caso e o CWE correspondente. O ZAP ativo exige endpoint e CWE. Uma ocorrência do Trivy de imagem com CWE coincidente produz vínculo indireto. As demais ocorrências de Trivy são condensadas em uma unidade sem matriz, com CVSS máximo. Para cada caso, classifica-se o vínculo por estágio, com a mesma precedência global. A simulação conta Semgrep, Trivy Image e ZAP ativo. Checkov Dockerfile, Trivy FS e ZAP passivo testam viabilidade operacional. A íntegra do pipeline histórico requer infraestrutura comparável e uma matriz independente e mais abrangente.

Em limiar 7, no recorte do Juice Shop, a progressiva reduz 10 para 8 bloqueios e 2/3 para 1/3 de cobertura bloqueante. No WebGoat, as duas regras ficam em 15 bloqueios e 1/3. Os pilotos usam conjuntos de regras adaptados à linguagem, versões fixadas e um ZAP ativo de duas regras sobre uma rota por aplicação, sem login. As diferenças mostram sensibilidade ao contexto do piloto. A magnitude entre aplicações depende do escopo, da imagem e do número de regras e rotas.

## TeaStore e Juice Shop (alvos pedidos pelo professor)

O professor pediu dois alvos adicionais: **TeaStore** (`DescartesResearch/TeaStore`, tag `v1.4.2`, commit `14648b79406db9be0cbbbc1620dd6a688b74109c`) e **Juice Shop** (`juice-shop/juice-shop`, tag `v19.0.0`, commit `36870cbbdfe7864698e1adf644c7bf772f67ebb7`), este substituindo o piloto reduzido da Etapa 02. O script `scripts/analise_alvos.py` aplica o mesmo modelo direto/indireto, P1–P3, sensibilidade, agregação do Trivy e fila da P4 aos dois, lendo `data/ground_truth/teastore.csv` e `data/ground_truth/juice-shop.csv` (14 casos cada, contra os 3 do piloto anterior). O TeaStore é relevante por não ser uma aplicação feita para ser vulnerável, o que ataca diretamente a maior ameaça à validade externa do artigo original.

**Regra única de escopo.** Entra na análise só o código e os artefatos da implantação de referência de cada projeto. Ficam fora: no TeaStore, `e2e-tests/` (harness de teste, não implantado) e os utilitários `kieker` (usados só no compose de monitoramento, fora do manifesto `examples/kubernetes/teastore-clusterip.yaml`); no Juice Shop, arquivos `*.spec.ts` (testes) e `frontend/src/assets/private/` (biblioteca `three.js` de terceiros, vendorizada). Essa exclusão derrubou os bloqueios da P3 do Juice Shop de 14 para 9 e a cobertura de 4/14 para 3/14, então a regra importa para o resultado.

**Ferramentas por alvo.** TeaStore: Semgrep (regras Java de lang/Spring/Servlets/JAX-RS/segredos, commit `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2` do `semgrep-rules`), Trivy FS sobre os `pom.xml`, Checkov sobre `examples/kubernetes/teastore-clusterip.yaml` e os 7 Dockerfiles de serviço, Trivy Image nas 7 imagens publicadas (`descartesresearch/teastore-*:1.4.2`). ZAP 2.17.0 **somente passivo** (spider de até 2 minutos + regras passivas, sem autenticação) sobre os 7 serviços em Docker local (`ambientes/teastore/docker-compose.yaml`, imagens fixadas por digest, portas só em `127.0.0.1`), via `scripts/zap_passivo_docker.py`; 29 URLs, 532 instâncias, 12 tipos de alerta (`pilotos/zap/teastore-*.json`). **Não houve ZAP ativo no TeaStore** (no Juice Shop houve, com 2 regras): o escaneamento ativo dispara payloads de ataque, o que este projeto deixa para execução manual (ver `limitacoes-assistente.md`). As rotas DAST de `ts-cookie-flags` (`/loginAction`) e `ts-output-encoding` (`/profile`) foram fixadas por leitura de código e commitadas **antes** da coleta (commit `66ba136`), para não repetir a circularidade descrita abaixo. Juice Shop: reaproveita o Trivy Image, Checkov e ZAP do piloto da Etapa 02 e roda o Semgrep de novo com **todas** as regras JavaScript/TypeScript de segurança do mesmo commit de regras, não só as 3 usadas no piloto (61 → ver `coletas/juice-shop/semgrep.json`).

**Matriz de referência.** As 14 entradas de cada alvo (`data/ground_truth/{teastore,juice-shop}.csv`) vieram de revisão de código e, no Juice Shop, dos marcadores `vuln-code-snippet` que o próprio projeto usa para localizar seus desafios oficiais (`routes/*.ts`, `server.ts`, `lib/insecurity.ts`). **Ressalva de circularidade:** as listas de CWE de alguns casos foram ajustadas depois de ver as primeiras coletas, para refletir o rótulo que cada ferramenta de fato emite (por exemplo `js-access-log` e `js-reflected-xss` ganharam um segundo CWE, e `ts-output-encoding`/`ts-cookie-flags` usam o CWE que o Semgrep reporta). Isso não é diferente do artigo original, que também declara a matriz a partir do conhecimento prévio da aplicação, mas enfraquece a independência da matriz como oráculo. `results/alvos_robustez_cwe_primario.csv` reavalia os dois alvos usando só o primeiro CWE de cada caso, como checagem de robustez: a P3 fica em 139 bloqueios e 4/14 no TeaStore e em 9 bloqueios e 3/14 no Juice Shop, os mesmos números da matriz com todos os CWEs — o resultado agregado (bloqueios e cobertura da P3) não depende de ter incluído o segundo CWE desses casos, embora os IDs individuais cobertos mudem de posição em P1 e P2. Qualquer achado específico de um ID deve ser conferido contra `data/ground_truth/*.csv` antes de ser citado como decisivo.

**Resultados (`results/alvos_politicas.csv`, `results/alvos_composicao.csv`).**

| Alvo | Unidades | Diretas | Indiretas | P1 | P2 | P3 | Cobertura P2 | Cobertura P3 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| TeaStore | 729 | 337 | 187 | 32 | 262 | 139 | 7/14 | 4/14 |
| Juice Shop | 83 | 17 | 33 | 12 | 28 | 9 | 7/14 | 3/14 |

A redução da P3 frente a P2 é de 47% no TeaStore e 68% no Juice Shop, maior que os 30% da DVWA no artigo, mas **o resultado qualitativo se repete num alvo que não foi construído para ser vulnerável**: a P3 bloqueia bem menos e perde cobertura (de 7/14 para 4/14 no TeaStore, de 7/14 para 3/14 no Juice Shop). Duas ressalvas específicas do TeaStore: (1) o Deploy Gate agora existe (ZAP passivo, 12 unidades), mas nenhum alerta passa do limiar 7 (os mais altos são Medium, nota proxy 5,0), então P1–P3 não mudam em relação à coleta sem Deploy e toda a diferença continua em Commit e Build. O ZAP acrescenta uma detecção direta (`ts-cookie-flags`, `Cookie No HttpOnly Flag` em `/loginAction`; o cookie alertado ali é `teastoreErrorMessageCookie`, criado pelo mesmo `AbstractUIServlet`; o `sessionBlob` aparece sem HttpOnly em `/cartAction`, rota não pré-registrada). O alerta `Absence of Anti-CSRF Tokens` (CWE-352) aparece em `/login`, a página que contém o formulário, e não em `/loginAction`, a rota registrada para `ts-csrf` — pela regra pré-registrada o vínculo não é feito e o caso continua não detectado; a rota não foi corrigida depois de ver o alerta; (2) 100 dos 139 bloqueios da P3 vêm de uma única regra do Semgrep (`detected-bcrypt-hash`, que dispara uma vez por linha do dump SQL `setupData.sql`), então o número de bloqueios é dominado por um artefato de como a regra conta ocorrências, não por 100 falhas distintas.

**Sensibilidade e agregação.** `scripts/analise_alvos.py` repete a varredura da DVWA (grupos de nota, tornado, Monte Carlo com 5.000 amostras, agregação do Trivy por máximo/média/mediana, mais uma variante nova — agregação por sistema inteiro em vez de por imagem). No cenário ± 2, a redução de P3 frente a P2 some entre 26% e 76% no TeaStore e entre 32% e 90% no Juice Shop; **a mediana coincide com a base no TeaStore** (os dois grupos de nota perto de 7 — Semgrep ERROR e Semgrep WARNING — dominam a amostra) pelo mesmo motivo de artefato de borda já documentado para a DVWA, enquanto no Juice Shop a mediana (70%) já se desloca da base (68%) porque mais grupos cruzam o limiar dentro de ± 2. A faixa do cenário amplo (1 a 10) é mais representativa: 19–76% no TeaStore, 28–90% no Juice Shop.

**Fila da P4.** `scripts/analise_alvos.py` aplica a mesma regra da DVWA (entra na fila todo caso sem bloqueio em P3 que só tem sinal indireto ou que a P2 bloqueava). No TeaStore, a fila (`results/alvos_p4_fila.csv`) tem três casos. **`ts-db-reset-unauth` foi confirmado** (`pilotos/p4-teastore/`): durante a coleta passiva, o próprio spider do ZAP, sem cookie nem autenticação, submeteu o formulário público de `/database` com os valores padrão; a resposta foi 302 para `/status` (ramo de sucesso do `DataBaseActionServlet`) e o log do webui registrou `DB is re-generating`. Nenhuma requisição foi montada à mão e nenhuma carregava payload de ataque. Vetor proposto AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H (9,1; apaga e regenera todos os dados) e alternativo C:N/I:L/A:L (6,5; dados sintéticos e regeneráveis). Resultado: P4-A e P4-B ficam em **140 decisões e 5/14**; P4-B-alt fica em 139 e 4/14. `ts-output-encoding` (XSS armazenado, confirmado por leitura de código) e `ts-tls-trust-all` (só ativo com `USE_HTTPS=true`, ausente da implantação de referência) ficam `nao_executada`: o primeiro exige enviar um payload de XSS (manual), o segundo não é exercitável na configuração de referência. No Juice Shop, uma instância local foi testada (ver `pilotos/p4-juice-shop/`): o caso `js-exposed-metrics` (métricas Prometheus sem autenticação) foi confirmado por um GET simples em `/metrics`, validado de forma independente pelo placar oficial de desafios da própria aplicação (`/api/Challenges?key=exposedMetricsChallenge`, que muda de não resolvido para resolvido). Isso adiciona 1 bloqueio no Deploy: P4-A fica em 10 decisões e 4/14 de cobertura (`results/alvos_p4_resultados.csv`). Com o vetor CVSS principal do caso (5,3, pela baixa confidencialidade exposta), a P4-B não adiciona o bloqueio; com o vetor alternativo (tratando a métrica como mais sensível), adiciona.

**Caso não testado por decisão do grupo — `js-rce-b2b`.** A fila também inclui a execução de código no endpoint `/b2b/v2/orders` (desafio oficial `rceChallenge`, confirmado pelo próprio Semgrep via `unsafe-dynamic-method` em `routes/b2bOrder.ts`, que entrega a entrada do cliente a um `vm.runInContext`). O teste dirigido que confirmaria esse caso reproduziria o próprio ataque documentado pelo projeto (um payload de laço não controlado para exercitar o limite de tempo do avaliador), o que tem efeito de negação de serviço sobre o processo-alvo mesmo numa instância local descartável. O grupo decidiu não automatizar esse teste e registra o caso como `nao_executada` em `pilotos/p4-juice-shop/validacoes.csv`, apoiado só na evidência estática do Semgrep e na evidência indireta do Trivy. Os dois casos de XSS (`js-dom-xss`, `js-reflected-xss`) exigem um navegador real e ficam para verificação manual (ver `docs/pilotos.md`).

**Achado positivo sobre o TeaStore.** Ao contrário da suspeita levantada para a matriz da DVWA (Seção anterior, Open HTTP Redirect), aqui as tags `1.4.2` e `latest` do Docker Hub apontam para o mesmo digest em todas as 7 imagens (conferido via `registry-1.docker.io`), e a cadeia de Dockerfiles (`teastore-webui` → `teastore-base:latest` → `tomcat:10.0.7-jdk11`) é consistente com o SO Debian 10.10 (EOSL) que o Trivy reporta nas imagens. Não há indício de descompasso entre código e imagem neste alvo.

**Pendências (ver `limitacoes-assistente.md`, seção 8, para o impacto de cada uma):**
- Verificação manual no navegador do XSS armazenado do TeaStore (`ts-output-encoding`) e dos dois XSS do Juice Shop.
- ZAP ativo no TeaStore, se o grupo quiser simetria com o Juice Shop (execução manual).
- `ts-tls-trust-all`: só testável numa variante com `USE_HTTPS=true`, fora da implantação de referência; o grupo decide se vale a pena.

## Decisões para o grupo

- (Superado: refere-se à P4 de confirmação dirigida, hoje P3\*) Ratificar P4-A e os vetores CVSS de CSRF e Weak Session IDs usados por P4-B e P4-B-alt.
- Ratificar a P4 orientada a ações ([`p4-acoes.md`](p4-acoes.md)) como a proposta do grupo, incluindo: medir em ações de correção, declarar os não carregados por VEX com reavaliação pelo Runtime Watch, e as três correções pós-registro (inicialização, distroless, VEX por imagem).
- (Superado) Ratificar a P4 com contexto de execução só sobre indiretos.
- (Anterior, superado) Ratificar a P4-A como "a P4" proposta, com a P4-B só como análise de sensibilidade, e a métrica de cobertura sustentada (ver `docs/p4-avaliacao.md`).
- (Superado, idem) Ratificar o vetor do `ts-db-reset-unauth` (TeaStore): proposto C:N/I:H/A:H (9,1, bloqueia na P4-B) contra alternativo C:N/I:L/A:L (6,5, não bloqueia). A escolha decide se a P4-B do TeaStore fica em 140 e 5/14 ou em 139 e 4/14.
- Rodar a listagem da imagem para o Open HTTP Redirect e decidir se o Exposed MySQL será testado em um cluster que reproduza o manifesto dos autores.
- Fixar o orçamento de cobertura aceitável antes de interpretar uma comparação confirmatória. Adotar um denominador auditado e justificar a margem em número de casos e pontos percentuais.
- Definir cenários equivalentes entre aplicações, ampliar o conjunto versionado de casos e confirmar cada vínculo relevante diretamente no artefato ou no laboratório.
- Divisão sugerida. Uma pessoa amplia a matriz e revisa associações. Outra configura autenticação e padroniza a coleta. A terceira integra políticas e análise. Revisão cruzada do artigo e dos slides.
