# Esquema e proveniência

## Camadas de arquivo

| Camada | Formato | Conteúdo |
|---|---|---|
| Relatórios históricos | JSON dos autores | Dados brutos fixados por commit e SHA-256 |
| Relatórios novos | JSON em `pilotos/` | Saídas independentes dos scanners, por aplicação e alvo |
| Normalização | `data/normalized/*.json` e CSV | Uma linha por unidade de decisão, com vínculos por ID |
| Referência | `data/ground_truth/*.csv` | Caso, CWE, camada ou artefato, observações de detecção |
| Saída de decisão | `results/*.csv` | Parâmetros, bloqueios por classe e estágio, IDs cobertos |
| Validação P4 | JSON e CSV | Evidência HTTP de cada teste, configuração e hash |

## Campos de uma unidade

| Campo | Interpretação |
|---|---|
| `id`, `ferramenta`, `identificador_scanner` | ID local, nome do scanner e identificador reportado. Uma regra ou CVE pode aparecer em várias unidades. |
| `camada`, `estagio` | APP ou INFRA e Commit, Build ou Deploy. |
| `classe`, `vinculos` | Classe global e mapa de vulnerabilidades → classe por par. As classes são direta, indireta e sem matriz. |
| `score`, `origem_score`, `severidade_original` | Pontuação comparada ao limiar, procedência da pontuação, rótulo reportado. JSON `null` representa valor ausente. |
| `cwes`, `granularidade` | CWEs reportados e unidade individual ou agregada. |
| `referencia` | Relatório relativo e localizador JSON. Para Trivy agregado, a tabela de composição identifica os membros. |

Uma unidade pode ter zero ou vários vínculos. O mesmo CWE pode identificar vários casos. Um evento de deploy acrescentado por P4 é uma decisão associada ao teste confirmado, fora das 226 unidades de entrada. Registre a versão da aplicação separadamente, com tag e commit ou digest, e a versão da ferramenta no relatório ou no manifesto do piloto. Use `data/templates/achados.csv` para novas bases e preserve JSON bruto. O CSV usa UTF-8. Os CSVs gerados usam BOM para facilitar a abertura no Excel.

`trivy_composicao.csv` referencia cada ocorrência histórica, com score, CWEs e participação em cada grupo. A presença em mais de um grupo é esperada.

Uma célula vazia em `trivy_fs_ocorrencias` significa que o scanner terminou sem identificar artefatos de dependências. Ocorrências iguais a zero exigem ao menos um artefato efetivamente avaliado.

## TeaStore e Juice Shop (`scripts/analise_alvos.py`)

Os arquivos `alvos_*.csv` em `results/` e `data/normalized/alvo-{teastore,juice-shop}.json` seguem o mesmo esquema de unidade acima, com `aplicacao` como coluna adicional. `alvos_composicao.csv` resume o volume bruto por ferramenta e inclui `bruto_fora_do_escopo`, as ocorrências descartadas pela regra de escopo (ver `docs/protocolo.md`). `alvos_trivy_composicao.csv` é o equivalente por imagem do `trivy_composicao.csv` da DVWA, com uma linha por grupo (`eosl`, `fixable`, `outras`) e por imagem. `alvos_trivy_agregacao.csv` compara a agregação por imagem (`por_imagem_*`) com uma agregação única para o sistema inteiro (`sistema_maximo`), que trata todas as imagens como um só estado de infraestrutura. `alvos_robustez_cwe_primario.csv` reavalia P1–P3 usando só o primeiro CWE de cada caso da matriz, como checagem de sensibilidade à própria matriz de referência (ver a ressalva de circularidade em `docs/protocolo.md`). `alvos_p4_fila.csv` e `alvos_p4_resultados.csv` seguem o esquema de `p4_fila.csv`/`p4_resultados.csv`, lendo os laudos de `pilotos/p4-<aplicacao>/validacoes.csv` quando existem. Na fila da P4 (`p4_fila.csv`), `motivo` vale `apenas_indireta` ou `perda_p2_p3`; `sinais_indiretos` e `sinais_diretos` contam as unidades vinculadas ao ID. Em `validacoes.csv`, `vetor_cvss_confirmacao` e `vetor_cvss_alternativo` são vetores base CVSS v3.1 do caso confirmado; as notas (`score_confirmacao`, `score_alternativo`) são calculadas por `scripts/cvss31.py`, e um `score_confirmacao` informado à mão precisa coincidir com o vetor. `evidence/p4_execucao.log` e `evidence/verificacao_extensao.log` registram a execução atual; `evidence/verificacao_final.log` corresponde à versão anterior da P4, com fila de três casos e P4-B sem nota. Entrada `nao_executada` na P4 significa que ainda não existe um teste com laudo para aquele caso. A ausência de score fica explícita na origem e no campo de pontuação.
