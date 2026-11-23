# Reprodução Experimental — SBSeg 2026

Projeto da disciplina de Cibersegurança, dedicado à reprodução e extensão dos experimentos do artigo **"Detecção Direta versus Indireta em Pipelines DevSecOps: Análise de Ruído Taxonômico e Calibração de Portões de Segurança Progressivos"**.

## Artigo original

**Autores:** Guilherme Machado, Fábio Cordeiro e Caroline Jandre.

**Evento:** XXVI Simpósio Brasileiro de Cibersegurança (SBSeg 2026).

- [Artigo científico](https://sol.sbc.org.br/index.php/sbseg/article/view/44310)
- [Repositório original dos pesquisadores](https://github.com/Machada1/sbseg2026-deteccao-direta-indireta)

## Objetivo

Reproduzir os resultados experimentais das Tabelas 3, 4 e 5 do artigo e avaliar extensões para as políticas de bloqueio.

O estudo investiga como a distinção entre detecções diretas e indiretas de vulnerabilidades influencia as decisões automatizadas de bloqueio em pipelines DevSecOps.

## Etapa 01 — Reprodução experimental

### Ambiente utilizado

| Componente | Ambiente |
|---|---|
| Sistema operacional | Windows 11 |
| Subsistema Linux | WSL2 |
| Distribuição Linux | Ubuntu 26.04.1 LTS |
| Python | 3.14.4 |
| Git | 2.53.0 |

### Procedimento

A reprodução foi realizada utilizando o código e os relatórios JSON disponibilizados pelos autores.

Para executar o experimento em um ambiente Linux com Python e Git instalados:

```bash
git clone https://github.com/Machada1/sbseg2026-deteccao-direta-indireta.git
cd sbseg2026-deteccao-direta-indireta
python3 src/analise_artigo.py
bash scripts/run_all.sh
```

A versão exata do código utilizada na reprodução está identificada pelo commit registrado em `etapa-01/evidencias/commit_original.txt`.

### Resultados reproduzidos

| Indicador | Resultado |
|---|---:|
| Ocorrências brutas | 1.750 |
| Achados consolidados para simulação | 226 |
| Vulnerabilidades com detecção direta | 10 |
| Vulnerabilidades apenas com detecção indireta | 3 |
| Bloqueios P1 | 5 |
| Bloqueios P2 | 80 |
| Bloqueios P3 | 56 |

A política P3 apresentou 30% menos bloqueios que a P2, preservando os 29 bloqueios de achados classificados como diretos. Entretanto, a cobertura bloqueante caiu de 11/13 para 8/13 vulnerabilidades da matriz.

### Validação

O script `scripts/run_all.sh` verificou as três principais reivindicações experimentais:

- **Tabela 3:** composição dos 226 achados do conjunto de avaliação.
- **Tabela 4:** cobertura das 13 vulnerabilidades analisadas.
- **Tabela 5:** comparação das políticas P1, P2 e P3.

Todas as verificações automáticas foram concluídas com sucesso e os resultados coincidiram com os valores de referência fornecidos pelos autores.

### Escopo e limitações

A reprodução utilizou os dados previamente coletados pelos pesquisadores. Foram reexecutados o processamento, a classificação, as simulações de bloqueio e as verificações dos resultados.

Não foram repetidas a implantação do ambiente na Google Cloud nem a coleta inicial com Trivy, Semgrep, Checkov e OWASP ZAP.

Portanto, a reprodução demonstra a correspondência dos resultados computacionais com os artefatos disponibilizados, mas não constitui uma repetição independente de toda a infraestrutura experimental.

### Evidências

Os arquivos estão em `etapa-01/evidencias/`:

| Arquivo | Descrição |
|---|---|
| `execucao_completa.txt` | Registro da execução e das verificações automáticas |
| `numeros_reproduzidos.json` | Resultados numéricos gerados |
| `versao_python.txt` | Versão do interpretador utilizado |
| `commit_original.txt` | Identificador da versão do código original |

## Etapa 02 — Extensão do estudo

A etapa inclui a reprodução dos portões originais, a variação do proxy Semgrep e dos limiares, a comparação de agregações Trivy, a política P4 candidata e a extensão da análise completa (P1–P3, sensibilidade e P4) para TeaStore 1.4.2 e Juice Shop 19.0.0, com matriz de 14 casos por alvo — os dois alvos indicados pelo professor para a disciplina. WebGoat 2025.3 segue como piloto reduzido (3 casos), de uma rodada anterior. Veja a [documentação da Etapa 02](etapa-02/README.md) para resultados, protocolo, scripts e evidências.

| Resultado | Onde conferir |
|---|---|
| Referência na DVWA · 5, 80 e 56 bloqueios em P1, P2 e P3 | [Baseline](etapa-02/results/baseline.csv) |
| Variação de nota, limiar e agregação | [CSVs](etapa-02/results/) e [gráficos](etapa-02/figures/) |
| Todas as notas proxy, isoladas e em conjunto · redução P3 vs P2 de 13% a 89% | [Tornado](etapa-02/results/sensibilidade_tornado.csv) e [Monte Carlo](etapa-02/results/sensibilidade_monte_carlo_resumo.csv) |
| P4 orientada a ações · 18–44% dos CVEs de imagem graves saem do bloqueio com VEX validado no Trivy; redução de trabalho não absorvida pela migração de SO só no Juice Shop (47 → 41 ações); S1 e S5 falharam como registrado ([protocolo e resultados](etapa-02/docs/p4-acoes.md)) | [Ações](etapa-02/results/p4_acoes_resumo.csv), [contexto](etapa-02/results/contexto_imagem.csv) e [VEX no Trivy](etapa-02/results/p4_vex_trivy.csv) |
| TeaStore 1.4.2 e Juice Shop 19.0.0 · matriz de 14 casos, P1–P3, sensibilidade e P4 | [Políticas](etapa-02/results/alvos_politicas.csv), [cobertura](etapa-02/results/alvos_cobertura.csv) e [fila P4](etapa-02/results/alvos_p4_resultados.csv) |
| WebGoat (piloto, 3 casos de referência) | [Simulação piloto](etapa-02/results/pilotos_politicas.csv) |

## Créditos

O código original, os dados experimentais e a metodologia-base são de autoria dos pesquisadores responsáveis pelo artigo. Este repositório documenta a reprodução acadêmica e a extensão experimental realizadas pelo grupo.
