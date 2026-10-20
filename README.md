# Reprodução Experimental — SBSeg 2026

Projeto da disciplina de Cibersegurança, dedicado à reprodução e extensão dos experimentos do artigo **"Detecção Direta versus Indireta em Pipelines DevSecOps: Análise de Ruído Taxonômico e Calibração de Portões de Segurança Progressivos"**.

## Artigo original

**Autores:** Guilherme Machado, Fábio Cordeiro e Caroline Jandre.

**Evento:** XXVI Simpósio Brasileiro de Cibersegurança (SBSeg 2026).

- [Artigo científico](https://sol.sbc.org.br/index.php/sbseg/article/view/44310)
- [Repositório original dos pesquisadores](https://github.com/Machada1/sbseg2026-deteccao-direta-indireta)

## Objetivo

Reproduzir os resultados experimentais das Tabelas 3, 4 e 5 do artigo, comparar os valores obtidos com os publicados e propor melhorias para uma segunda etapa experimental.

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

Nesta etapa, o grupo implementará e avaliará uma melhoria sobre a metodologia ou as políticas de bloqueio estudadas.

A proposta específica será definida após a análise crítica dos resultados originais.

## Créditos

O código original, os dados experimentais e a metodologia-base são de autoria dos pesquisadores responsáveis pelo artigo. Este repositório documenta a reprodução acadêmica realizada pelo grupo e reunirá suas futuras extensões experimentais.
