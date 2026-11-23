# Etapa 02 · Portões de segurança DevSecOps

Extensão da reprodução acadêmica do artigo de Machado, Cordeiro e Jandre ([SBSeg 2026, p. 534–548](https://doi.org/10.5753/sbseg.2026.28882)). A Etapa 02 examina quanto a decisão de bloqueio muda com a nota atribuída ao Semgrep, com o limiar de severidade e com a agregação do Trivy. Também propõe e avalia uma política P4 e testa a transferência da análise para dois alvos em escala piloto.

## Resultados

- **DVWA.** O artefato dos autores passou nas três verificações. O script adicional reproduziu 5, 80 e 56 bloqueios e coberturas bloqueantes de 3/13, 11/13 e 8/13. A base contém 226 unidades, com 51 alertas Semgrep ERROR e 26 WARNING.
- **Sensibilidade.** Com as regras originais, atribuir 5 ou 6 ao grupo ERROR reduz P2 para 29 bloqueios e 9/13 de cobertura e P3 para 5 e 4/13. Atribuir 9 ou 10 eleva P1 para 56 e 6/13. O pacote inclui a grade de 70 combinações, a variação separada de WARNING e a análise dos agregados de Trivy.
- **Pilotos (3 casos, WebGoat).** WebGoat 2025.3 passou por Semgrep, Checkov Dockerfile, Trivy Image, Trivy FS e ZAP passivo/ativo, com simulação de três casos de referência (`results/pilotos_*.csv`). Mantido como apêndice; não foi um dos alvos pedidos para a extensão.
- **TeaStore e Juice Shop (pedido do professor, matriz de 14 casos).** Os dois alvos indicados — TeaStore 1.4.2 (`DescartesResearch/TeaStore`) e Juice Shop 19.0.0 — passaram pela mesma análise completa da DVWA: classificação direta/indireta, P1–P3, sensibilidade e fila da P4, com uma matriz de 14 vulnerabilidades por alvo (substituindo os 3 casos do piloto). TeaStore: 729 unidades, P2 262/7-14, P3 139/4-14 (redução de 47%; Deploy Gate com ZAP passivo em Docker local, sem alerta acima do limiar). Deploy Gate executado (P3\*) no TeaStore: `ts-db-reset-unauth` confirmado (uma ação sem login regenera o banco), 140 decisões e 5/14. Juice Shop: 83 unidades, P2 28/7-14, P3 9/3-14 (redução de 68%). O padrão da DVWA se repete num alvo que não foi construído para ser vulnerável. Veja `docs/protocolo.md` para as ressalvas (regra de escopo, circularidade da matriz, dominância de uma única regra do Semgrep nos blocos do TeaStore).
- **Todas as notas proxy.** A análise passou a variar também o Checkov (63 unidades sem severidade no relatório, com 5,0 aplicado por padrão), o ZAP Baseline e o teste de credenciais, isoladamente e em conjunto (Monte Carlo). A redução de 30% de P3 frente a P2 vai de 17% a 83% variando uma nota por vez em ± 2 e de 13% a 89% com todas as notas sorteadas entre 1 e 10. Em todas as amostras, P3 bloqueia menos e perde de 2 a 5 casos de cobertura.
- **P4 orientada a ações, com contexto de execução (proposta atual, [docs/p4-acoes.md](docs/p4-acoes.md)).** Pergunta: o que o time precisa fazer para liberar o deploy? Um coletor no Deploy registra o que os processos da aplicação carregam. Todo CVE de imagem com nota ≥ 7, sem usar a matriz, sai do bloqueio com uma declaração VEX quando nenhum pacote afetado está carregado, e cada política é medida em ações de correção. Resultados: de 18% a 44% dos CVEs de imagem graves saem do bloqueio com VEX, e o Trivy oficial suprime exatamente esses nas 2 imagens testadas (181 de 550 achados no webui do TeaStore; 38 de 363 no Juice Shop). A redução de trabalho que não é absorvida pela migração obrigatória do SO aparece só no Juice Shop (47 → 41 ações); na DVWA e no TeaStore, a migração do SO absorve toda a redução. Dois critérios registrados falharam (S1, magnitude; S5, um falso negativo real do coletor, corrigido depois do registro e reportado com as duas definições). A cobertura (11, 7 e 7 casos) vem do escopo, não do coletor: a mesma regra sem coletor já a tem. Achado exploratório: medidas em ações e com o agregado do Trivy pelo máximo, P2 e P3 do artigo exigem o mesmo trabalho nos três alvos; com a média, não. A versão anterior, que filtrava só os indiretos, fica em [docs/p4-contexto.md](docs/p4-contexto.md) como histórico; a de confirmação dirigida virou P3\* ([docs/p4-avaliacao.md](docs/p4-avaliacao.md)).
- **P3\* na DVWA (antes chamada P4).** A fila de testes dirigidos recebe toda lacuna sem bloqueio em P3 que só tem sinal indireto ou que P2 bloqueava, o que inclui Exposed MySQL. Cada confirmação soma um bloqueio no Deploy (58 e 10/13), como o Deploy Gate do artigo prevê para testes customizados. Exigir também CVSS ≥ 7 de vetores escolhidos pelo grupo (antiga P4-B) dá 57 e 9/13. Consulte o protocolo e os laudos da configuração local em `pilotos/p4-dvwa/`.
- **P3\* no Juice Shop (antes chamada P4).** Uma instância local confirmou `js-exposed-metrics` (métricas Prometheus sem autenticação) por uma única requisição GET, validada pelo placar oficial de desafios da aplicação. Soma 1 bloqueio no Deploy (10 decisões, 4/14). O caso `js-rce-b2b` (execução de código no pedido B2B) foi deixado como `nao_executada` por decisão do grupo: confirmá-lo ativamente reproduziria um ataque de negação de serviço documentado pelo próprio projeto. Ver `pilotos/p4-juice-shop/` e `docs/protocolo.md`.

## Onde conferir

| Conteúdo | Caminho |
|---|---|
| **Tudo o que mudou em relação ao `main` original** | [docs/mudancas.md](docs/mudancas.md) |
| Protocolo, decisões e limitações | [docs/protocolo.md](docs/protocolo.md) |
| Evidências, configuração e comandos dos pilotos | [docs/pilotos.md](docs/pilotos.md) |
| Esquema das saídas e referência de vulnerabilidades | [docs/esquema.md](docs/esquema.md) |
| CSVs das políticas e da sensibilidade | [results/](results/) |
| Gráficos para apresentação e artigo | [figures/](figures/) |
| Dados normalizados e vínculos de origem | [data/](data/) |
| Registro do baseline e arquivos de referência | [evidence/](evidence/) |
| Relatórios dos scanners e laudos HTTP | [pilotos/](pilotos/) |

A versão para publicação contém os relatórios JSON necessários à reanálise. Os caminhos absolutos da coleta nesses relatórios foram normalizados para `/laboratorio`.

## Reprodução sem scanners

Em Linux ou Ubuntu no WSL, abra a raiz que contém `etapa-02/`. Use Python 3.10 ou superior e Git. No exemplo, o artefato dos autores é clonado em uma pasta vizinha ao repositório do grupo.

```bash
AUTOR="../sbseg2026-deteccao-direta-indireta"
git clone https://github.com/Machada1/sbseg2026-deteccao-direta-indireta.git "$AUTOR"
git -C "$AUTOR" checkout --detach 5b18244126350d1a6a4bf39e7a34701af9190563
(cd "$AUTOR" && bash scripts/run_all.sh)
python3 etapa-02/scripts/analise_dvwa.py --autores "$AUTOR"
python3 etapa-02/scripts/resumir_pilotos.py
python3 etapa-02/scripts/sensibilidade_proxies.py
python3 etapa-02/scripts/politica_p4.py --validacoes etapa-02/pilotos/p4-dvwa/validacoes.csv
python3 -m unittest discover -s etapa-02/tests -v
```

A saída esperada do baseline é P1 5/3, P2 80/11 e P3 56/8, onde os primeiros valores são bloqueios e os segundos são vulnerabilidades cobertas de 13. O script confere também as classes, a matriz por vulnerabilidade e os estágios.

Para reproduzir a coleta e a P4 orientada a ações, siga [docs/pilotos.md](docs/pilotos.md) (seção "P4 orientada a ações"). Para recalcular gráficos, instale `matplotlib` no seu ambiente Python e execute `python3 etapa-02/scripts/gerar_figuras.py`. Os PNGs e PDFs permanecem disponíveis para uso direto.

Código e dados da Etapa 01 referenciados por commit e hash. A fonte original é [o artefato dos autores](https://github.com/Machada1/sbseg2026-deteccao-direta-indireta). As verificações anteriores do grupo estão [no repositório da disciplina](https://github.com/jldsn/sbseg2026-replicacao-devsecops/tree/main/etapa-01/evidencias).
