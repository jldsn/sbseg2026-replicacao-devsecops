# Avaliação da P4 como melhoria: protocolo registrado antes da execução

> **Proposta atual: [`p4-acoes.md`](p4-acoes.md)** (P4 orientada a ações). Este documento foi
> substituído primeiro por [`p4-contexto.md`](p4-contexto.md), também superado.
>
> **Substituído em 22/11/2026 por [`p4-contexto.md`](p4-contexto.md).** Uma análise posterior
> mostrou que esta P4 de "confirmação dirigida" não é uma política nova: o Deploy Gate do artigo
> já bloqueia achados confirmados por testes customizados; o sinal indireto que abria a fila
> (CVE de biblioteca com o mesmo CWE) não tinha relação com o caso testado; e a fila dependia
> da matriz de referência. Os testes executados continuam válidos como **o Deploy Gate do
> artigo efetivamente executado (P3\*)**. O texto abaixo é mantido como registro.

**Registrado em 22/11/2026, antes de calcular qualquer política nova.** Este arquivo foi
commitado sem resultados. A seção "Resultados" é preenchida depois, em outro commit, para
que a diferença entre o que foi combinado e o que saiu fique visível no histórico do git.

## 1. A afirmação que queremos testar

A P3 do artigo trata todo achado indireto como informativo, e com isso perde casos de
cobertura que a P2 bloqueava. A P4 propõe um mecanismo diferente: **o achado indireto vira
uma obrigação de teste no Deploy**. O caso só bloqueia se um teste dirigido, sem payload de
ataque, confirmar a falha no ambiente.

Afirmação: *a P4 recupera parte da cobertura perdida pela P3 com um custo em bloqueios muito
menor que o da P2, e nenhuma alternativa simples, obtida só com ajustes de limiar, faz o
mesmo com menos bloqueios.*

## 2. Proposta e variantes

- **P4 (proposta) = P4-A.** P3 + um bloqueio no Deploy para cada caso da fila confirmado
  pelo teste dirigido.
- **P4-B e P4-B-alt deixam de ser variantes da proposta** e passam a ser **análise de
  sensibilidade**: mostram quanto o resultado mudaria se exigíssemos também nota CVSS ≥ 7,
  com vetores escolhidos pelo grupo. As colunas e os testes continuam no código.
  (Proposta do grupo; precisa ser ratificada.)

## 3. Políticas comparadas (lista fechada)

| Código | Política | Papel |
|---|---|---|
| P2 | Nota ≥ 7, todas as classes | Referência do artigo |
| P3 | Nota ≥ 7, só diretos e sem matriz | Referência do artigo |
| A1 | P3 com limiar 6 | Alternativa simples: P3 mais rígida |
| A2 | P3 + achados indiretos com nota ≥ 9 também bloqueiam | Alternativa simples: híbrida |
| A3 | P2 com limiar 8 | Alternativa simples: uniforme mais branda |
| A4 | P3 + bloqueia todas as unidades indiretas dos casos da fila, sem teste | Ablação: a P4 sem o passo de confirmação |
| P4 | P3 + 1 bloqueio por caso da fila confirmado (laudos reais) | Proposta |
| P4-teto | P3 + 1 bloqueio por caso da fila, todos confirmados | Limite superior, não é resultado |

Os três alvos: DVWA (13 casos), TeaStore 1.4.2 (14) e Juice Shop 19.0.0 (14), com as unidades
de `data/normalized/` e as filas de `results/p4_fila.csv` e `results/alvos_p4_fila.csv`.

## 4. Métricas (declaradas agora)

1. **Bloqueios**: unidades bloqueadas mais as decisões de Deploy da P4.
2. **Cobertura bruta**: casos da matriz com pelo menos um bloqueio, como no artigo.
3. **Cobertura sustentada**: casos com pelo menos um bloqueio vindo de uma unidade **direta
   para aquele caso**, ou de uma confirmação da P4. Um caso coberto só por achado indireto
   não conta.

   *Por que esta métrica existe:* o próprio artigo argumenta que o achado indireto tem
   outro escopo de impacto. E já sabemos, por leitura de código, que um bloqueio indireto
   pode cair num caso que nem existe na implantação: `ts-tls-trust-all` só roda com
   `USE_HTTPS=true`, ausente da implantação de referência.
4. **Recuperação** = (cobertura de X − cobertura da P3) / (cobertura da P2 − cobertura da P3).
5. **Custo** = (bloqueios de X − bloqueios da P3) / (bloqueios da P2 − bloqueios da P3).
6. **Testes exigidos** (só P4): tamanho da fila.

## 5. Regra de decisão (declarada agora)

- X **domina** Y num alvo se X tem bloqueios ≤ e cobertura ≥ que Y, com pelo menos uma
  desigualdade estrita. A dominância é avaliada separadamente para a cobertura bruta e para a
  sustentada.
- **A P4 se sustenta como melhoria** se, nos três alvos, nenhuma alternativa (A1 a A4) a
  domina em cobertura sustentada. O resultado em cobertura bruta é reportado por alvo, sem
  esconder os casos em que uma alternativa a domina.

**Previsão feita antes de calcular**, a partir de `results/alvos_politicas.csv` (a P1 do
TeaStore bloqueia 7 achados indiretos com nota ≥ 9, que cobrem `ts-output-encoding` e
`ts-tls-trust-all`): **é provável que A2 domine a P4 em cobertura bruta no TeaStore**. Se
isso acontecer, será reportado como resultado, não escondido.

## 6. Verificação do avaliador

O script novo (`scripts/comparar_politicas.py`) precisa reproduzir os números já publicados
antes de avaliar qualquer política nova: DVWA 5/80/56, TeaStore 32/262/139, Juice Shop
12/28/9 e as linhas de `results/alvos_limiares.csv`. Isso vira teste unitário.

## 7. Catálogo de testes benignos (automação da confirmação)

Um teste de catálogo é escolhido pelo CWE do caso e não envia payload de ataque. Cada
modelo tem critério de aprovação escrito antes e um **controle negativo**: o mesmo teste numa
rota protegida, que precisa reprovar.

| Modelo | CWEs | Critério de confirmação | Controle negativo |
|---|---|---|---|
| Acesso sem autenticação | 306, 284, 200 | Função sensível responde com o conteúdo esperado, sem redirecionar para login e sem 401/403 | Rota que exige sessão, que deve redirecionar ou negar |
| Função crítica sem autenticação | 306 | A ação executa (efeito observado no serviço), sem sessão | A mesma rota sem o parâmetro de confirmação, que não deve executar |
| CSRF | 352 | Ação com sessão, sem token, aceita com Referer de outra origem | Mesma ação sem sessão, que deve redirecionar para login |
| IDs de sessão previsíveis | 330 | 12 identificadores consecutivos com incremento constante | — (critério estatístico) |

Para a DVWA, `scripts/validar_dvwa_http.py` já é esse teste automatizado; o laudo existente
é reaproveitado.

**Ficam fora do catálogo, por decisão de protocolo:** XSS (exige enviar marcação ou script e
observar no navegador) e `js-rce-b2b` (o teste oficial tem efeito de negação de serviço).
Verificações de configuração estática (TLS, porta do banco) **não contam como confirmação**.

Funil reportado, em categorias exclusivas: na fila → com modelo dinâmico benigno → executável
na configuração local → confirmado.

**Limitação a declarar:** o modelo é escolhido pelo CWE, mas a rota testada vem da matriz de
referência, que um pipeline real não tem. Num pipeline, a rota viria do próprio achado
(o URL do alerta do ZAP ou o arquivo do Semgrep mapeado para a rota).

## Resultados

*Preenchido depois da execução (commits `0f47772` e `848ce2f`). Fontes:
`results/p4_comparacao.csv`, `results/p4_dominancia.csv` e `results/p4_funil.csv`.*

**Verificação do avaliador:** o script reproduziu DVWA 5/80/56, TeaStore 32/262/139,
Juice Shop 12/28/9 e todas as linhas de `alvos_limiares.csv` (teste
`tests/test_comparacao.py`).

### Tabela principal (bloqueios · cobertura bruta · cobertura sustentada)

| Política | DVWA (13) | TeaStore (14) | Juice Shop (14) |
|---|---|---|---|
| P2 | 80 · 11 · 8 | 262 · 7 · 4 | 28 · 7 · 3 |
| P3 | 56 · 8 · 8 | 139 · 4 · 4 | 9 · 3 · 3 |
| A1 · P3 limiar 6 | 56 · 8 · 8 | 140 · 4 · 4 | 9 · 3 · 3 |
| A2 · P3 + indiretos ≥ 9 | 58 · 8 · 8 | 146 · 6 · 4 | 19 · 4 · 3 |
| A3 · P2 limiar 8 | 12 · 4 · 2 | 82 · 5 · 2 | 18 · 5 · 1 |
| A4 · fila sem teste | 79 · 12 · 8 | 326 · 7 · 4 | 41 · 7 · 3 |
| A4c · só os casos confirmados, sem teste (pós-registro) | 59 · 10 · 8 | 157 · 5 · 4 | 14 · 4 · 3 |
| **P4** | **58 · 10 · 10** | **140 · 5 · 5** | **10 · 4 · 4** |
| P4-teto | 60 · 12 · 12 | 142 · 7 · 7 | 13 · 7 · 7 |

*Contagem:* as alternativas contam bloqueios por achado; a P4 conta uma decisão de Deploy
por caso confirmado. A diferença de granularidade favorece a P4 nas comparações de custo.

### O que os números mostram (resultados que poderiam ter dado errado)

1. **Custo frente à P2 (cobertura bruta, a métrica do artigo).** A P4 recupera 67% da
   cobertura perdida na DVWA com 8% dos bloqueios extras da P2; 33% no TeaStore com 0,8%;
   25% no Juice Shop com 5%. No agregado: 4 dos 10 casos perdidos, com 4 dos 166 bloqueios
   extras da P2 (2,4%).
2. **Dominância em cobertura bruta: a P4 não é dominada na DVWA nem no Juice Shop, mas é
   dominada no TeaStore.** Lá, a A3 (P2 com limiar 8) tem 82 bloqueios e 5/14, contra 140 e
   5/14 da P4. A A3 chega lá trocando casos com evidência direta por casos só indiretos: perde
   `ts-default-credentials` e `ts-private-key` (bloqueados por achados diretos) e ganha casos
   cobertos só por achados indiretos.
3. **Cobrir um caso por achado indireto pode ser cobrir algo que não existe.** A A2 (P3 +
   indiretos ≥ 9) chega a 6/14 no TeaStore, mais que a P4, porque passa a "cobrir"
   `ts-output-encoding` e `ts-tls-trust-all`. Mas o código de `ts-tls-trust-all` só roda com
   `USE_HTTPS=true`, ausente da implantação de referência: o bloqueio é por uma falha que não
   está ativa no sistema implantado.
4. **A previsão registrada errou o mecanismo.** Previmos que a A2 dominaria a P4 em cobertura
   bruta no TeaStore; quem dominou foi a A3. A A2 tem mais cobertura, mas também mais bloqueios.
5. **O valor do teste não é bloquear menos pelos mesmos casos.** Bloquear sem teste só os
   casos que a P4 confirmou (A4c, calculada depois do registro) custa +3, +18 e +5 bloqueios,
   contra +2, +1 e +1 da P4; a diferença é quase toda de granularidade de contagem. O que o
   teste muda é **quais** casos bloqueiam: sem teste, a fila inteira (A4) bloqueia 11 casos por
   +23, +187 e +32 achados; com teste, só os confirmados entram. Contra o mesmo conjunto de
   casos (A4 contra P4-teto: +4, +3 e +4), são de 83% a 98% menos bloqueios.

### A regra registrada e por que ela não é a evidência principal

A regra combinada antes se cumpre: **em nenhum alvo uma alternativa domina a P4 em cobertura
sustentada.** Mas esse resultado é quase garantido pela definição da métrica, e por isso não
deve ser apresentado como a prova da melhoria:

- a P3 é a P2 menos as unidades sem vínculo direto, então "P2 e P3 têm a mesma cobertura
  sustentada" é uma identidade, não um achado;
- A2 e A4 só acrescentam unidades indiretas, e os bloqueios diretos da A3 são um subconjunto
  dos da P3; nenhuma das três poderia aumentar a cobertura sustentada;
- só a A1 (P3 com limiar 6) poderia ter derrubado a regra, ao acrescentar achados diretos
  entre 6 e 7. Ela não acrescentou nenhum caso.

A métrica foi sugerida e registrada por nós, e o defeito é nosso. A evidência que sustenta a
P4 está nos itens 1, 3 e 5 acima; o item 2 é a sua principal limitação.

### Funil da automação (catálogo benigno)

| Etapa | Casos | Detalhe |
|---|---:|---|
| Na fila da P4 | 11 | DVWA 4, TeaStore 3, Juice Shop 4 |
| Com modelo dinâmico benigno | 6 | 5 implementados (CSRF, IDs previsíveis, redirecionamento, função crítica sem autenticação, acesso sem autenticação) e 1 só especificado (porta do banco, sem código) |
| Executável na configuração local | 5 | Exposed MySQL exige o manifesto Kubernetes dos autores |
| **Confirmados** | **4** | 1 inconclusivo (redirecionamento: rotas 404 na imagem) |

Os controles negativos reprovaram nos dois modelos executados agora (TeaStore: a mesma rota sem
confirmação não executa e `/profile` exige sessão; Juice Shop: `/api/Users` responde 401).
Ficaram fora: 3 XSS (manual, exige navegador), 1 RCE (efeito de DoS) e 1 caso só de
configuração (TLS). **Taxa de automação: 4 de 11 casos da fila (36%), ou 4 de 5 entre os que
têm modelo benigno executável (80%).**

### Desvios do protocolo

- A "recuperação" da métrica 4 ficou indefinida para a cobertura sustentada, porque a P2 e a
  P3 têm o mesmo valor nos três alvos (divisão por zero). No lugar, reporta-se o ganho absoluto
  (`ganho_sustentado`).
- No TeaStore, o laudo da P4 passou a apontar para uma cópia congelada da execução do catálogo
  (`pilotos/p4-teastore/catalogo-teastore.json`, com requisição bruta, log, controle negativo e
  digests das imagens). A evidência anterior, do spider do ZAP, continua em
  `pilotos/p4-teastore/teastore-http.json`.
- A ablação A4c (sem teste, só os casos confirmados) e a comparação A4 contra P4-teto foram
  calculadas **depois** do registro, porque a A4 registrada compara conjuntos de casos
  diferentes. Ficam na tabela marcadas como pós-registro e fora da regra de dominância.
- A conclusão foi reescrita depois de uma revisão: a primeira versão apresentava a regra de
  cobertura sustentada como a prova principal e dizia "91% a 99% menos bloqueios pelos mesmos
  casos", comparação que não era entre os mesmos casos.

### Conclusão

A P4 é uma melhoria concreta, com um limite claro. Recupera 4 dos 10 casos que a P3 perde
com 2,4% dos bloqueios extras que a P2 exigiria, e não é dominada por nenhum ajuste simples de
limiar na DVWA e no Juice Shop. No TeaStore, a P2 com limiar 8 a domina em cobertura bruta,
trocando casos com evidência direta por casos só indiretos. O que a P4 acrescenta e os ajustes
de limiar não conseguem é **bloquear com evidência de que a falha existe no sistema
implantado** (o caso `ts-tls-trust-all` mostra o risco do contrário). Hoje, só 36% da fila é
confirmável por testes benignos automáticos, e os XSS dependem de uma etapa de DAST com
navegador. A P4-B continua no código como análise de sensibilidade.
