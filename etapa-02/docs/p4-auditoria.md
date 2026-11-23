# Auditoria manual do coletor da P4: critérios registrados antes

**Registrado em 22/11/2026, antes de sortear e de olhar qualquer caso.** Complementa
`p4-contexto.md`. Pergunta: o coletor só separa os achados, ou separa **corretamente**?

## Unidade amostrada

Pares distintos (pacote, CVE) entre os achados indiretos com nota ≥ 7 (os que a P2 bloqueia e
a P3 não), por alvo. Pares, e não unidades, porque o TeaStore repete o mesmo par em várias
imagens.

## Sorteio (estratificado, semente fixa 20261123)

- **Estrato "não carregado" (10 pares):** DVWA 4, TeaStore 6. O Juice Shop não tem pares não
  carregados na classificação final.
- **Estrato "carregado" (10 pares):** DVWA 3, TeaStore 3, Juice Shop 4.
- Dentro de cada célula, sorteio aleatório simples sem reposição (`scripts/amostra_auditoria.py`).
  Se uma célula tiver menos pares que o pedido, entram todos.

## O que se verifica em cada caso

Fontes permitidas: a descrição do CVE no relatório do Trivy, o sistema de arquivos e a
configuração da imagem implantada, o código e os arquivos de configuração da aplicação na
versão analisada. Nenhum teste de exploração.

**Para um par "não carregado", a pergunta é: algo na implantação de referência executa ou
carrega esse pacote?**

- `confirmado_nao_usado`: nenhum processo, script de inicialização, configuração de serviço ou
  código da aplicação referencia os binários ou bibliotecas do pacote.
- `usado` (falso negativo do coletor): existe um caminho na implantação que executa ou carrega
  o pacote (por exemplo, um script chamado em algum fluxo, ou uma biblioteca carregada sob
  demanda).
- `indeterminado`: não foi possível decidir com as fontes permitidas.

**Para um par "carregado", a pergunta é: a condição descrita no CVE é plausível no uso que a
aplicação faz do pacote?**

- `aplicavel`: a aplicação usa a funcionalidade afetada (ou a descrição do CVE não restringe a
  funcionalidade além de carregar o componente).
- `nao_aplicavel`: o CVE exige uma funcionalidade, configuração ou entrada que a aplicação
  claramente não usa.
- `indeterminado`: não foi possível decidir com as fontes permitidas.

## Como o resultado será lido (definido antes)

- **Precisão do "não carregado"** = `confirmado_nao_usado` / (`confirmado_nao_usado` + `usado`).
  Se for menor que 80%, o filtro não é confiável para rebaixar achados, e a P4 deve tratar o
  "não carregado" apenas como prioridade menor, não como informativo.
- **Fração aplicável entre os "carregados"** = `aplicavel` / (`aplicavel` + `nao_aplicavel`).
  É descritiva: mostra quanto ruído ainda passa pelo filtro, já que carregado não é o mesmo
  que explorável.
- Indeterminados são reportados à parte e não entram nos denominadores.

## Limite declarado antes

A auditoria é feita por **um único avaliador** (o assistente de IA, com supervisão do grupo),
sem segundo avaliador independente. Os julgamentos ficam registrados caso a caso, com a
evidência usada, para que o grupo possa revisar ou contestar cada um.

## Resultados

*Preenchido depois do sorteio (`scripts/amostra_auditoria.py`, semente 20261123). Julgamentos e
evidência caso a caso em `results/auditoria_amostra.csv`. Fontes usadas: descrições dos CVEs
nos relatórios do Trivy, `dpkg -L`, `ldd`, entrypoint e scripts das imagens fixadas por digest,
manifesto Kubernetes de referência e código do TeaStore 1.4.2, código compilado do Juice Shop
19.0.0 e do `juicy-chat-bot`. Nenhum teste de exploração.*

| Estrato | Pares | Resultado |
|---|---:|---|
| Não carregado | 10 (DVWA 4, TeaStore 6) | **10 `confirmado_nao_usado`**, 0 `usado`, 0 indeterminado |
| Carregado | 10 (DVWA 3, TeaStore 3, Juice Shop 4) | **2 `aplicavel`**, 8 `nao_aplicavel`, 0 indeterminado |

**Precisão do "não carregado": 10 de 10.** Com n = 10, o intervalo de confiança de 95%
(Clopper-Pearson) vai de 69% a 100%. A estimativa pontual passa do limite de 80% registrado,
mas o intervalo ainda o inclui. A amostra é pequena demais para afirmar o limite com
segurança. Os motivos encontrados se repetem:
- pacotes que só existem por dependência transitiva (Heimdal no banco do TeaStore);
- ferramentas de linha de comando usadas só no build ou no host (`curl` em
  `tools/test_webui.sh`, `perl` em `tools/build_docker.sh`);
- metapacotes e pacotes só de configuração (`php7.0`, `libldap-common`);
- binários chamados por um cron que nem roda na imagem (`php7.0-cli`).

O único falso negativo conhecido do coletor, o `handlebars` carregado só no fluxo autenticado,
foi achado e corrigido **antes** desta auditoria (observação S4) e por isso caiu no estrato
"carregado".

**Fração aplicável entre os "carregados": 2 de 10** (IC 95%: 3% a 56%). Carregado não é o
mesmo que explorável, como o protocolo previa. Os não aplicáveis caem em dois padrões:
- **CVE de servidor atribuído a uma biblioteca cliente:** o SECURITY DEFINER do PostgreSQL em
  `libpq5`, o back-sql do `slapd` em `libldap`;
- **CVE de funcionalidade que a aplicação não usa:** ChaCha20 com nonce longo; política X.509,
  desligada por padrão; validação de certificados no `gosu`, que não faz TLS; AST injetada no
  `compile()` do handlebars; `NodeVM` com `zlib` no vm2.

**Os dois aplicáveis são as fugas de sandbox do `vm2` no Juice Shop.** O `juicy-chat-bot`
executa no vm2 código montado com o nome do usuário e com a pergunta enviada ao chatbot
(`routes/chatbot.js`). São exatamente os achados que a P3 do artigo transformaria em registro
informativo, e que a P4 mantém bloqueantes.

### Leitura

- **O filtro "não carregado" acertou em todos os casos auditados.** Isso sustenta usar o coletor
  para tirar do bloqueio os achados de pacotes que a implantação não executa, mantendo-os
  informativos e reavaliados pelo Runtime Watch.
- **O filtro "carregado" ainda deixa passar ruído** (8 de 10 não aplicáveis). A P4 reduz o ruído
  da P2, mas não o elimina. Um segundo refinamento natural, apontado pela própria auditoria,
  é separar CVEs de componente servidor de bibliotecas cliente.
- **Limite:** um único avaliador, amostra de 20 pares. Os julgamentos estão escritos caso a caso
  para revisão do grupo.
