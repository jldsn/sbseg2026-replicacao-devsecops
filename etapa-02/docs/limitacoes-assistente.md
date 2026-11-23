# Limitações do assistente neste projeto e como evitar interrupções

Documento prático para o grupo. Explica **por que** algumas respostas do assistente de IA
(Claude) foram cortadas no meio, **o que** ele pode e não pode fazer neste projeto, e um
protocolo para seguir sem novas interrupções. Baseado nas páginas oficiais da Anthropic
(citadas no fim) e no comportamento observado em duas sessões.

## 1. O que aconteceu (diagnóstico)

*Revisado em 22/11/2026: citações conferidas nas páginas oficiais, CVP incluído, regra 3 do
protocolo corrigida e seção 8 (impacto) adicionada.*

Em duas ocasiões a resposta do assistente foi **interrompida por um classificador de
segurança automático**, não por erro de ferramenta e **não por decisão do professor ou da
disciplina**:

1. **Sessão anterior:** ao planejar automatizar a confirmação do caso `js-rce-b2b` do Juice
   Shop — o teste oficial envia um payload que força um laço não controlado até estourar o
   tempo limite, ou seja, tem **efeito de negação de serviço** sobre o processo-alvo.
2. **Sessão de 22/11/2026 (manhã):** ao enumerar pontos de injeção de XSS no código do TeaStore e logo em
   seguida preparar o ambiente para **confirmar o XSS enviando payloads via HTTP**.

Em ambos os casos o gatilho foi a **trajetória "localizar vulnerabilidade → confirmar
disparando um exploit"**, mesmo em alvo local e descartável.

## 2. A distinção que importa: Política de Uso ≠ classificador em tempo real

Há **duas camadas diferentes**, e confundi-las faz perder tempo:

### Camada A — Política de Uso da Anthropic (o que é *permitido*)

A Política de Uso (vigente desde 12/11/2026) **permite explicitamente** este projeto. A
seção "Do Not Compromise Computer or Network Systems Without Authorization" proíbe
descobrir/explorar vulnerabilidades, acesso não autorizado, malware e negação de serviço
**sem autorização** — mas traz uma ressalva:

> "This section does not prohibit security research, testing, or tool development conducted
> on systems you own or operate, with the authorization of the system owner, or within the
> scope of an authorized bug bounty program or vulnerability disclosure policy, provided the
> activity complies with applicable law."

(Citação conferida na página oficial em 22/11/2026. A versão anterior deste documento
omitia os trechos "with the authorization of the system owner" e "provided the activity
complies with applicable law". Nenhum dos dois muda a conclusão: as máquinas e contêineres
são do próprio usuário.)

A mesma seção lista **negação de serviço** entre as atividades proibidas ("Conduct
denial-of-service attacks…"), mas a ressalva acima vale para a seção inteira, inclusive
esse item: um teste com efeito de DoS no próprio contêiner não viola a AUP por si. A faixa
vermelha (seção 5) se apoia em outra coisa: a página do Cyber Verification Program diz que
"Denial-of-service attacks" ficam fora de **todos** os níveis de acesso ajustado, e o
primeiro corte observado foi exatamente nesse tipo de teste. Ou seja, é uma linha que as
salvaguardas não liberam nem com verificação, e que o grupo decidiu não cruzar.

Este projeto se encaixa na ressalva: são **aplicações de treino propositalmente vulneráveis
(DVWA, TeaStore, Juice Shop) rodando em contêineres locais e descartáveis, na própria
máquina do usuário**, para reproduzir um artigo acadêmico. É "security research/testing on
systems you own or operate". **Nada aqui viola a Política de Uso.**

A própria política diz: *"encountering a block does not by itself indicate a violation of
the Usage Policy."* Ou seja: **ser bloqueado não quer dizer que o projeto é proibido.**

### Camada B — Classificador de segurança em tempo real (o que *interrompe*)

Sobre os modelos mais capazes, a Anthropic roda **salvaguardas automáticas em tempo real**
que detectam e bloqueiam conteúdo que *se parece* com atividade proibida (ex.: criação de
malware, exfiltração em massa, **ataques de negação de serviço**). Esse classificador:

- é **mais conservador** que a Política de Uso: a própria Anthropic diz que pode haver
  "model refusals and classifier blocks for allowed security work" (página do Cyber
  Verification Program);
- no post sobre as salvaguardas do Fable 5, a Anthropic classifica "Hacking, penetration
  testing, red teaming, and bug bounties" como **uso dual de alto risco**, categoria que
  bloqueada por padrão **no Fable 5** até haver controle de acesso para usuários
  verificados (o post não diz que a mesma regra vale para Opus/Sonnet);
- **inferência do grupo (não declarada pela Anthropic):** pelo que observamos nos dois
  cortes, o classificador reage à forma do que está sendo gerado (montar e disparar um
  payload) mais do que ao contexto declarado (alvo local, trabalho acadêmico). Nenhuma
  página oficial descreve como o classificador pesa o contexto.

**É a Camada B que nos interrompe, não a Camada A.** A conclusão prática: não adianta
"explicar melhor que é acadêmico" — o jeito de não ser cortado é **não fazer o modelo gerar
o passo que parece um ataque ativo**, e passar esse passo específico para execução manual.

### Caminho oficial que a versão anterior não mencionava: Cyber Verification Program

A Política de Uso aponta para o **Cyber Verification Program (CVP)**, para trabalho
coberto pelas salvaguardas cibernéticas em tempo real. Segundo a página de suporte (lida em
22/11/2026; a página diz "Updated October 6, 2026"):

| Ponto | O que a página diz | Efeito para nós |
|---|---|---|
| O que muda | Menos interrupções das salvaguardas cibernéticas; a Política de Uso continua valendo integralmente | Reduziria cortes na faixa amarela |
| Modelos | Mythos, Opus e Sonnet a partir de Mythos 5.1/5.2, Opus 5.5 e Sonnet 5.5 | Inclui o modelo desta sessão (Opus 5.5) |
| Pessoa física | Só **Defense Access**, que inclui "vulnerability triage and validation" | Pode cobrir a confirmação de XSS da fila da P4 |
| Pentest e exploits | **Red Team Access**, que é só para organizações (Enterprise/API) | Fora do alcance de um aluno individual |
| Negação de serviço | Proibida em **todos** os níveis | `js-rce-b2b` continua vermelho mesmo com CVP |
| Requisitos | Plano pago (não vale no Free), verificação com documento oficial com foto, MFA, retenção de dados obrigatória | Decisão pessoal do usuário |
| Estudantes | **Não mencionados** na página | Elegibilidade incerta; a página cita "a university" só na verificação de empresas |
| Prazo | Meta de dois dias para Defense Access | Cabe no cronograma, se o grupo quiser |

Inscrever-se é **decisão do usuário**; o assistente não faz isso. Sem CVP, o protocolo
abaixo continua sendo a forma de trabalhar.

## 3. O que o assistente PODE fazer (verde — sem risco de corte)

- Ler e analisar código-fonte, inclusive localizar e explicar vulnerabilidades (SAST manual).
- Rodar scanners: Semgrep, Checkov, Trivy (FS e Image), ZAP **passivo/baseline**.
- Subir os ambientes em Docker/Kubernetes local (TeaStore, DVWA, Juice Shop). Feito para
  o TeaStore em 22/11/2026 sem nenhum corte (`ambientes/teastore/docker-compose.yaml`).
- Fazer **requisições benignas** que só exercitam uma rota sem payload de ataque — ex.:
  `GET /metrics` do Juice Shop (confirmado assim, sem problema), um healthcheck, um
  `GET /dataBaseAction` que só dispara a rota.
- Toda a análise de dados, políticas P1–P4, sensibilidade, gráficos, CSVs.
- Documentação, protocolo, slides, revisão de texto.
- Git: branches, commits, tags, bundles de recuperação.

## 4. O que é LIMÍTROFE (amarelo — pode cortar)

- **Enviar qualquer requisição que carregue um payload de ataque**, mesmo benigno na
  aparência e mesmo em alvo local: string `<script>` para XSS, `' OR 1=1` para SQLi, corpo
  de upload XXE. Policy permite; o classificador pode cortar.
- Escrever **scripts que montam e disparam esses payloads** automaticamente.

Regra para o amarelo: **se o próximo passo é o modelo emitir/disparar um exploit, pare e
entregue o comando pronto para o usuário rodar**, em vez de executar.

## 5. O que o assistente NÃO vai fazer (vermelho)

- **Automatizar qualquer teste com efeito de negação de serviço**, mesmo documentado pelo
  próprio alvo, mesmo local, mesmo "só para confirmar". Isso cobre o `js-rce-b2b` do Juice
  Shop (payload de laço não controlado). Decisão já registrada em `protocolo.md`.
- Gerar malware, ransomware, ferramentas de acesso remoto persistente, botnets.
- Qualquer coisa contra sistema que **não** seja do usuário / fora do escopo local.

Para esses casos, a evidência fica **estática** (Semgrep/Trivy) ou a confirmação dinâmica é
**manual pelo usuário**, com o caso marcado `nao_executada` e justificado.

## 6. Protocolo para não ter mais interrupções neste projeto

1. **Confirmação por código primeiro.** Para cada caso, a prova por leitura de código +
   scanner estático já basta para a análise direto/indireto do artigo. Isso cobre quase tudo.
2. **Dinâmico só quando benigno.** O assistente só dispara HTTP quando é um acesso sem
   payload de ataque (GET de rota, healthcheck, métrica exposta).
3. **Exploit ativo → vira procedimento manual.** Quando confirmar exige disparar um payload
   (XSS, SQLi, RCE), o assistente **não executa nem escreve o payload**: descreve o
   procedimento (rota, campo, o que observar como evidência, onde salvar o laudo) e aponta
   a documentação oficial do alvo (no Juice Shop, o guia oficial de soluções dos desafios).
   *Correção em relação à versão anterior, que mandava escrever "o comando exato": escrever
   o payload é a mesma geração que dispara o classificador, então essa regra contradizia a
   seção 2.* O caso fica `nao_executada` até o usuário registrar o laudo.
4. **Nada de DoS, nunca.** Independe de contexto.
5. **Sempre com rede de segurança.** Trabalho em branch dedicado; tag + bundle de
   recuperação antes de mudanças grandes; `git status`/`stash -u` antes de operação
   destrutiva. Assim, se uma resposta for cortada no meio, nada se perde.

Seguindo isso, o projeto avança em tudo que é análise, coleta estática, infraestrutura e
documentação — que é a maior parte — sem tocar nos gatilhos do classificador.

## 7. Impacto no resultado científico (tranquilizador)

A metodologia do artigo é **classificar detecções como diretas ou indiretas e simular
portões P1–P4**. Isso depende de *quais ferramentas sinalizam cada caso e com que CWE* —
informação que vem de **scanners estáticos e leitura de código**, não de explorar a falha. A
confirmação dinâmica ativa serve só para enriquecer a fila da P4 em alguns casos pontuais.
Portanto, os números centrais do projeto (composição, cobertura, P1–P3, sensibilidade) **não
dependem** do que o classificador bloqueia. Os poucos casos afetados ficam documentados como
confirmação manual pendente, o que é uma limitação metodológica honesta e comum na área.

## 8. Impacto no projeto do que não pode ser feito (estado em 22/11/2026)

Tabela por caso. Esta seção trata dos testes customizados do Deploy Gate (**P3\***, antes chamada P4; a P4 atual é a orientada a ações, ver `p4-acoes.md`, que usa a P3\* como base e não depende de novos testes). "Teto" é o que a P3\* alcançaria se **todos** os casos restantes da fila
fossem confirmados (`results/alvos_p4_condicionais.csv`). Com **uma exceção** (o ZAP
ativo do TeaStore, ver a linha), nenhum item desta tabela altera P1, P2, P3, a composição
direto/indireto ou a análise de sensibilidade, que são os números centrais da reprodução.

| Item | Por que não é feito pelo assistente | Camada | O que fica faltando no resultado |
|---|---|---|---|
| TeaStore `ts-output-encoding` (XSS armazenado) | Confirmar exige enviar payload de script | Classificador (amarelo) | P3\* do TeaStore: 1 confirmação a menos. Evidência por código já existe (`CartActionServlet.java:131` → `profile.jsp`) |
| TeaStore `ts-tls-trust-all` | Código só roda com `USE_HTTPS=true`, ausente da implantação de referência | **Nenhuma** (limite técnico do alvo) | Fica fora do alcance da P3\* na configuração de referência |
| TeaStore: ZAP ativo | Escaneamento ativo dispara payloads de ataque | Classificador (amarelo) | **Única pendência que pode mexer em P1–P3.** Um alerta ativo High recebe nota proxy 7,5, acima do limiar; o tornado já mostra P2 266 / P3 143 se o ZAP chegar a 7,0, e um alerta direto em `/profile` poderia devolver `ts-output-encoding` à P3. Hoje há assimetria com o Juice Shop (2 regras ativas, 1 indicador de SQL Injection com confiança Low) |
| Juice Shop `js-dom-xss`, `js-reflected-xss` | Confirmar exige payload de XSS no navegador | Classificador (amarelo) | P3\* do Juice Shop: até 2 confirmações a menos |
| Juice Shop `js-rce-b2b` | O teste oficial tem efeito de negação de serviço | Salvaguardas: DoS fora de **todos** os níveis do CVP; 1º corte observado (vermelho, decisão do grupo) | 1 confirmação que nunca será automatizada; caso apoiado só em evidência estática e indireta |
| Push para o GitHub do grupo | `git push` dava 403: a conta não tem escrita no repositório | Permissão do GitHub (não é política da Anthropic) | Resolvido pelo fork do usuário; o Pull Request para o `jldsn` é aberto pelo navegador |
| Decisões do grupo (vetores CVSS, regra de escopo, circularidade) | São escolhas metodológicas do grupo | Papel, não política | A P4 atual depende de o grupo ratificá-la; os vetores CVSS da antiga P4-B ficaram só como análise de sensibilidade |

**Efeito numérico na P3\* (limiar 7):**

| Alvo | Confirmado hoje | Restantes na fila | Hoje | Teto se todos confirmados | Teto sem os casos vermelhos e sem os não exercitáveis |
|---|---|---|---|---|---|
| TeaStore | `ts-db-reset-unauth` | `ts-output-encoding`, `ts-tls-trust-all` | 140 decisões, 5/14 | 142, 7/14 | 141, 6/14 (só com o XSS manual) |
| Juice Shop | `js-exposed-metrics` | `js-dom-xss`, `js-reflected-xss`, `js-rce-b2b` | 10 decisões, 4/14 | 13, 7/14 | 12, 6/14 (com os dois XSS manuais) |

Leitura: na P3\*, o que fica sem confirmação custa **até 2 casos de cobertura no TeaStore**
(um deles, `ts-tls-trust-all`, é limite técnico do alvo, não de política) e **até 3 no
Juice Shop** (um deles, `js-rce-b2b`, nunca será automatizado), sempre dentro da faixa já
publicada em `alvos_p4_condicionais.csv`. As confirmações manuais de XSS recuperam 1 caso no
TeaStore e 2 no Juice Shop. O catálogo de testes benignos (`scripts/p4_catalogo.py`, `results/p4_funil.csv`) confirma automaticamente 4 dos 11 casos da fila; os que ficam de fora são exatamente os desta tabela. A conclusão qualitativa (o Deploy Gate executado recupera parte do que a
P3 perde, de forma controlada por confirmação) já se sustenta com uma confirmação em cada
alvo.

## Fontes

Todas conferidas em 22/11/2026.

- [Política de Uso da Anthropic (Usage Policy / AUP)](https://www.anthropic.com/legal/aup) — "Effective Nov 12, 2026"; ressalva de pesquisa, DoS proibido, salvaguardas em tempo real, menção ao CVP e "encountering a block does not by itself indicate a violation".
- [Anúncio da atualização da Política de Uso](https://www.anthropic.com/news/usage-policy-update) — 15/08/2025 (vigência 15/09/2025); criou a seção de cibersegurança. Não fala de classificadores nem do CVP.
- [Fable 5's cyber safeguards and our jailbreak framework](https://www.anthropic.com/news/fable-safeguards-jailbreak-framework) — 02/07/2026; quatro categorias (proibido, dual de alto risco, dual de baixo risco, benigno); pentest/red team como dual de alto risco.
- [Mapping AI-enabled cyber threats](https://www.anthropic.com/research/attack-navigator) — 03/06/2026; salvaguardas em tempo real nos modelos mais capazes e encaminhamento de uso dual ao CVP.
- [Cyber Verification Program (central de suporte)](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude-opus-and-sonnet) — o endereço fala em "real-time cyber safeguards", mas a página exibida é a do CVP; o corpo diz "Updated October 6, 2026" e o cabeçalho "Updated yesterday" (datas inconsistentes na própria página).
- *Removida:* a referência ao System Card do Claude Sonnet 4.5, que não foi lida e não sustentava nenhuma afirmação deste documento.
