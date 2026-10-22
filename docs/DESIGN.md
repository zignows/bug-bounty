# Árbitro — Design (v2)

Rascunho consolidado. Assistente de bug bounty para **vulnerabilidades
web de aplicação** (IDOR, XSS, lógica de autorização/negócio). Fora de
escopo por design: rede, RCE, infraestrutura, SSRF-para-infra.

Fluxo: escopo → recon permitido → mapa da aplicação → hipóteses →
contestação independente → decisão por consenso → validação autorizada →
revisão de evidências → relatório ou parada.

## 1. Princípios reitores

1. **Escopo é código, não prompt.** Autorização validada e imposta em
   camada determinística de rede; o LLM não a amplia.
2. **Determinismo primeiro; LLM só onde é insubstituível.** Detecção
   mecânica, parsing e scoring são código; o LLM gera hipótese, prioriza
   e redige.
3. **Human-in-the-loop como requisito.** A IA superestima criticidade, é
   ruim de encadear lows→crits, perde coisas e sai dos trilhos.
4. **Consenso ≠ autorização ≠ prova.** `CONFIRMADA` só com evidência
   observável, reproduzível e revisada.
5. **Começar simples e iterar com runs reais.**
6. **Autorização é real.** Nunca simular permissão nem driblar
   classificador. Caminho legítimo = programa de acesso autorizado.

## 2. Arquitetura (na VPS)

```
CONTROL PLANE (determinístico, sem LLM na decisão)
  máquina de estados · budget governor · policy engine
  human-approval gate · fila de revisão · audit log (append-only)
  agent runner (jobs isolados, valida saída por schema)
    │ só ele transiciona estado / gasta orçamento / pede aprovação
POLICY / REDE (escopo como código)
  proxy de egress obrigatório + firewall de kernel (nftables)
  allowlist host/porta/protocolo · re-resolve DNS (anti-rebind)
  valida redirects · bloqueia privado/metadata · rate/limites
  passivo por default; ativo só por host após gate
    │ todo tráfego dos agentes passa aqui e fica logado
AGENTES (LLM, por papel, provedor configurável)
  raciocínio (hands-off): Otimista · Cético · Árbitro
  execução (hands-on): Recon · Validador
  + sub-agentes efêmeros p/ trabalho pesado/sujo (e quarentena)
CONHECIMENTO: specs normativas · reports curados · observação diferencial
EXECUÇÃO (só HTTP): browser driver (anti-bot) · AST parser · sessão injetada
```

**Regra de ouro:** o LLM **propõe** um plano estruturado; o control plane
**confere e executa**. Agentes nunca chamam uns aos outros — tudo via
jobs do runner.

### 2.1 Arquitetura de duas velocidades

- **Núcleo estável (muda devagar, com revisão):** policy engine, imposição
  de escopo, proxy/sandbox, denylist destrutiva, audit log. Não se itera
  solto. É o chão que não pode rachar.
- **Camada rápida (itera todo dia):** skills, prompts, heurísticas,
  oráculos, matriz de autorização, wordlists.

A velocidade fica na camada certa: itera-se rápido em cima sem nunca
afrouxar a segurança embaixo.

## 3. Papéis, provedores e contexto

| Papel | Mão | Provedor (empírico) | Função |
|---|---|---|---|
| Orquestrador | fora | Codex | **aconselha** o próximo passo; não transiciona estado |
| Otimista | fora | configurável | hipótese a partir de observações + conhecimento |
| Cético | fora | K3/Kimi (Bedrock) | refuta; cita spec; levanta explicações benignas |
| Árbitro | fora | modelo "forte" | decide por evidência citada |
| Recon / Validador | na massa | GLM via opencode | executam, atrás do proxy/sandbox |
| Sub-agente efêmero | na massa | barato | absorve trabalho pesado/sujo; devolve destilado; serve de quarentena |

Seleção de modelo é empírica (testar vários, 2× cada). Mapeamento
inicial: achar leads → GPT/Codex; fechar o loop (validar/reportar) →
Claude; GLM/Kimi (baratos) exigem prompt mais preciso.

## 4. Fluxo de estados

Estados: `PROPOSTA`, `MAIS_EVIDENCIA`, `REJEITADA`,
`APROVADA_PARA_VALIDACAO`, `REVISAO_HUMANA`, `CONFIRMADA`,
`RELATORIO_PRONTO` (ver `src/arbiter/states.py`).

```
RECON (passivo) → produz evidência replayável (capturada pelo proxy)
  → PROPOSTA: Otimista e Cético analisam ÀS CEGAS (não veem a conclusão um do outro)
  → ÁRBITRO decide SÓ por evidência citada:
       REJEITADA | MAIS_EVIDENCIA (volta ao Recon, 1×) | REVISAO_HUMANA | APROVADA_PARA_VALIDACAO
  → (gate humano) VALIDADOR executa plano aprovado; proxy registra tudo
  → REVISÃO DE EVIDÊNCIAS: reproduzível+revisada? → CONFIRMADA → RELATORIO_PRONTO
```

Limites: 1 rodada de contestação, 1 de revisão. Transição sem `id` de
evidência citada é rejeitada pelo código.

## 5. Oráculos por classe

Critério de confirmação explícito e, onde possível, determinístico:

- **Client-side (DOM XSS, postMessage, sinks):** detector é **query em
  AST**, não "IA ache XSS". XSS exige **evidência de execução** em
  contexto real, não só reflexão.
- **IDOR / autorização:** **matriz de autorização** (identidades ×
  recursos esperados) + **observação diferencial**. O bug é a célula onde
  `observado ≠ pretendido`; a matriz é a evidência. (Nenhum RFC decide.)
- **Protocolo (headers, cookies, cache, CORS, redirect, auth):** oráculo
  são as **specs normativas** citadas (MUST/SHOULD). O Cético as usa para
  **derrubar** falso-positivo.
- **Severidade:** **CVSS calculado** (código, a partir do spec), nunca
  opinado. Rubrica determinística por classe; mostrar também o que parece
  seguro (há falso-positivo).

## 6. Conhecimento (três papéis)

- **Specs normativas** → oráculo de protocolo; indexadas como asserções
  citáveis (cláusula + id).
- **Reports (hackerone) → hipóteses.** Curadoria > volume (<1% dos
  writeups públicos presta); retriever devolve conhecimento sintetizado,
  não URLs; dedup, proveniência e licença antes de redistribuir.
- **Observação diferencial** → oráculo de authz/lógica, via contas de
  teste do operador.

Conteúdo recuperado e respostas de alvo = **dado não confiável**: passam
por sub-agente efêmero e entram como observação normalizada, nunca no
canal de instrução nem nas políticas. Web search do agente desligado por
padrão.

## 7. Segurança, escopo e limites

- **Policy engine (fonte de verdade):** allowlist host/porta/protocolo;
  exclusões; re-resolução de DNS + checagem do IP final (anti-rebind);
  validação de redirect; bloqueio de privado/link-local/metadata no
  kernel. (Núcleo offline implementado em `src/arbiter/policy.py`.)
- **Denylist de ações destrutivas:** proibido por padrão logout, troca de
  senha/email, DoS, brute force, persistência, exfiltração, fora-de-escopo.
- **Autenticação assistida por humano:** o operador entrega a sessão; o
  bot não tenta logar sozinho (dispara anti-bot/CAPTCHA) e chama o humano.
- **Bom cidadão:** tráfego com header identificável; respeita rps/regras;
  denylist de terceiros embutidos (CDN/analytics) em páginas in-scope.
- **Limites (default conservador):** US$2/investigação · 1 req/s por host
  · concorrência 2 · 30 min · 20 iterações. Paradas: 5 erros seguidos →
  pausa; 429 → respeita `Retry-After`; efeito inesperado → `REVISAO_HUMANA`.
- **Passivo é o default global;** ativo só liga por host após gate, com
  **dry-run** do que será enviado.

## 8. Qualidade e anti-preguiça

- **Micro-skills** de trabalho único (combate "completion bias");
  decompor por classe (XSS refletido/stored/DOM/blind separados).
- **Checklist markdown como ledger** + **review determinístico no control
  plane**: artefato existe? byte não-zero? a requisição realmente saiu
  pelo proxy? (vantagem: o proxy é a verdade do que rodou — não se confia
  no agente). Falhou → nudge pra refazer.
- **Sintaxe de ferramenta sempre explícita**; caminhos completos; nunca
  guardar output na pasta da skill.
- **"Como é um bom output"**: cada skill tem exemplo do artefato-alvo.

### 8.1 Loop de iteração (motor do projeto)

finding → entender por quê → **cristalizar em skill/asserção reutilizável
(pipeline de promoção)** → o bot passa a achar sozinho. Sinal de melhoria
vem da **pista dupla** (bot vs. caça manual): "por que o bot achou e eu
não / vice-versa?". Guardas: **git** (iteração acumula) + **evals de
regressão** (uma skill não degrada outra em silêncio). Generalizar ao
promover (tirar o específico do alvo), para não dar overfitting.

## 9. Avaliação

- **Pista dupla** (bot vs. manual) é o sinal honesto; benchmark sintético
  sofre overfitting e não prevê bug bounty real.
- **Evals por skill:** ligada vs. desligada (às vezes a skill piora) +
  teste de ativação.

### 9.1 Redundância por tipo de passo (controle de custo)

Multi-run/multi-model não é global; é calibrado e governado pelo budget:

| Tipo de passo | Exemplo | Quanto rodar |
|---|---|---|
| Determinístico | AST, CVSS, checagem de escopo | 1× |
| Gerativo / hipótese | o que investigar, como escalar | poucas amostras, ~2 modelos |
| Decisão | Cético / Árbitro | no máx. 2 modelos (pontos cegos correlacionados) |

Escala = botão do orçamento, default no chão, dial-up por alvo.

## 10. Descartado (e por quê)

- **PDF de permissão falso / bypass de classificador** — fraude; antítese
  do escopo-como-verdade. Legítimo = programa de acesso autorizado.
- **Autonomia 24/7 desassistida** ("não pare até 10 criticals") —
  contraria passive-first + gates.
- **RAG ingênuo de corpus gigante não curado** — lixo entra, lixo sai.
- **Spray massivo de inferência** (120 skills × 6 modelos × 2 × 3) —
  economia de pentest financiado, não de hunter solo; adotada só a ideia
  calibrada (seção 9.1).
- **Classes fora do escopo web** (SSRF→infra, k8s, RCE) — fora por ora.

## 11. MVP em fases

| Fase | Entrega | Tráfego |
|---|---|---|
| 0 | Config multi-provedor; schema de evidência/estado; audit log | não |
| 1 | **Policy engine + proxy + sandbox**, testados c/ alvos fictícios e casos adversariais | não |
| 2 | Conhecimento: specs como asserções + reports curados + RAG sintetizado | não |
| 3 | Loop de agentes em simulação; máquina de estados + review determinístico | não |
| 4 | JS-analyze + AST como backbone do Recon passivo; auth assistida | passivo |
| 5 | Validação ativa opt-in (oráculos por classe, dry-run, gate humano) | ativo controlado |
| 6 | Relatório (CVSS calculado, evidência replayável) → `RELATORIO_PRONTO` | — |

**Estado atual:** base da Fase 0–1 em andamento — núcleo determinístico e
offline com testes: scope, policy engine, state machine, e o **modelo de
evidência** (imutável, content-addressed) + **registros de raciocínio**
(Analysis/ArbiterDecision/ValidationRecord) com os invariantes em código
(cético precisa de explicação benigna; decisão só com transição legal +
evidência existente citada); e a **camada de conhecimento** (specs como
asserções citáveis + reports distilados), tratada como **dado não
confiável**, com gate de curadoria, dedup, proveniência/licença e
retrieval que devolve conhecimento (não URL). A ingestão em massa do
corpus `reddelexc/hackerone-reports` é passo posterior, *gated* na decisão
de licença/dedup (ver `knowledge/README.md`). Há também o **esqueleto do
control plane** (determinístico, sem LLM/rede): audit log append-only,
budget governor com condições de parada, e o orquestrador que aplica
decisões (validadas), impõe os limites de rodada, o gate humano de
validação ativa e registra tudo — demonstrado em
`examples/simulate_investigation.py`. Primeiro **oráculo** pronto: a
**matriz de autorização** (`src/arbiter/oracles/authz_matrix.py`) — declara
intenção de acesso por identidade×recurso, compara com o observado e emite
violações (DENIED-mas-ALLOWED = IDOR/BOLA; a matriz é a evidência). O
oráculo de **CVSS v3.1** (`src/arbiter/oracles/cvss.py`) calcula o base
score de forma determinística a partir do vetor (constantes, impacto/
exploitability e o Roundup oficiais), validado contra 8 vetores canônicos
conhecidos — severidade é **calculada, não opinada** (duplamente verificada: a
implementação e uma derivação independente batem em 18/18 vetores). Há
ainda o **oráculo de invariante de negócio**
(`src/arbiter/oracles/business_invariant.py`): detecta, sobre um fluxo
observado, violações do tipo "regra de servidor imposta no cliente" —
passo-obrigatório-precedente (payment bypass/step-skip), limites de valor
(preço/qtd), uso-no-máximo-N (cupom) e estado-tem-que-mudar (crédito/quota).
A *detecção* é offline; a *confirmação* continua ativa/Fase 5/gated.
Começou também a trilha de **egresso**: o *gate* determinístico
(`src/arbiter/egress.py`) que o proxy chamará por requisição — método em
modo passivo, re-resolução de DNS + bloqueio de IP, **pin do IP resolvido**
(anti-rebinding) e rate-limit por host — mais os artefatos de deploy
(`deploy/`: nftables + sandbox) como as outras duas barreiras de defesa em
profundidade, pra aplicar na VPS. A camada de coleta/proxy escolhida é o
**Caido** (com o plugin **JX Scout** para coletar/beautify/de-chunk do JS);
o egress gate fica como **upstream do Caido**, mantendo o escopo-como-código
em Python como fonte de verdade — ver `deploy/caido.md`. A **fronteira de
ingestão** (`src/arbiter/ingest.py`) normaliza qualquer troca HTTP
(`CapturedExchange`) em evidência `HTTP_EXCHANGE` content-addressed,
independente da versão/API do Caido (o mapeamento específico do Caido é um
adapter fino, escrito contra amostra real, por a API dele ser instável
entre releases). Sem lógica de execução ativa.

## 12. Decisões abertas (não bloqueiam o desenho)

1. Confirmar modelo exato do K3 (assumindo Kimi K2/Bedrock).
2. Números finais de limites/parada.
3. Contas/estados de teste que o operador consegue fornecer (destrava IDOR).
4. Licença/dedup do corpus antes da Fase 2.

## 13. Backlog (candidatos de fase futura)

- **Oráculo de invariante de negócio** — generaliza "regra de servidor
  imposta no cliente": payment/quota bypass client-side (ex.: débito e
  ação em requests separados → pular o débito), price tampering,
  quantidade negativa, reuso de cupom, pular etapa de fluxo multi-step,
  rate-limit só no front. Declara-se a invariante pretendida (ex.: "ação
  X exige cobrança bem-sucedida e saldo deve cair") e procura-se a
  sequência observável que a viola. Confirmação por **diferencial**
  (estado antes/depois) com **conta e saldo de teste do operador**.
  Classe **ativa, Fase 5**, muda estado → **gate humano obrigatório**;
  jamais contra dinheiro real ou terceiros.
  *(Detecção já implementada offline em
  `src/arbiter/oracles/business_invariant.py`; a confirmação ativa é que
  permanece Fase 5/gated.)*

- **SSRF por callback (OOB)** — *proposto, aguardando confirmação.*
  Detecção de SSRF apontando para um endpoint de callback **do próprio
  operador**; oráculo = "meu callback recebeu a request?". Não encosta em
  rede interna/metadata, então **não fura o núcleo** de segurança.
  Pós-exploração interna/metadata e **RCE** permanecem **fora de escopo**.
