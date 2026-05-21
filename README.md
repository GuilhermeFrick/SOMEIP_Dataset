# SOME/IP IDS — Dataset de PCAPs

Repositório de capturas de rede (PCAPs) para treinamento e avaliação de um
Sistema de Detecção de Intrusão (IDS) para o protocolo **SOME/IP** (AUTOSAR).

Contém os PCAPs do dataset **Alkhatib et al.** (comprometidos diretamente neste repo).  
Os PCAPs do dataset **Kim et al.** (~1.4 GB) são baixados automaticamente do Figshare
pelo script `detection/src/00_download.py`.

---

## Estrutura do repositório

```
SOMEIP_Dataset/
├── fakeClientID.pcap        # Alkhatib — FakeClientID, cenário 1
├── fakeClientID2.pcap       # Alkhatib — FakeClientID, cenário 2
├── eerror.pcap              # Alkhatib — Error on Error
├── eevent.pcap              # Alkhatib — Error on Event
├── drequest.pcap            # Alkhatib — Missing Request
├── dresponse.pcap           # Alkhatib — Missing Response
├── deleteRequest_test1.pcap # Alkhatib — Delete Request (teste)
├── wrongInterface.pcap      # Alkhatib — Wrong Interface, cenário 1
└── wrongInterface2.pcap     # Alkhatib — Wrong Interface, cenário 2
```

---

## Dataset Kim et al.

> **Fonte:** https://figshare.com/articles/dataset/SOME_IP_traffic_normal_and_abnormal_traffic_/30970450  
> **Publicado:** 2026-01-29 por Taeguen Kim  
> **Download:** `python detection/src/00_download.py`

Dataset de captura de pacotes coletado em uma rede baseada em SOME/IP composta por 9 ECUs.
O tráfego usa arquitetura publish-subscribe: quando um evento é gerado, os dados são entregues
dinamicamente às ECUs subscritoras.

---

### `benign_traffic.pcap` — Tráfego Normal

Tráfego normal registrado sob condições de operação benignas.
ECUs comunicam usando arquitetura publish-subscribe.

| Campo | Valor |
|---|---|
| Tamanho | 213 MB |
| Ataque | Nenhum |
| Atacantes | — |

---

### `dos_noti_flood.pcap` — DoS via Event Notification Flooding

Modela um nó malicioso dentro do veículo que degrada a disponibilidade da rede e das ECUs
gerando um volume anormalmente alto de event notifications de serviço em uma janela de tempo
curta. Diferente de ataques furtivos que tentam imitar comportamento periódico normal,
o atacante prioriza amplificação de tráfego para induzir congestionamento, acúmulo de fila
e sobrecarga de processamento. Como resultado, mensagens legítimas podem experimentar
maior latência, jitter ou perda, e a pressão na CPU e nos buffers do receptor aumenta.

| Campo | Valor |
|---|---|
| Tamanho | 186 MB |
| Ataque | DoS (Denial of Service) |
| Atacante | `172.18.0.11` |

**Pacotes de ataque:**
- `service_id` = `0x1001`
- `instance_id` = `0x0001`
- `method_id` = `0x0001` (event notifications)
- Volume: 3000 notifications enviadas o mais rápido possível (tight loop)

---

### `fuzzy_sd_offer_rand_noti(1/2/3).pcap` — Protocol Fuzzing

Modela um nó malicioso que tenta estressar e confundir a comunicação orientada a serviços
anunciando um grande número de identificadores de serviço/evento aleatorizados e emitindo
simultaneamente event notifications sem semântica real. O atacante perturba primariamente
o Service Discovery e a consistência do modelo de serviços injetando muitas instâncias
de serviço sintéticas, o que pode aumentar o tráfego de discovery, ampliar o estado
no lado receptor e criar ambiguidade para lógica de monitoramento que espera
uma topologia de serviços estável.

| Campo | Valor |
|---|---|
| Tamanho | 219 MB / 127 MB / 216 MB |
| Ataque | Fuzzing |
| Atacante (1) | `172.18.0.17` |
| Atacante (2,3) | `172.18.0.12` |

**Componente A — SD identifier fuzzing:**
- L4: UDP dst port = `30490` (SOME/IP SD)
- `service_id` = `0xFFFF` (SD), `method_id` = `0x8100`, `msg_type` = `0x02` (Notification)
- SD Entry type: `OfferService`

**Componente B — ADAS fuzzing notifications (payload aleatório de tamanho fixo):**
- `service_id` = `0x1001`, `instance_id` = `0x0001`
- `method_id` = `0x0001`, `eventgroup_id` = `0x0001`

---

### `mitm_multi_attacker.pcap` — MITM via Event Relay + SD Spoofing (2 atacantes)

Modela um adversário que se posiciona entre um publicador legítimo e os subscribers
em uma rede SOME/IP. O atacante primeiro intercepta o stream de eventos ADAS legítimo,
então retransmite o mesmo payload através de um serviço malicioso criando um "middle hop"
controlado pelo atacante. Em paralelo, emite tráfego SD falsificado que pode forçar
os receptores a abandonarem o provedor legítimo (disrupção de disponibilidade), enquanto
simultaneamente impersona o serviço original e transmite um stream de notificações ADAS forjado.

| Campo | Valor |
|---|---|
| Tamanho | 239 MB |
| Ataque | Man-in-the-Middle |
| Atacantes | `172.18.0.14`, `172.18.0.15` |

**Componente A — Relay stage (Attacker → subscribers):**
- `service_id` = `0x100B`, `instance_id` = `0x000B`
- `method_id` = `0x0001`, `eventgroup_id` = `0x0001`
- Payload: cópia byte-a-byte do evento ADAS legítimo (service_id `0x1001`)

**Componente B — SD spoofing (UDP → vítima):**
- UDP dst port = `30490`; `service_id` = `0xFFFF`; SD Entry TTL = `0x000000` (withdraw)
- `IP.src` = `172.18.0.10` (forjado); `IP.dst` = `172.18.0.2`

**Componente C — Injection/impersonation:**
- `service_id` = `0x1001`, `instance_id` = `0x0001`
- `method_id` = `0x0001`, `eventgroup_id` = `0x0001`

---

### `mitm_single_attacker.pcap` — MITM via SD Withdraw + Event Injection (1 atacante)

Modela um adversário que interfere com a rede SOME/IP (i) perturbando o binding
da vítima ao provedor legítimo via semântica SD withdraw, e (ii) impersonando o
serviço original para injetar notificações ADAS forjadas.

| Campo | Valor |
|---|---|
| Tamanho | 205 MB |
| Ataque | Man-in-the-Middle |
| Atacante | `172.18.0.13` |

**Componente A — SD withdraw (disrupção de serviço):**
- UDP dst port = `30490`; `service_id` = `0xFFFF`; `msg_type` = `0x02`
- SD Entry TTL = `0x000000` (withdraw); `service_id` retirado = `0x1001`
- Endpoint anunciado: `172.18.0.10`, TCP `30501`, UDP `31097`

**Componente B — Forged ADAS event injection:**
- `service_id` = `0x1001`, `instance_id` = `0x0001`
- `method_id` = `0x0001`, `eventgroup_id` = `0x0001`

---

## Dataset Alkhatib et al.

> **Fonte:** https://github.com/alkhatib99/someip_traces  
> **Labels por pacote:** pasta `dataframes/` do repositório someip_traces  
> **Referência:** Alkhatib et al., "SOME/IP Intrusion Detection", 2021

PCAPs gerados via simulação em ambiente Docker com `vsomeip`.
Os labels por pacote estão nos CSVs correspondentes em `someip_traces/dataframes/`.

---

### `fakeClientID.pcap` / `fakeClientID2.pcap` — FakeClientID Attack

Cliente legítimo usa `client_id` fixo atribuído pelo servidor. O atacante injeta REQUESTs
rotacionando múltiplos `client_id` falsos para a mesma sessão, violando a unicidade do campo.
Feature discriminante: `f22_src_clientid_diversity` (janela de client_ids únicos por IP src).

| Campo | Valor |
|---|---|
| Tamanho | 188 KB / 135 KB |
| Label CSV | `fakeclientid1.csv` / `fakeclientid2.csv` |
| Usado em | Treino (label=5) |

---

### `eerror.pcap` — Error on Error

Servidor que já retornou ERROR recebe nova requisição e responde com ERROR novamente —
padrão anômalo de retransmissão de erro violando o fluxo normal REQUEST→RESPONSE.

| Campo | Valor |
|---|---|
| Tamanho | 7.3 MB |
| Usado em | Out-of-scope (teste de robustez) |

---

### `eevent.pcap` — Error on Event

ERROR enviado em resposta a uma NOTIFICATION (evento), violando a semântica
REQUEST/RESPONSE do SOME/IP onde eventos não esperam resposta de erro.

| Campo | Valor |
|---|---|
| Tamanho | 135 KB |
| Usado em | Out-of-scope |

---

### `drequest.pcap` — Missing Request

RESPONSE enviada sem REQUEST correspondente — servidor responde a uma
requisição inexistente no histórico da sessão.

| Campo | Valor |
|---|---|
| Tamanho | 184 KB |
| Usado em | Out-of-scope |

---

### `dresponse.pcap` — Missing Response

REQUEST enviada mas sem RESPONSE — cliente não recebe confirmação
dentro do timeout esperado.

| Campo | Valor |
|---|---|
| Tamanho | 200 KB |
| Usado em | Out-of-scope |

---

### `deleteRequest_test1.pcap` — Delete Request (Teste)

Cenário de teste com remoção de REQUEST da sequência antes que o servidor processe,
criando uma janela de estado inconsistente.

| Campo | Valor |
|---|---|
| Tamanho | 112 KB |
| Usado em | Out-of-scope |

---

### `wrongInterface.pcap` / `wrongInterface2.pcap` — Wrong Interface

Mensagem enviada para `service_id`/`method_id` incorretos — cliente tenta acessar
interface inexistente ou com versão incompatível.

| Campo | Valor |
|---|---|
| Tamanho | 179 KB / 133 KB |
| Usado em | Out-of-scope |

---

## Mapeamento: PCAP → Pipeline

```
00_download.py
├── Figshare   → benign_traffic, dos_noti_flood, fuzzy×3, mitm×2   (Kim, ~1.4 GB)
└── git clone  → fakeClientID×2, eerror, eevent, drequest, dresponse,
                 deleteRequest_test1, wrongInterface×2               (Alkhatib, ~10 MB)

01_parse.py  → data/parsed/*.csv   (um CSV por PCAP)

Classificador Binário (Kim)
  03_features.py → XGBoost 18 features
  Dados: benign + dos + fuzzy×3 + mitm×2

Classificador Multiclasse (Kim + Alkhatib)
  multiclass/01_features.py → 5 classes base (Kim)
  fake_client_id/01_features.py → label=5 (fakeClientID×2 + CSVs labels)
  multiclass/01b_merge_fakeclientid.py → XGBoost 13 features, 6 classes

  multiclass/03_test_outofscope.py
  └── eerror, eevent, drequest, dresponse, wrongInterface×2
```

---

## Labels

| label | Classe | Dataset |
|---|---|---|
| 0 | Benigno | Kim + Alkhatib |
| 1 | DoS | Kim |
| 2 | Fuzzy | Kim |
| 3 | MITM_Multi | Kim |
| 4 | MITM_Single | Kim |
| 5 | FakeClientID | Alkhatib |

---

## Como usar

```bash
# Clonar apenas os PCAPs Alkhatib
git clone https://github.com/GuilhermeFrick/SOMEIP_Dataset.git

# Ou usar o script de download do pipeline (recomendado — obtém tudo)
cd detection/
python src/00_download.py
```
