# SOME/IP IDS — Dataset de PCAPs

Repositório de capturas de rede (PCAPs) para treinamento e avaliação de um
Sistema de Detecção de Intrusão (IDS) para o protocolo **SOME/IP** (AUTOSAR).

Contém os PCAPs do dataset **Alkhatib et al.** (pequenos, comprometidos diretamente).
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

## Catálogo completo de PCAPs

### Dataset Kim et al. — Figshare
> Fonte: https://figshare.com/articles/dataset/SOME_IP_traffic_normal_and_abnormal_traffic_/30970450
> Baixado automaticamente por `00_download.py`

| Arquivo | Tamanho | Ataque | IP(s) Atacante | Descrição |
|---|---|---|---|---|
| `benign_traffic.pcap` | 213 MB | — | — | Tráfego SOME/IP normal entre servidores e clientes legítimos. Usado como classe benigna em todos os classificadores. |
| `dos_noti_flood.pcap` | 186 MB | DoS | `172.18.0.11` | Ataque de negação de serviço por inundação de mensagens SOME/IP NOTIFICATION no canal SD, sobrecarregando subscribers. |
| `fuzzy_sd_offer_rand_noti(1).pcap` | 219 MB | Fuzzy | `172.18.0.17` | Ataque fuzzy: envio de SD OFFERs e NOTIFICATIONs com campos aleatórios (service_id, method_id, payload), visando corromper o estado do SD. |
| `fuzzy_sd_offer_rand_noti(2).pcap` | 127 MB | Fuzzy | `172.18.0.12` | Segunda variação do ataque fuzzy (mesmo tipo, IP atacante diferente). |
| `fuzzy_sd_offer_rand_noti(3).pcap` | 216 MB | Fuzzy | `172.18.0.12` | Terceira variação do ataque fuzzy com maior volume de tráfego. |
| `mitm_multi_attacker.pcap` | 239 MB | MITM | `172.18.0.14`, `172.18.0.15` | Man-in-the-Middle com dois atacantes coordenados interceptando e retransmitindo mensagens SOME/IP entre cliente e servidor legítimos. |
| `mitm_single_attacker.pcap` | 205 MB | MITM | `172.18.0.13` | Man-in-the-Middle com atacante único que intercepta e replica o tráfego SD, realizando relay entre cliente e servidor. |

---

### Dataset Alkhatib et al. — Este repositório
> Fonte: simulação em ambiente Docker com vsomeip
> Referência: Alkhatib et al., "SOME/IP Intrusion Detection", 2021
> Label por pacote disponível em: https://github.com/alkhatib99/someip_traces (pasta `dataframes/`)

| Arquivo | Tamanho | Ataque/Anomalia | Descrição | Usado em |
|---|---|---|---|---|
| `fakeClientID.pcap` | 188 KB | FakeClientID | Cliente legítimo com `client_id` fixo; atacante injeta REQUESTs rotacionando múltiplos `client_id` falsos para a mesma sessão, violando unicidade do campo. | Treino (label=5) |
| `fakeClientID2.pcap` | 135 KB | FakeClientID | Segunda captura do mesmo ataque FakeClientID com diferente semente de simulação. | Treino (label=5) |
| `eerror.pcap` | 7.3 MB | ErrorOnError | Servidor que já retornou ERROR recebe nova requisição e responde com ERROR novamente — padrão anômalo de retransmissão de erro. | Out-of-scope |
| `eevent.pcap` | 135 KB | ErrorOnEvent | ERROR enviado em resposta a uma NOTIFICATION (evento), violando a semântica REQUEST/RESPONSE do SOME/IP. | Out-of-scope |
| `drequest.pcap` | 184 KB | MissingRequest | RESPONSE enviada sem REQUEST correspondente — servidor responde a uma requisição inexistente. | Out-of-scope |
| `dresponse.pcap` | 200 KB | MissingResponse | REQUEST enviada mas sem RESPONSE — cliente não recebe confirmação dentro do timeout esperado. | Out-of-scope |
| `deleteRequest_test1.pcap` | 112 KB | DeleteRequest | Cenário de teste com remoção de REQUEST da sequência antes que o servidor processe. | Out-of-scope |
| `wrongInterface.pcap` | 179 KB | WrongInterface | Mensagem enviada para `service_id`/`method_id` incorretos — cliente tenta acessar interface inexistente. | Out-of-scope |
| `wrongInterface2.pcap` | 133 KB | WrongInterface | Segunda variação do WrongInterface com diferente combinação de serviço/método errado. | Out-of-scope |

---

## Mapeamento: PCAP → Pipeline

```
00_download.py
├── Figshare → benign_traffic.pcap, dos_noti_flood.pcap, fuzzy×3, mitm×2
└── git clone SOMEIP_Dataset → fakeClientID×2, eerror, eevent, drequest, dresponse,
                                deleteRequest_test1, wrongInterface×2

01_parse.py  (todos os PCAPs acima → data/parsed/*.csv)

03_features.py  (data/parsed/*.csv → data/features/)
    ├── Binário Kim: benign + dos + fuzzy×3 + mitm×2        (18 features, XGBoost)
    └── Multiclasse: acima + fakeClientID×2                  (13 features, XGBoost 6 classes)

fake_client_id/01_features.py
    └── fakeClientID×2 (PCAP) + fakeclientid{1,2}.csv (labels) → features para label=5

multiclass/03_test_outofscope.py
    └── eerror, eevent, drequest, dresponse, wrongInterface×2 → testes fora do escopo
```

---

## Labels por dataset

### Kim et al. (binário: 0=benigno, 1=ataque)
| label | Classe |
|---|---|
| 0 | Benigno (tráfego normal) |
| 1 | Ataque (src_ip ∈ conjunto de atacantes do PCAP) |

### Alkhatib — Multiclasse
| label | Classe |
|---|---|
| 0 | Benigno |
| 1 | DoS |
| 2 | Fuzzy |
| 3 | MITM_Multi |
| 4 | MITM_Single |
| 5 | FakeClientID |

---

## Como usar

```bash
# Clonar este repositório de dataset
git clone https://github.com/GuilhermeFrick/SOMEIP_Dataset.git data/raw_alkhatib

# Ou usar o script de download do pipeline (recomendado)
cd detection/
python src/00_download.py
```

O script `00_download.py` clona este repositório e baixa os PCAPs Kim do Figshare,
colocando tudo em `detection/data/raw/` automaticamente.

---

## Referências

- **Kim et al.**: Kim, S. et al. "Autosar SOME/IP Intrusion Detection Dataset." Figshare, 2024.
  https://figshare.com/articles/dataset/SOME_IP_traffic_normal_and_abnormal_traffic_/30970450

- **Alkhatib et al.**: Alkhatib, A. et al. "SOME/IP Intrusion Detection System." GitHub, 2021.
  https://github.com/alkhatib99/someip_traces
