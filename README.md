# IOC Extractor

Ferramenta em Python que **extrai Indicadores de Comprometimento (IOCs)** de alertas, tickets e e-mails de phishing, no estilo da rotina de um SOC Nível 1. Reconhece texto já "defanged" (`hxxp`, `[.]`), classifica IPs como públicos ou internos e exporta o resultado em Markdown, JSON ou CSV, sempre com **defang** para ser seguro de compartilhar.

Sem dependências externas (Python 3.9+). Não faz nenhuma requisição de rede.

## O que extrai

| Tipo | Detalhes |
|---|---|
| IPv4 | validação real e classificação: público, interno, loopback, link-local, reservado ou documentação |
| URLs | inclui as defanged (`hxxps://site[.]com`) |
| Domínios | de texto, URLs e e-mails; ignora nomes de arquivo como `payload.exe` ou `script.py` |
| E-mails | endereços do remetente, Reply-To e corpo |
| Hashes | MD5, SHA-1 e SHA-256 (descarta números longos formados só por dígitos) |
| CVEs | normalizadas em maiúsculas e contadas |

## Instalação e uso

```bash
git clone https://github.com/josuemdea8-pixel/ioc-extractor.git
cd ioc-extractor
python ioc_extractor.py samples/alerta_phishing.txt
```

Opções:

```text
arquivos                 .txt, .log ou .eml (use - para ler da entrada padrão)
--format md|json|csv     formato de saída (padrão md)
--ignore-domain DOMINIO  ignora um domínio e seus subdomínios (pode repetir)
--exclude-internal       remove IPs internos, loopback e link-local
--raw                    mostra os valores sem defang no Markdown (cuidado)
-o ARQUIVO               salva a saída em arquivo
```

Exemplos:

```bash
# Ignorar ruído de sites legítimos e IPs da rede interna
python ioc_extractor.py alerta.txt --ignore-domain microsoft.com --exclude-internal

# Exportar para CSV e subir numa planilha ou plataforma de TI
python ioc_extractor.py alerta.txt --format csv -o iocs.csv

# Ler direto da área de transferência/pipe
cat alerta.txt | python ioc_extractor.py -
```

## Exemplo de resultado

Com `samples/alerta_phishing.txt` (alerta **fictício**, IPs de documentação RFC 5737 e domínios `.example`), a ferramenta encontra 22 indicadores únicos: 6 IPs, 3 URLs, 5 domínios, 3 e-mails, 3 hashes e 2 CVEs. Veja [`samples/example_output.md`](samples/example_output.md) e [`samples/example_output.csv`](samples/example_output.csv).

## Testes

```bash
python -m unittest discover -s tests -v
```

9 testes cobrem defang/refang, classificação de IP, entradas inválidas, URLs defanged, falsos positivos de nome de arquivo, tipos de hash, CVEs, filtros e a exportação JSON/CSV/Markdown.

## Limitações

- Apenas IPv4 (IPv6 fica como próximo passo).
- Domínios são reconhecidos por padrão de texto, sem lista pública de sufixos; nomes de arquivo incomuns podem passar como domínio.
- Não consulta reputação dos IOCs. Próximo passo: enriquecer com VirusTotal e AbuseIPDB.
- Os IOCs extraídos devem ser validados por um analista antes de qualquer bloqueio.

## Autor

Josué Moreira, Analista SOC Júnior, Belém/PA.
