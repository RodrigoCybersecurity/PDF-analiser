# File Analiser

Pipeline de triagem para dois tipos de ficheiro:

1. PDFs com análise estática + sandbox
2. JPEGs com sanitização por reencode seguro

## Estrutura

```text
.
├── file_analyser/         # CLI e pipeline principal em Python
├── triage/
│   ├── pdfid.py           # ferramenta de análise estática
│   ├── sanitize_jpeg.py   # wrapper standalone para sanitização JPEG
│   ├── triage.ps1         # wrapper PowerShell
│   └── triage.sh          # wrapper shell
├── sandbox/
│   └── analyze_inside.py  # análise executada dentro do contentor
├── incoming/              # PDFs/JPEGs a analisar
├── accepted/              # PDFs aceites e JPEGs sanitizados
├── rejected/              # PDFs/JPEGs rejeitados
├── reports/               # relatórios txt/json
├── docker-compose.yml
└── Dockerfile.sandbox
```

## Fluxo

Quando executas a CLI:

- para PDFs:
  - corre `pdfid.py`
  - se houver indicadores suspeitos, envia o ficheiro para a sandbox Docker
- para JPEGs:
  - valida a estrutura básica
  - descodifica a imagem
  - remove metadados e volta a codificar para um novo JPEG limpo
- no fim, o ficheiro seguro vai para `accepted/` e o rejeitado vai para `rejected/`

Os relatórios finais continuam a ser gravados em `reports/<nome>_verdict.json`.

## Como executar

### Python

Analisar um ficheiro:

```bash
python3 -m file_analyser incoming/sample_signed.pdf
```

```bash
python3 -m file_analyser incoming/foto.jpg
```

Analisar todos os ficheiros suportados em `incoming/`:

```bash
python3 -m file_analyser --incoming
```

### Shell

```bash
./triage/triage.sh incoming/sample_signed.pdf
```

### PowerShell

```powershell
powershell -ExecutionPolicy Bypass -File .\triage\triage.ps1 .\incoming\sample_signed.pdf
```

Sem argumentos, o wrapper PowerShell analisa todos os ficheiros suportados em `incoming/`.

### JPEG standalone

O script que testaste continua disponível:

```bash
python3 triage/sanitize_jpeg.py imagem.jpg imagem_clean.jpg --report reports/imagem.json
```

## Relatórios

Cada análise produz:

- `reports/<nome>_pdfid.txt`: saída completa do `pdfid.py` para PDFs
- `reports/<nome>_verdict.json`: veredito final do pipeline

O JSON inclui:

- `status`: `accepted` ou `rejected`
- `source`: `static`, `sandbox` ou `jpeg_sanitizer`
- `reasons`: motivos do veredito
- `checks`: detalhe técnico de cada etapa
- `artifacts`: caminhos para os ficheiros gerados

## Requisitos

- Python 3
- Pillow
- Docker com `docker compose`

Se um PDF for suspeito e a sandbox falhar, o pipeline falha em modo conservador e rejeita o ficheiro.
