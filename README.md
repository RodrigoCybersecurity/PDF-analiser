# PDF Analiser

Pipeline de triagem de PDFs com duas fases:

1. análise estática com `pdfid.py`
2. análise dinâmica numa sandbox Docker quando existem indicadores suspeitos

## Estrutura

```text
.
├── pdf_analyser/          # CLI e pipeline principal em Python
├── triage/
│   ├── pdfid.py           # ferramenta de análise estática
│   ├── triage.ps1         # wrapper PowerShell
│   └── triage.sh          # wrapper shell
├── sandbox/
│   └── analyze_inside.py  # análise executada dentro do contentor
├── incoming/              # PDFs a analisar
├── accepted/              # PDFs aceites
├── rejected/              # PDFs rejeitados
├── reports/               # relatórios txt/json
├── docker-compose.yml
└── Dockerfile.sandbox
```

## Fluxo

Quando executas a CLI:

- corre `pdfid.py` e guarda o relatório em `reports/<nome>_pdfid.txt`
- procura marcadores suspeitos como `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile` e `/URI`
- se não houver sinais suspeitos, aceita o ficheiro logo na fase estática
- se houver, envia o PDF para a sandbox Docker
- a sandbox tenta abrir o ficheiro com `evince`, observa o comportamento com `strace` e grava `reports/<nome>_verdict.json`
- no fim, o PDF é copiado para `accepted/` ou `rejected/`

## Como executar

### Python

Analisar um ficheiro:

```bash
python3 -m pdf_analyser incoming/sample_signed.pdf
```

Analisar todos os PDFs em `incoming/`:

```bash
python3 -m pdf_analyser --incoming
```

### Shell

```bash
./triage/triage.sh incoming/sample_signed.pdf
```

### PowerShell

```powershell
powershell -ExecutionPolicy Bypass -File .\triage\triage.ps1 .\incoming\sample_signed.pdf
```

Sem argumentos, o wrapper PowerShell analisa todos os PDFs em `incoming/`.

## Relatórios

Cada análise produz:

- `reports/<nome>_pdfid.txt`: saída completa do `pdfid.py`
- `reports/<nome>_verdict.json`: veredito final do pipeline

O JSON inclui:

- `status`: `accepted` ou `rejected`
- `source`: `static` ou `sandbox`
- `reasons`: motivos do veredito
- `checks`: detalhe técnico de cada etapa
- `artifacts`: caminhos para os ficheiros gerados

## Requisitos

- Python 3
- Docker com `docker compose`

Se o PDF for suspeito e a sandbox falhar, o pipeline falha em modo conservador e rejeita o ficheiro.
