# Integração HTTP para o teu repositório

## O que foi adicionado

- `scanner_api/app.py`: API FastAPI com `POST /scan`
- `requirements-api.txt`: dependências da API
- `Dockerfile.api`: imagem da API
- `docker-compose.site-example.yml`: exemplo para subir junto com o site
- `examples/frontend-example.js`: exemplo mínimo de consumo pelo frontend

## Fluxo

1. O frontend envia um `multipart/form-data` com o campo `file`.
2. A API grava o ficheiro em `scanner_api/runtime_jobs/<job_id>/incoming/`.
3. A API chama `analyse_file(...)` do teu projeto atual.
4. Se o veredito for `accepted`, devolve o ficheiro final.
5. Se o veredito for `rejected`, devolve `422` com JSON.

## Endpoint

### `POST /scan`

Campo esperado:
- `file`

### Aprovação

Retorna `200 OK` com o próprio ficheiro aprovado.

Headers úteis:
- `X-Scan-Status: accepted`
- `X-Scan-Job: <uuid>`

### Rejeição

Retorna `422` com JSON:

```json
{
  "status": "rejected",
  "reason": "motivo",
  "job_id": "...",
  "report": {}
}
```

## Rodar local sem container

```bash
pip install -r requirements-api.txt
uvicorn scanner_api.app:app --host 0.0.0.0 --port 8000
```

## Rodar com container junto do site

```bash
export PDF_ANALISER_HOST_PATH=/caminho/absoluto/do/PDF-analiser
docker compose -f docker-compose.site-example.yml up --build
```

## Observação importante sobre Docker dentro do container

Como o teu pipeline atual chama `docker compose run ... sandbox`, a API em container precisa:

- do socket Docker do host (`/var/run/docker.sock`)
- do repositório montado no mesmo caminho esperado pelo container

Esse segundo ponto é necessário porque a sandbox usa bind mounts para enviar o PDF e receber o veredito.

## Frontend

Qualquer frontend que consiga enviar `multipart/form-data` consegue integrar.
