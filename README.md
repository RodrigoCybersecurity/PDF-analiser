# PDF Analiser

Sistema de triagem e análise de arquivos para **PDF** e **JPEG**, com foco em **segurança**, **isolamento** e **integração simples com frontend**.

O projeto combina **análise estática**, **sanitização de imagens** e **execução isolada em sandbox Docker** para decidir se um arquivo pode ser aceito com segurança ou deve ser rejeitado.

---

## Visão geral

Este repositório foi criado para receber arquivos enviados por usuários, analisar o conteúdo e devolver um resultado objetivo:

- **arquivo aceito**: o sistema retorna o arquivo aprovado ou sanitizado
- **arquivo rejeitado**: o sistema descarta o arquivo e retorna o motivo
- **relatório JSON**: cada execução pode gerar um relatório com o veredito da análise

Além do fluxo por linha de comando, o projeto também pode ser exposto por uma **API HTTP**, permitindo integração com qualquer frontend que consiga enviar `multipart/form-data`.

---

## Principais capacidades

### PDFs
- identificação do tipo de arquivo por extensão e assinatura
- análise estática com indicadores suspeitos
- envio para sandbox quando necessário
- validação adicional por ferramentas do ecossistema PDF
- rejeição de arquivos com comportamento suspeito ou malformado

### JPEGs
- validação da estrutura básica do arquivo
- detecção de anomalias simples no conteúdo
- reencode da imagem para remover metadados e reconstruir o arquivo
- retorno de uma versão sanitizada quando o arquivo é considerado seguro

### Integração web
- endpoint HTTP para upload
- resposta binária quando o arquivo é aprovado
- resposta JSON quando o arquivo é rejeitado
- modelo simples, compatível com qualquer frontend

---

## Arquitetura

```text
Frontend
   ↓
Scanner API (FastAPI)
   ↓
Pipeline de análise
   ├─→ Triagem estática
   ├─→ Sanitização JPEG
   └─→ Sandbox Docker para PDFs suspeitos
   ↓
Decisão final
   ├─→ accepted
   └─→ rejected
```

---

## Estrutura do projeto

```text
PDF-analiser/
├── accepted/                         # Arquivos aprovados
├── examples/                         # Exemplos de integração
├── file_analyser/                    # Núcleo do pipeline de análise
├── incoming/                         # Arquivos recebidos
├── rejected/                         # Arquivos rejeitados
├── reports/                          # Relatórios gerados
├── sandbox/                          # Lógica de execução isolada
├── scanner_api/                      # API HTTP para integração com frontend
├── triage/                           # Regras e validações auxiliares
├── .gitignore
├── docker-compose.site-example.yml   # Exemplo de compose com site + scanner
├── docker-compose.yml                # Compose da sandbox
├── Dockerfile.api                    # Imagem da API
├── Dockerfile.sandbox                # Imagem da sandbox
├── README-INTEGRACAO-API.md          # Guia específico da API
├── README.md                         # Este arquivo
├── requirements-api.txt              # Dependências da API
└── requirements.txt                  # Dependências do núcleo
```

---

## Como o sistema funciona

## 1. Recebimento do arquivo

O fluxo começa quando um arquivo é enviado para análise. Isso pode acontecer de duas formas:

- pela **CLI**
- pela **API HTTP**

---

## 2. Identificação do tipo

O sistema verifica o tipo do arquivo com base em:

- extensão
- assinatura binária
- validações iniciais de integridade

Isso evita tratar um arquivo com extensão falsa como se fosse legítimo.

---

## 3. Pipeline por tipo de arquivo

### Fluxo de PDF

1. o arquivo é identificado como PDF
2. o sistema executa análise estática
3. se o arquivo parecer limpo, ele pode ser aceito
4. se houver sinais suspeitos, o arquivo é enviado para sandbox
5. a sandbox executa validações adicionais em ambiente isolado
6. o sistema decide se o PDF será aceito ou rejeitado

### Fluxo de JPEG

1. o arquivo é identificado como JPEG
2. a estrutura básica da imagem é validada
3. a imagem é reconstruída por reencode
4. metadados e conteúdo residual são removidos
5. a versão sanitizada é devolvida se o resultado for seguro

---

## 4. Decisão final

A análise termina com um veredito simples:

- `accepted`
- `rejected`

Quando aplicável, o sistema também registra:
- tipo do arquivo
- motivo da decisão
- caminho do arquivo de saída
- relatório JSON

---

## API HTTP

A pasta `scanner_api/` adiciona uma camada HTTP ao projeto, permitindo que qualquer frontend envie arquivos para análise.

### Endpoint principal

```http
POST /scan
```

### Entrada

A requisição deve ser enviada como `multipart/form-data` com um campo:

- `file`: arquivo a ser analisado

### Saídas possíveis

#### Arquivo aceito

**Status:** `200 OK`

Retorna o arquivo aprovado ou sanitizado no corpo da resposta.

Exemplo de header útil:

```http
X-Scan-Status: accepted
```

#### Arquivo rejeitado

**Status:** `422 Unprocessable Entity`

Exemplo:

```json
{
  "status": "rejected",
  "reason": "Arquivo suspeito",
  "report": {
    "decision": "rejected",
    "file_type": "pdf"
  }
}
```

#### Erro interno

**Status:** `500 Internal Server Error`

Exemplo:

```json
{
  "status": "error",
  "reason": "Falha interna no processamento"
}
```

---

## Como rodar localmente

## Requisitos

- Python 3.10+ recomendado
- Docker instalado e em execução
- Docker Compose disponível
- ambiente com permissão para criar arquivos temporários

---

## Instalação do núcleo

```bash
pip install -r requirements.txt
```

## Instalação da API

```bash
pip install -r requirements-api.txt
```

---

## Executando pela CLI

Exemplo genérico:

```bash
python -m file_analyser caminho/do/arquivo.pdf
```

> O comando exato pode variar conforme a forma como o módulo foi estruturado no seu ambiente.

---

## Executando a API

```bash
uvicorn scanner_api.app:app --host 0.0.0.0 --port 8000 --reload
```

Depois, acesse:

```text
http://localhost:8000/docs
```

A interface `/docs` do FastAPI permite testar o endpoint `/scan` sem precisar criar frontend primeiro.

---

## Executando com Docker

### Build da API

```bash
docker build -f Dockerfile.api -t pdf-scanner-api .
```

### Execução da API

```bash
docker run -p 8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  pdf-scanner-api
```

> O acesso ao socket Docker é importante porque o pipeline pode acionar a sandbox durante a análise de PDFs suspeitos.

---

## Docker Compose

Há um arquivo de exemplo para cenários em que o scanner roda junto com o site:

- `docker-compose.site-example.yml`

Esse modelo permite um fluxo como:

```text
frontend → backend do site → scanner-api → pipeline → sandbox
```

Também é possível usar um fluxo direto:

```text
frontend → scanner-api
```

---

## Sandbox

A sandbox existe para aumentar o isolamento durante a análise de PDFs suspeitos.

### Objetivo
Executar verificações adicionais em um ambiente mais restrito, reduzindo o risco de processar conteúdo potencialmente malicioso diretamente no host principal.

### Características desejadas
- sem acesso de rede
- filesystem restrito
- privilégios reduzidos
- limites de memória, CPU e processos
- execução descartável

### Observação
Para que esse fluxo funcione corretamente, o Docker precisa estar ativo no host.

---

## Exemplo de integração com frontend

Qualquer frontend capaz de enviar `FormData` pode usar a API.

### Exemplo em JavaScript

```javascript
async function enviarArquivo(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch("/scan", {
    method: "POST",
    body: formData
  });

  if (response.status === 200) {
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = file.name;
    a.click();

    URL.revokeObjectURL(url);
    return;
  }

  const error = await response.json();
  alert(error.reason || "Arquivo rejeitado");
}
```

---

## Exemplo de teste com cURL

```bash
curl -X POST http://localhost:8000/scan \
  -F "file=@teste.pdf" \
  --output resultado.pdf
```

### API

```bash
cd PDF-analiser                                      
pip install -r requirements-api.txt
uvicorn scanner_api.app:app --host 0.0.0.0 --port 8000
```
Depois só ir a **localhost:8000/docs**

### Shell

```bash
curl -i -X POST http://localhost:8000/scan \
  -F "file=@teste.pdf"
```

---

## Fluxo recomendado em produção

```text
Usuário envia arquivo
        ↓
Frontend
        ↓
Backend do site
        ↓
Scanner API
        ↓
Pipeline de análise
        ↓
Sandbox (quando necessário)
        ↓
Resposta final para o usuário
```

### Vantagens desse modelo
- desacopla o frontend da lógica de segurança
- evita expor detalhes internos do pipeline
- facilita escalabilidade futura
- permite auditoria e observabilidade

---

## Relatórios

O projeto pode registrar relatórios em JSON na pasta:

```text
reports/
```

Exemplo de estrutura:

```json
{
  "decision": "accepted",
  "reason": "Arquivo validado com sucesso",
  "file_type": "jpeg",
  "output_file": "/tmp/job-123/output.jpg"
}
```

Esses relatórios são úteis para:
- auditoria
- depuração
- rastreabilidade
- integração com logs externos

---

## Boas práticas recomendadas

Para uso real em ambiente web, é recomendável adicionar:

- limite de tamanho de upload
- timeout por requisição
- autenticação entre backend e scanner
- limpeza periódica de arquivos temporários
- logs estruturados
- monitoramento da sandbox
- rate limit
- tratamento explícito de concorrência

---

## Limitações atuais

Este projeto é uma **camada de triagem**, não uma garantia absoluta de benignidade.

Isso significa que:
- um arquivo aceito passou pelas verificações implementadas
- isso não equivale a afirmar que ele é 100% seguro em qualquer contexto
- o sistema deve ser visto como parte de uma estratégia maior de defesa

---

## Roadmap sugerido

Algumas melhorias naturais para evolução do projeto:

- testes automatizados
- CI/CD com GitHub Actions
- score de risco por arquivo
- filas assíncronas com Redis/Celery
- suporte a mais tipos de arquivo
- autenticação por API key
- dashboard administrativo
- observabilidade centralizada

---

## Desenvolvimento

### Fluxo sugerido com branch `dev`

```bash
git checkout master
git pull origin master

git checkout dev
git rebase master
```

Depois disso, aplique suas alterações, teste localmente e faça o commit.

---

## Documentação adicional

- `README-INTEGRACAO-API.md`: detalhes da integração HTTP
- `examples/`: exemplos de uso pelo frontend

---

## Contribuição

Contribuições são bem-vindas.

Se quiser propor melhorias, o fluxo recomendado é:

1. criar uma branch a partir de `dev`
2. implementar a alteração
3. testar localmente
4. abrir um Pull Request com contexto claro

---

## Licença

Defina aqui a licença do projeto, se aplicável.

Exemplo:

```text
MIT License
```

---

## Autor

<div>

<a href="https://github.com/RodrigoCybersecurity" style="text-decoration: none;">
  <img src="https://github.com/RodrigoCybersecurity.png" width="70px;" align="left"/>
</a>
<p><b style="color: white;">RodrigoCybersecurity</b></p>

<a href="https://github.com/0xthearchitect" style="text-decoration: none;">
  <img src="https://github.com/0xthearchitect.png" width="70px;" align="left"/>
</a>
<p><b style="color: white;">TheArchitect</b></p>

</div>

Se este projeto foi útil, considere manter a documentação, os testes e o modelo de threat assessment sempre atualizados.
