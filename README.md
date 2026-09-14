# 🇧🇷 Servidor de Assinatura Digital Local

Servidor de assinatura digital **100% local** conforme a base legal brasileira.

## Base Legal
- **Lei 14.063/2020** - Classificação das assinaturas eletrônicas
- **MP 2.200-2/2001** - ICP-Brasil
- **Decreto 10.543/2020** - Regulamentação
- **LGPD (Lei 13.709/2018)** - Proteção de dados

## Arquitetura

```
┌─────────────┐     HTTP      ┌─────────────────┐
│  Frontend   │ ◄────────────►│  API FastAPI    │
│  (HTML/JS)  │   (CORS)      │  Porta 8443     │
└─────────────┘               └─────────────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    ▼                  ▼                  ▼
            ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
            │  Certificados│    │  Documentos │    │   Auditoria  │
            │   (X.509)    │    │  Assinados  │    │   (LGPD)    │
            └─────────────┘    └─────────────┘    └─────────────┘
```

## Níveis de Assinatura Implementados

| Nível | Formato | Certificado | Uso |
|-------|---------|-------------|-----|
| Simples | Qualquer | Não obrigatório | Interações de menor impacto |
| Avançada | PAdES/CAdES/XAdES | Local (não ICP-Brasil) | Contratos B2B, saúde |
| Qualificada | PAdES/CAdES/XAdES | ICP-Brasil (externo) | NF-e, escrituras, petições |

## Como Usar

### 1. Instalação

```bash
# Clone ou extraia o projeto
cd servidor_assinatura_digital

# Instale as dependências
pip install -r requirements.txt
```

### 2. Iniciar o Servidor

```bash
# Método 1: Python direto
cd backend
python api_server.py

# Método 2: Docker
docker-compose up --build

# Método 3: Uvicorn
uvicorn backend.api_server:app --host 127.0.0.1 --port 8443 --ssl-keyfile data/certificates/server.key --ssl-certfile data/certificates/server.crt
```

### 3. Acessar Interface

Abra `frontend/index.html` no navegador ou acesse `http://localhost:8080` se usando Docker.

## Endpoints da API

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/` | Status do servidor |
| GET | `/legal/base` | Base legal completa |
| POST | `/certificates/issue` | Emitir certificado |
| GET | `/certificates` | Listar certificados |
| GET | `/certificates/{id}` | Detalhes do certificado |
| POST | `/certificates/{id}/revoke` | Revogar certificado |
| GET | `/certificates/{id}/validate` | Validar certificado |
| POST | `/documents/sign` | Assinar documento |
| POST | `/documents/verify` | Verificar assinatura |
| GET | `/documents/signatures` | Listar assinaturas |
| GET | `/documents/download/{id}` | Baixar documento |
| GET | `/audit/logs` | Logs de auditoria |

## Segurança

- **RSA-2048** para assinaturas
- **SHA-256** para hashing
- **AES-256-GCM** para proteção de chaves privadas
- **PBKDF2** com 100.000 iterações para derivação de chave
- **Carimbo de tempo** para não-repúdio
- **Logs de auditoria** conforme LGPD

## ⚠️ Aviso Importante

Este servidor emite certificados **locais** que **não** são reconhecidos pela ICP-Brasil. Para uso em produção com validade jurídica plena:

1. Adquira certificados ICP-Brasil de uma AC credenciada (Serasa, Certisign, Valid, etc.)
2. Para assinatura qualificada, é **obrigatório** o uso de certificado ICP-Brasil
3. A assinatura avançada é válida entre particulares mediante aceitação

## Licença

Código aberto conforme Art. 16 da Lei 14.063/2020.
