# Assinatura Digital Local — integrada ao Holerite Digital

## O que foi adicionado

Uma alternativa **gratuita e local** ao D4Sign (que já existia no sistema),
para o colaborador assinar o holerite direto pelo portal, sem precisar
baixar, assinar por fora e reenviar o PDF.

Novos arquivos:
- `signature_engine.js` — gera/usa chave RSA-2048 local (equivalente a um
  certificado autoassinado) e assina/verifica documentos
- `email_service.js` — envia o código de confirmação por e-mail (modo dev
  se `SMTP_HOST` não estiver configurado — o código sai no console e em
  `pending_codes.log`)
- `signed_pdf.js` — gera o PDF final: holerite original + folha de
  assinatura com nome do assinante, hash SHA-256 e QR code

Tabelas novas (criadas automaticamente pelo `database.js`):
- `local_signature_codes` — códigos pendentes de confirmação (expiram em 5 min)
- `local_signatures` — assinaturas confirmadas (hash, assinatura, assinante)

Rotas novas em `server.js`:
- `POST /api/holerites/:id/assinatura-local/solicitar-codigo` — `{ email }`
- `POST /api/holerites/:id/assinatura-local/confirmar` — `{ token, codigo }`
- `GET  /api/holerites/:id/assinatura-local` — metadados da assinatura
- `GET  /api/assinatura-local/certificado` — identidade/chave pública

Frontend (`index.html`): na tela "Enviar Holerite Assinado" (colaborador),
foi adicionada a opção **"Assinar digitalmente agora"** acima do fluxo
manual existente — que continua funcionando normalmente como alternativa.

## Como funciona

1. Colaborador escolhe o holerite pendente e informa o e-mail
2. Sistema envia um código de 6 dígitos (válido 5 min, até 5 tentativas)
3. Ao confirmar o código, o sistema:
   - Calcula o hash SHA-256 do PDF original e assina com RSA-PSS
   - Gera o PDF final (original + folha de assinatura com QR code)
   - Marca o holerite como `assinado` (mesmo status usado pelo D4Sign e
     pelo upload manual — nada mais no sistema precisou mudar)

## Reconhecimento facial (alternativa ao código por e-mail)

Agora, na mesma tela, o colaborador pode escolher **🤳 Reconhecimento facial**
em vez do código por e-mail — útil para assinar pelo celular sem precisar
checar a caixa de entrada.

Novos arquivos:
- `face_match.js` — compara o vetor facial (descriptor de 128 posições)
  capturado no momento da assinatura com o vetor cadastrado do usuário
  (distância euclidiana, limite configurável por `FACE_MATCH_THRESHOLD`,
  padrão `0.5`)

Novas tabelas (criadas automaticamente pelo `database.js`):
- `face_references` — vetor facial de referência de cada usuário (cadastro único)
- `local_signature_facial_requests` — solicitações de assinatura facial pendentes

Novas rotas em `server.js`:
- `POST   /api/face/cadastrar` — `{ descriptor, selfie? }` (cadastra/atualiza o rosto do usuário logado)
- `GET    /api/face/status` — indica se o usuário já tem rosto cadastrado
- `DELETE /api/face/cadastrar` — remove o cadastro facial do usuário logado
- `POST   /api/holerites/:id/assinatura-local/facial/solicitar` — inicia a assinatura (exige cadastro prévio)
- `POST   /api/holerites/:id/assinatura-local/facial/confirmar` — `{ token, descriptor, selfie? }`

### Como funciona

1. **Cadastro (uma vez só):** o colaborador liga a câmera, o navegador
   (biblioteca `face-api.js`) detecta o rosto e extrai um vetor numérico
   de 128 posições. Só esse vetor é enviado ao servidor e salvo — **a
   imagem nunca é usada no servidor para comparar rostos**. A selfie é
   opcional e fica só como evidência de auditoria (igual ao QR code do
   fluxo por e-mail).
2. **Assinatura:** ao escolher "Reconhecimento facial", a câmera liga de
   novo, o navegador extrai um novo vetor e o servidor compara com o vetor
   cadastrado (`face_match.js`). Se a distância ficar dentro do limite, o
   sistema assina o documento exatamente como no fluxo por e-mail (hash
   SHA-256 + RSA-PSS + PDF final com QR code) e registra
   `verification_method = 'facial'` na assinatura.
3. Expira em 5 minutos e tem limite de 5 tentativas, igual ao código por e-mail.

### Setup necessário (uma vez, no servidor)

A biblioteca `face-api.js` é carregada via CDN no `index.html`, mas os
**arquivos de peso dos modelos** (~6 MB) precisam estar publicados em
`/models` (ex.: `public/models/`) para funcionar de forma confiável e sem
depender de terceiros para dado sensível. Baixe os modelos
`tiny_face_detector`, `face_landmark_68` e `face_recognition` do
repositório oficial do face-api.js e coloque-os nessa pasta.

### ⚠️ Atenção — LGPD (dado biométrico)

O vetor facial é **dado sensível** (LGPD, Art. 5º, II). Antes de ativar
essa opção para os colaboradores:
- Peça consentimento explícito no cadastro (ex.: checkbox de aceite);
- Ofereça uma forma de o colaborador excluir o cadastro (`DELETE
  /api/face/cadastrar` já existe — falta só o botão na tela de perfil);
- Documente a finalidade (assinatura de holerite) e o prazo de guarda no
  seu aviso de privacidade.
- Assim como o RSA local, essa é uma assinatura **avançada** (não
  ICP-Brasil) — mesma tabela de níveis do `README.md` se aplica.

## Configurar e-mail (produção)

```bash
export SMTP_HOST=smtp.seuservidor.com
export SMTP_PORT=587
export SMTP_USER=seu_usuario
export SMTP_PASS=sua_senha
export SMTP_FROM=holerite@easynet.com.br
```

Sem isso, o sistema roda em modo dev (código aparece no console/log) —
útil para testar sem SMTP configurado.

## Caminho para certificadora oficial (ICP-Brasil)

`signature_engine.js` isola toda a lógica de assinatura — para evoluir
para um certificado oficial, basta trocar a chave carregada em
`_loadPrivateKey()` (A1 importado, A3 via PKCS#11, ou nuvem via API da AC)
e ajustar `getIdentity()`. Nenhuma rota do `server.js` precisa mudar.
