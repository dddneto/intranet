/**
 * signature_engine.js — Assinatura digital local (RSA-2048 + PSS/SHA-256)
 * ==========================================================================
 * Gera e usa um par de chaves local para assinar holerites dentro do
 * próprio sistema, sem depender de um serviço pago externo (D4Sign).
 *
 * Ponto de extensão para certificadora oficial (ICP-Brasil):
 *   Hoje a assinatura usa uma chave RSA local autogerada (equivalente a
 *   um certificado autoassinado). Para evoluir para um certificado oficial
 *   (A1/A3 ou nuvem ICP-Brasil), basta:
 *     1. Trocar a chave privada carregada em `_loadPrivateKey()` pela
 *        chave do certificado oficial (.pfx/.p12 convertido para PEM, ou
 *        acesso via PKCS#11 para token/HSM)
 *     2. Ajustar `getIdentity()` para refletir os dados do certificado
 *        oficial (emissor real, validade, CPF/CNPJ do titular)
 *   Nenhuma rota do server.js precisa mudar — a interface (sign/verify/
 *   getIdentity) permanece a mesma.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEYS_DIR = path.join(__dirname, 'keys');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'local_private.pem');
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, 'local_public.pem');
const IDENTITY_PATH = path.join(KEYS_DIR, 'identity.json');

function _ensureKeys() {
  if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) return;

  fs.mkdirSync(KEYS_DIR, { recursive: true });

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  fs.writeFileSync(PRIVATE_KEY_PATH, privateKey, { mode: 0o600 });
  fs.writeFileSync(PUBLIC_KEY_PATH, publicKey);

  const identity = {
    common_name: 'EasyNet Holerite Digital — Assinador Local',
    organization: 'EasyNet Telecomunicações',
    country: 'BR',
    issuer: 'Autoassinado (local) — SEM validade jurídica ICP-Brasil',
    generated_at: new Date().toISOString(),
    provider_type: 'local_self_signed',
  };
  fs.writeFileSync(IDENTITY_PATH, JSON.stringify(identity, null, 2));
}

function _loadPrivateKey() {
  _ensureKeys();
  return fs.readFileSync(PRIVATE_KEY_PATH, 'utf8');
}

function _loadPublicKey() {
  _ensureKeys();
  return fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
}

function getIdentity() {
  _ensureKeys();
  return JSON.parse(fs.readFileSync(IDENTITY_PATH, 'utf8'));
}

function getPublicKeyPem() {
  return _loadPublicKey();
}

/**
 * Assina os bytes de um buffer. Retorna metadados da assinatura
 * (não grava nada em disco — quem chama decide o que persistir).
 */
function sign(dataBuffer) {
  const privateKey = _loadPrivateKey();
  const digest = crypto.createHash('sha256').update(dataBuffer).digest('hex');

  const signature = crypto.sign('sha256', dataBuffer, {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
  });

  return {
    signature: signature.toString('base64'),
    digest_sha256: digest,
    algorithm: 'RSA-PSS-SHA256',
    signed_at: new Date().toISOString(),
    signer: getIdentity(),
  };
}

function verify(dataBuffer, signatureB64) {
  const publicKey = _loadPublicKey();
  try {
    return crypto.verify(
      'sha256',
      dataBuffer,
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      },
      Buffer.from(signatureB64, 'base64')
    );
  } catch {
    return false;
  }
}

module.exports = { sign, verify, getIdentity, getPublicKeyPem };
