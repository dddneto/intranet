/**
 * totp.js — TOTP (RFC 6238) compatível com Google Authenticator, Authy, etc.
 * ==========================================================================
 * Implementação própria (HMAC-SHA1, base32), sem dependências externas —
 * usa apenas o módulo `crypto` nativo do Node.
 */

const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP = 30;     // segundos por janela de código (padrão Google Authenticator)
const DIGITS = 6;    // dígitos do código
const WINDOW = 1;    // tolerância de ±1 janela (±30s) para diferenças de relógio

function base32Encode(buffer) {
  let bits = 0, value = 0, output = '';
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(str) {
  str = String(str).replace(/=+$/, '').toUpperCase().replace(/\s+/g, '');
  let bits = 0, value = 0;
  const bytes = [];
  for (const char of str) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** Gera um novo segredo aleatório (base32), pronto para exibir/escanear. */
function generateSecret(byteLength = 20) {
  return base32Encode(crypto.randomBytes(byteLength));
}

function hotp(secretBuffer, counter) {
  const buf = Buffer.alloc(8);
  let tmp = counter;
  for (let i = 7; i >= 0; i--) {
    buf[i] = tmp % 256;
    tmp = Math.floor(tmp / 256);
  }
  const hmac = crypto.createHmac('sha1', secretBuffer).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (code % 10 ** DIGITS).toString().padStart(DIGITS, '0');
}

function generateTOTP(base32Secret, timestamp = Date.now()) {
  const counter = Math.floor(timestamp / 1000 / STEP);
  return hotp(base32Decode(base32Secret), counter);
}

/** Verifica um código de 6 dígitos com tolerância de ±1 janela (relógio do celular). */
function verifyTOTP(base32Secret, token) {
  if (!base32Secret || !token) return false;
  const clean = String(token).trim();
  if (!/^\d{6}$/.test(clean)) return false;
  const secretBuffer = base32Decode(base32Secret);
  const counter = Math.floor(Date.now() / 1000 / STEP);
  for (let w = -WINDOW; w <= WINDOW; w++) {
    if (hotp(secretBuffer, counter + w) === clean) return true;
  }
  return false;
}

/** Monta a URI otpauth:// usada para gerar o QR code do app autenticador. */
function buildOtpAuthUrl({ secret, accountName, issuer = 'EasyNet Holerite Digital' }) {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({
    secret, issuer, algorithm: 'SHA1', digits: String(DIGITS), period: String(STEP),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

module.exports = { generateSecret, generateTOTP, verifyTOTP, buildOtpAuthUrl };
