/**
 * email_service.js — Envio do código de confirmação de assinatura
 * ==========================================================================
 * Configuração via variáveis de ambiente:
 *   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
 *
 * Se SMTP_HOST não estiver definido, entra em "modo dev": o código não é
 * enviado de verdade, só aparece no console e em `pending_codes.log` —
 * útil para testar o fluxo sem servidor SMTP configurado.
 */

const fs = require('fs');
const path = require('path');

let nodemailer = null;
try { nodemailer = require('nodemailer'); } catch { /* opcional em modo dev */ }

const LOG_PATH = path.join(__dirname, 'pending_codes.log');
const LOGO_URL = 'https://easynet.com.br/assets/logo-sem-fundo-B6eWoACO.png';

function _buildHtml(name, code, documentName) {
  return `
  <div style="font-family:Arial,Helvetica,sans-serif;background:#f3f4f6;padding:32px 16px;">
    <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e5e7eb;">
      <div style="background:#0f172a;padding:24px;text-align:center;">
        <img src="${LOGO_URL}" alt="EasyNet Telecomunicações" style="max-width:180px;height:auto;">
      </div>
      <div style="padding:28px 24px;">
        <p style="font-size:15px;color:#111827;margin:0 0 12px;">Olá, <strong>${name}</strong>.</p>
        <p style="font-size:14px;color:#374151;margin:0 0 20px;line-height:1.5;">
          Use o código abaixo para confirmar a assinatura do documento
          "<strong>${documentName}</strong>":
        </p>
        <div style="text-align:center;margin:24px 0;">
          <span style="display:inline-block;font-size:28px;font-weight:700;letter-spacing:6px;color:#0f172a;background:#f3f4f6;border:1px solid #e5e7eb;border-radius:8px;padding:14px 20px;">
            ${code}
          </span>
        </div>
        <p style="font-size:13px;color:#6b7280;margin:0 0 6px;">Este código expira em 5 minutos.</p>
        <p style="font-size:13px;color:#6b7280;margin:0;">Se você não solicitou esta assinatura, ignore este e-mail.</p>
      </div>
      <div style="padding:14px 24px;background:#f9fafb;border-top:1px solid #e5e7eb;text-align:center;">
        <p style="font-size:11px;color:#9ca3af;margin:0;">EasyNet Telecomunicações — Holerite Digital</p>
      </div>
    </div>
  </div>`;
}

function _devFallback(email, code, name, documentName) {
  const line = `[MODO DEV] Código para ${name} <${email}> (doc: ${documentName}): ${code}\n`;
  console.log(line.trim());
  fs.appendFileSync(LOG_PATH, line);
}

async function sendVerificationCode(email, code, name, documentName) {
  const host = process.env.SMTP_HOST;

  if (!host || !nodemailer) {
    _devFallback(email, code, name, documentName);
    return true;
  }

  const transporter = nodemailer.createTransport({
    host,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_PORT === '465',
    auth: process.env.SMTP_USER
      ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
      : undefined,
  });

  const from = process.env.SMTP_FROM || process.env.SMTP_USER;

  const text =
    `Olá, ${name}.\n\n` +
    `Use o código abaixo para confirmar a assinatura do documento "${documentName}":\n\n` +
    `    ${code}\n\n` +
    `Se você não solicitou esta assinatura, ignore este e-mail.\n` +
    `Este código expira em 5 minutos.`;

  try {
    await transporter.sendMail({
      from,
      to: email,
      subject: 'Código de confirmação — Holerite Digital EasyNet',
      text,
      html: _buildHtml(name, code, documentName),
    });
    return true;
  } catch (err) {
    console.error('[ERRO] Falha ao enviar e-mail:', err.message);
    _devFallback(email, code, name, documentName);
    return false;
  }
}

module.exports = { sendVerificationCode };
