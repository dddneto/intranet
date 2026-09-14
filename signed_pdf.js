/**
 * signed_pdf.js — Gera o PDF final assinado: anexa uma folha de
 * assinatura ao holerite original, com nome do assinante, hash SHA-256
 * e um QR code (assinante + hash + data) para conferência rápida.
 */

const fs = require('fs');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const QRCode = require('qrcode');

async function _buildQrPng(content) {
  const dataUrl = await QRCode.toDataURL(content, { margin: 1, scale: 6 });
  return Buffer.from(dataUrl.split(',')[1], 'base64');
}

/**
 * @param {string} originalPath caminho do PDF original em disco
 * @param {object} meta { originalName, signerName, signerEmail, digest, signedAt, algorithm }
 * @returns {Buffer} bytes do PDF final (original + folha de assinatura)
 */
async function createSignedPdf(originalPath, meta) {
  const originalBytes = fs.readFileSync(originalPath);
  const originalPdf = await PDFDocument.load(originalBytes, { ignoreEncryption: true });

  const outPdf = await PDFDocument.create();
  const copiedPages = await outPdf.copyPages(originalPdf, originalPdf.getPageIndices());
  copiedPages.forEach((p) => outPdf.addPage(p));

  const page = outPdf.addPage([595.28, 841.89]); // A4
  const fontBold = await outPdf.embedFont(StandardFonts.HelveticaBold);
  const font = await outPdf.embedFont(StandardFonts.Helvetica);
  const fontMono = await outPdf.embedFont(StandardFonts.Courier);
  const gray = rgb(0.4, 0.4, 0.4);
  const black = rgb(0, 0, 0);

  const marginX = 56;
  let y = 800;

  page.drawText('Folha de Assinatura Digital', { x: marginX, y, size: 16, font: fontBold, color: black });
  y -= 16;
  page.drawText('EasyNet Telecomunicações — Holerite Digital', { x: marginX, y, size: 9, font, color: gray });
  y -= 34;

  const fields = [
    ['Documento assinado:', meta.originalName],
    ['Assinado por:', meta.signerName],
    ['E-mail confirmado:', meta.signerEmail],
    ['Verificação:', meta.verificationLabel || 'Código de confirmação por e-mail'],
    ['Data/hora (UTC):', meta.signedAt],
    ['Algoritmo:', meta.algorithm],
  ];
  fields.forEach(([label, value]) => {
    page.drawText(label, { x: marginX, y, size: 10, font: fontBold, color: black });
    page.drawText(String(value), { x: marginX + 130, y, size: 10, font, color: black });
    y -= 16;
  });

  y -= 6;
  page.drawText('Hash SHA-256:', { x: marginX, y, size: 10, font: fontBold, color: black });
  y -= 15;
  page.drawText(meta.digest.slice(0, 32), { x: marginX, y, size: 8, font: fontMono, color: black });
  y -= 11;
  page.drawText(meta.digest.slice(32), { x: marginX, y, size: 8, font: fontMono, color: black });
  y -= 20;

  const qrContent = `ASSINANTE:${meta.signerName}|HASH:${meta.digest}|DATA:${meta.signedAt}`;
  const qrPng = await _buildQrPng(qrContent);
  const qrImage = await outPdf.embedPng(qrPng);
  const qrSize = 130;
  page.drawImage(qrImage, { x: marginX, y: y - qrSize, width: qrSize, height: qrSize });

  page.drawText('Escaneie o QR code para conferir', {
    x: marginX + qrSize + 20, y: y - qrSize / 2, size: 8.5, font, color: gray,
  });
  page.drawText('o assinante, o hash e a data da assinatura.', {
    x: marginX + qrSize + 20, y: y - qrSize / 2 - 12, size: 8.5, font, color: gray,
  });

  page.drawText(
    'Certificado autoassinado (uso interno). Sem validade jurídica ICP-Brasil até integração com certificadora oficial.',
    { x: marginX, y: 40, size: 7, font, color: gray }
  );

  return Buffer.from(await outPdf.save());
}

module.exports = { createSignedPdf };
