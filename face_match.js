/**
 * face_match.js — Comparação de descritores faciais (128 dimensões,
 * padrão face-api.js / face-recognition-net).
 *
 * IMPORTANTE: o reconhecimento facial roda todo no NAVEGADOR do
 * colaborador (face-api.js). O servidor nunca recebe a foto em si
 * para "olhar o rosto" — recebe apenas o vetor numérico (descriptor)
 * já calculado pelo navegador, e compara com o vetor de referência
 * cadastrado. Isso reduz superfície de exposição de dado biométrico
 * (LGPD, Art. 5º, II — dado biométrico é dado sensível).
 */

const DESCRIPTOR_LENGTH = 128;
const DEFAULT_THRESHOLD = 0.5; // menor = mais rígido. face-api.js recomenda ~0.6 como limite máximo.

const THRESHOLD = parseFloat(process.env.FACE_MATCH_THRESHOLD || DEFAULT_THRESHOLD);

function euclideanDistance(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    const diff = a[i] - b[i];
    sum += diff * diff;
  }
  return Math.sqrt(sum);
}

function isValidDescriptor(d) {
  return Array.isArray(d) && d.length === DESCRIPTOR_LENGTH && d.every(n => typeof n === 'number' && Number.isFinite(n));
}

/**
 * @param {number[]} referenceDescriptor vetor cadastrado do usuário
 * @param {number[]} candidateDescriptor vetor capturado no momento da assinatura
 * @returns {{ match: boolean, distance: number|null, threshold: number, error?: string }}
 */
function isMatch(referenceDescriptor, candidateDescriptor) {
  if (!isValidDescriptor(referenceDescriptor) || !isValidDescriptor(candidateDescriptor)) {
    return { match: false, distance: null, threshold: THRESHOLD, error: 'Descritor facial inválido' };
  }
  const distance = euclideanDistance(referenceDescriptor, candidateDescriptor);
  return { match: distance <= THRESHOLD, distance, threshold: THRESHOLD };
}

module.exports = { isMatch, euclideanDistance, isValidDescriptor, THRESHOLD, DESCRIPTOR_LENGTH };
