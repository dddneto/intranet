/**
 * afd_layout.js — Geração do AFD (Arquivo Fonte de Dados) no leiaute oficial
 * publicado pelo Ministério do Trabalho e Emprego:
 *   "Leiaute do Arquivo Fonte de Dados - AFD.pdf" (atualizado em 09/06/2022)
 *   https://www.gov.br/trabalho-e-emprego/pt-br/assuntos/inspecao-do-trabalho/
 *     fiscalizacao-do-trabalho/leiaute-do-arquivo-fonte-de-dados-afd.pdf
 *   (Anexo referenciado pelo art. 81 da Portaria MTP nº 671/2021)
 *
 * Este módulo implementa o leiaute específico do REP-P (Registrador
 * Eletrônico de Ponto via Programa), que é o modelo em uso neste sistema:
 *   - Registro tipo "1": Cabeçalho
 *   - Registro tipo "7": Marcação de ponto (REP-P — NÃO é o tipo "3",
 *     que é exclusivo de REP-C/REP-A)
 *   - Registro tipo "9": Trailer
 *   - Linha final: placeholder de assinatura digital (ver ATENÇÃO abaixo)
 *
 * Regras gerais do leiaute (itens 1 a 10 do documento oficial):
 *   - Texto em ISO-8859-1 (Latin-1), NÃO UTF-8.
 *   - Cada linha é um registro, terminando em \r\n (chars 13 e 10 ASCII).
 *   - Registros ordenados por NSR, sem linhas em branco.
 *   - Campos N (numérico): alinhados à direita, zeros à esquerda.
 *   - Campos A/D/DH (alfanumérico/data/data-hora): alinhados à esquerda,
 *     espaços à direita até completar o tamanho fixo do campo.
 *   - Registros tipo "1" a "5" levam CRC-16/KERMIT (CRC-16/CCITT-TRUE) do
 *     próprio registro nos últimos 4 caracteres (hex, sem "0x").
 *   - Registro tipo "7" leva hash SHA-256 (campo nº 8) em vez de CRC-16.
 *
 * ⚠️ ATENÇÃO — pendência legal que este módulo NÃO resolve sozinho:
 *   O art. 88 da Portaria 671/2021 exige que a assinatura eletrônica do
 *   REP-P use certificado ICP-Brasil (padrão CAdES, arquivo .p7s destacado
 *   do AFD). Enquanto isso não estiver implementado, a linha final deste
 *   arquivo é preenchida com o texto literal exigido pelo leiaute para
 *   indicar "assinatura em arquivo externo" — mas SEM um .p7s real
 *   acompanhando, o AFD gerado por este módulo ainda não está 100%
 *   conforme para fins de fiscalização. Ver painel /api/ponto/conformidade.
 */

const crypto = require('crypto');

// ───────────────────────── Helpers de formatação posicional ─────────────────

// Campo tipo N (numérico): mantém apenas dígitos, alinha à direita, zero-pad à esquerda.
function num(value, len) {
  const digits = String(value ?? '').replace(/\D/g, '');
  return (digits || '0').slice(-len).padStart(len, '0');
}

// Campo tipo A (alfanumérico): alinha à esquerda, espaço-pad à direita, trunca se maior.
function alfa(value, len) {
  return String(value ?? '').slice(0, len).padEnd(len, ' ');
}

// Campo tipo D (data): "AAAA-MM-dd", 10 caracteres, espaço-pad à direita se vazio.
function dataFmt(isoDate) {
  return alfa((isoDate || '').slice(0, 10), 10);
}

// Campo tipo DH (data e hora): "AAAA-MM-ddThh:mm:00ZZZZZ" — 24 caracteres.
// Brasil não usa mais horário de verão desde 2019, fuso de Brasília é -03:00 fixo.
function dhFmt(dataISO, horaHHMMSS) {
  const data = (dataISO || '').slice(0, 10);
  const hora = (horaHHMMSS || '00:00:00').slice(0, 5); // hh:mm
  return `${data}T${hora}:00-0300`;
}

// Constrói o campo DH a partir de um objeto Date (ex.: created_at do banco),
// convertendo para o fuso de Brasília.
function dhFromDate(date) {
  const d = date instanceof Date ? date : new Date(date);
  const dataStr = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Sao_Paulo', year: 'numeric', month: '2-digit', day: '2-digit',
  }).format(d);
  const horaStr = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'America/Sao_Paulo', hour12: false, hour: '2-digit', minute: '2-digit',
  }).format(d);
  return `${dataStr}T${horaStr}:00-0300`;
}

// ───────────────────────── CRC-16/KERMIT (CRC-16/CCITT-TRUE) ────────────────
// Exigido pelo item 8 do leiaute para os registros tipo "1" a "5".
// Vetor de teste oficial do documento: CRC16("123456789") deve dar "2189".
function crc16Kermit(str) {
  let crc = 0x0000;
  const buf = Buffer.from(str, 'latin1');
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc & 1) ? (crc >>> 1) ^ 0x8408 : (crc >>> 1);
    }
  }
  return crc.toString(16).toUpperCase().padStart(4, '0');
}

// Auto-teste do CRC contra o vetor oficial — roda uma vez ao carregar o módulo.
// Se isso disparar, o algoritmo do CRC está errado e o AFD será inválido.
if (crc16Kermit('123456789') !== '2189') {
  throw new Error('[afd_layout] Falha no auto-teste do CRC-16/KERMIT — implementação incorreta');
}

// ───────────────────────── Registro tipo "1" — Cabeçalho ────────────────────
function registroTipo1({
  cnpjEmpregador, nomeEmpregador, numeroRegistroInpi,
  dataInicial, dataFinal, dataHoraGeracao, cnpjDesenvolvedor,
}) {
  const cnpjLimpo = String(cnpjEmpregador || '').replace(/\D/g, '');
  const tipoIdentEmpregador = cnpjLimpo.length > 11 ? '1' : '2'; // 1=CNPJ, 2=CPF
  const cnpjDevLimpo = String(cnpjDesenvolvedor || '').replace(/\D/g, '');

  let corpo = '';
  corpo += num('0', 9);                                    // 1: fixo "000000000"
  corpo += '1';                                             // 2: tipo do registro
  corpo += tipoIdentEmpregador;                             // 3
  corpo += alfa(cnpjLimpo, 14);                             // 4: CNPJ/CPF empregador
  corpo += alfa('', 14);                                    // 5: CNO/CAEPF (não utilizado)
  corpo += alfa(nomeEmpregador, 150);                       // 6: razão social
  corpo += num(numeroRegistroInpi || '99999999999999999', 17); // 7: nº registro INPI
  corpo += dataFmt(dataInicial);                            // 8
  corpo += dataFmt(dataFinal);                              // 9
  corpo += alfa(dataHoraGeracao, 24);                       // 10
  corpo += '004';                                           // 11: versão do leiaute
  corpo += '1';                                             // 12: 1=CNPJ desenvolvedor
  corpo += alfa(cnpjDevLimpo, 14);                          // 13
  corpo += alfa('', 30);                                    // 14: modelo (só REP-C)

  return corpo + crc16Kermit(corpo);
}

// ───────────────────────── Registro tipo "7" — Marcação (REP-P) ─────────────
// Referência dos campos usados no hash (item 9 do leiaute):
//   NSR | tipo | data-hora marcação | CPF | data-hora gravação |
//   coletor | online/offline | hash SHA-256 do registro anterior
function calcularHashOficialTipo7({
  nsr, dataMarcacao, horaMarcacao, cpf, dataHoraGravacao, coletor, online, hashAnterior,
}) {
  const conteudo = [
    num(nsr, 9),
    '7',
    dhFmt(dataMarcacao, horaMarcacao),
    num(cpf, 12),
    dataHoraGravacao, // já em formato DH
    coletor,
    online,
    hashAnterior || '0'.repeat(64),
  ].join('');
  return crypto.createHash('sha256').update(conteudo, 'utf8').digest('hex');
}

// Mapa de origem do registro (como armazenado hoje em pontos_registros.origem)
// para o "identificador do coletor da marcação" exigido pelo leiaute.
function coletorFromOrigem(origem) {
  if (origem === 'portal') return '02'; // browser (navegador internet)
  if (origem === 'totem') return '04';  // dispositivo eletrônico
  return '05';                          // outro dispositivo não especificado
}

function registroTipo7({ nsr, dataMarcacao, horaMarcacao, cpf, dataHoraGravacao, coletor, online, hashRegistro }) {
  let corpo = '';
  corpo += num(nsr, 9);                                     // 1: NSR
  corpo += '7';                                              // 2: tipo do registro
  corpo += alfa(dhFmt(dataMarcacao, horaMarcacao), 24);      // 3: data/hora da marcação
  corpo += num(cpf, 12);                                     // 4: CPF do empregado
  corpo += alfa(dataHoraGravacao, 24);                       // 5: data/hora de gravação
  corpo += alfa(coletor, 2);                                 // 6: identificador do coletor
  corpo += alfa(online, 1);                                  // 7: 0=online, 1=offline
  corpo += alfa(hashRegistro, 64);                           // 8: código hash SHA-256
  return corpo;
}

// ───────────────────────── Registro tipo "9" — Trailer ──────────────────────
function registroTipo9({ qtdTipo2 = 0, qtdTipo3 = 0, qtdTipo4 = 0, qtdTipo5 = 0, qtdTipo6 = 0, qtdTipo7 = 0 }) {
  let corpo = '';
  corpo += num('9', 9).replace(/^0+/, '').padStart(9, '9'); // 1: fixo "999999999"
  corpo += num(qtdTipo2, 9);
  corpo += num(qtdTipo3, 9);
  corpo += num(qtdTipo4, 9);
  corpo += num(qtdTipo5, 9);
  corpo += num(qtdTipo6, 9);
  corpo += num(qtdTipo7, 9);
  corpo += '9'; // 8: tipo do registro
  return corpo;
}

// ───────────────────────── Linha de assinatura digital ──────────────────────
// Enquanto a assinatura ICP-Brasil real (CAdES, .p7s destacado) não estiver
// implementada (art. 88 da Portaria 671/2021), o leiaute exige preencher esta
// linha com o texto literal abaixo — mas isso NÃO substitui o .p7s real.
function linhaAssinaturaPlaceholder() {
  return alfa('ASSINATURA_DIGITAL_EM_ARQUIVO_P7S', 100);
}

module.exports = {
  num, alfa, dataFmt, dhFmt, dhFromDate,
  crc16Kermit,
  registroTipo1, registroTipo7, registroTipo9,
  calcularHashOficialTipo7, coletorFromOrigem,
  linhaAssinaturaPlaceholder,
};
