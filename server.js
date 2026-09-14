require('dotenv').config();
const express = require('express');

// Carregar config SMTP do banco na inicialização (white-label)
setTimeout(() => {
  db.all(`SELECT chave, valor FROM configuracoes WHERE chave LIKE 'smtp_%'`, [], (err, rows) => {
    if (err || !rows) return;
    const envMap = { smtp_host:'SMTP_HOST', smtp_port:'SMTP_PORT', smtp_user:'SMTP_USER', smtp_pass:'SMTP_PASS', smtp_from:'SMTP_FROM', smtp_from_name:'SMTP_FROM_NAME' };
    rows.forEach(({ chave, valor }) => {
      if (envMap[chave] && valor && !process.env[envMap[chave]]) {
        process.env[envMap[chave]] = valor;
      }
    });
    console.log('✅ Configurações SMTP carregadas do banco');
  });
}, 500);

const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { PDFDocument } = require('pdf-lib');
const { spawn } = require('child_process');
const os = require('os');
const db = require('./database');
const signatureEngine = require('./signature_engine');
const { sendVerificationCode } = require('./email_service');
const { createSignedPdf } = require('./signed_pdf');
const faceMatch = require('./face_match');
const totp = require('./totp');
const afdLayout = require('./afd_layout');
const QRCode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'easynet-secret-key-2024';

// Caminho absoluto para o script Python
const PYTHON_SCRIPT = path.join(__dirname, 'extract_holerites.py');

app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

// ===================== MIGRAÇÕES / TABELAS NOVAS =====================
db.run(`CREATE TABLE IF NOT EXISTS empresas ( 
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  nome TEXT NOT NULL, 
  cnpj TEXT UNIQUE, 
  status TEXT DEFAULT 'ativo', 
  observacao TEXT, 
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP, 
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP 
)`);

db.run(`CREATE TABLE IF NOT EXISTS permissoes_admin ( 
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  usuario_id INTEGER NOT NULL UNIQUE, 
  usuarios INTEGER DEFAULT 0, 
  empresas INTEGER DEFAULT 0, 
  financeiro INTEGER DEFAULT 0, 
  relatorios INTEGER DEFAULT 0, 
  cadastro INTEGER DEFAULT 0, 
  edicao INTEGER DEFAULT 0, 
  exclusao INTEGER DEFAULT 0, 
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP, 
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, 
  FOREIGN KEY (usuario_id) REFERENCES users(id) 
)`);

db.run(`CREATE TABLE IF NOT EXISTS financeiro_uploads ( 
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  usuario_id INTEGER NOT NULL, 
  empresa_id INTEGER, 
  valor REAL NOT NULL, 
  data_pagamento TEXT NOT NULL, 
  arquivo TEXT, 
  original_name TEXT, 
  status TEXT DEFAULT 'nao_pago', 
  observacao TEXT, 
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP, 
  FOREIGN KEY (usuario_id) REFERENCES users(id), 
  FOREIGN KEY (empresa_id) REFERENCES empresas(id) 
)`);

db.run(`CREATE TABLE IF NOT EXISTS ocorrencias ( 
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  user_id INTEGER NOT NULL, 
  tipo TEXT NOT NULL, 
  data TEXT NOT NULL, 
  obs TEXT, 
  status TEXT DEFAULT 'pendente', 
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP 
)`);

db.run(`CREATE TABLE IF NOT EXISTS ferias ( 
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  user_id INTEGER NOT NULL, 
  data_inicio TEXT NOT NULL, 
  data_fim TEXT NOT NULL, 
  observacao TEXT, 
  status TEXT DEFAULT 'pendente', 
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP 
)`);

db.run(`CREATE TABLE IF NOT EXISTS informes ( 
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  ano TEXT NOT NULL, 
  user_id INTEGER, 
  filename TEXT, 
  original_name TEXT, 
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP 
)`);

db.run(`CREATE TABLE IF NOT EXISTS documentos ( 
  id INTEGER PRIMARY KEY AUTOINCREMENT, 
  titulo TEXT NOT NULL, 
  categoria TEXT, 
  user_id INTEGER, 
  obs TEXT, 
  filename TEXT, 
  original_name TEXT, 
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP 
)`);

// Migration: coluna modulos
db.run(`ALTER TABLE users ADD COLUMN modulos TEXT DEFAULT NULL`, () => {});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// Salva uma imagem enviada como data URL base64 (usado no cadastro/verificação facial)
function saveBase64Image(dataUrl, prefix) {
  if (!dataUrl || typeof dataUrl !== 'string') return null;
  const matches = dataUrl.match(/^data:image\/(png|jpe?g|webp);base64,(.+)$/);
  if (!matches) return null;
  const ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
  const filename = `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}.${ext}`;
  fs.writeFileSync(path.join(__dirname, 'uploads', filename), Buffer.from(matches[2], 'base64'));
  return filename;
}

// ===================== HELPERS =====================
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => { if (err) reject(err); else resolve(rows); });
  });
}
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => { if (err) reject(err); else resolve(row); });
  });
}
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) { if (err) reject(err); else resolve({ lastID: this.lastID, changes: this.changes }); });
  });
}

// ===================== MIDDLEWARES =====================
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token não fornecido' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Token inválido' }); }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  next();
}

// Permite admin global e RH — bloqueia financeiro e outros perfis restritos
function adminComumOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  if (req.user.admin_type === 'financeiro') return res.status(403).json({ error: 'Acesso negado ao módulo RH' });
  next();
}

// Permite apenas admin global e financeiro
function financeiroOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  if (!['global', 'financeiro'].includes(req.user.admin_type)) return res.status(403).json({ error: 'Acesso restrito ao módulo financeiro' });
  next();
}

// Verifica se o usuário tem acesso a um módulo específico
// Admins sempre passam; colaboradores precisam ter o módulo na lista
function hasModulo(modulo) {
  return (req, res, next) => {
    if (req.user.role === 'admin') return next();
    const mods = req.user.modulos;
    if (Array.isArray(mods) && mods.includes(modulo)) return next();
    return res.status(403).json({ error: `Sem acesso ao módulo: ${modulo}` });
  };
}

function checkPermission(perm) {
  return async (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
    if (!req.user.admin_type || req.user.admin_type === 'global') return next();
    try {
      const row = await dbGet('SELECT * FROM permissoes_admin WHERE usuario_id = ?', [req.user.id]);
      const perms = Array.isArray(perm) ? perm : [perm];
      const hasPerm = perms.some(p => row && row[p] === 1);
      if (hasPerm) return next();
      return res.status(403).json({ error: 'Permissão insuficiente' });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  };
}

// Permite apenas contas do tipo "totem" (terminal de ponto por CPF na recepção)
function somenteTotem(req, res, next) {
  if (req.user.role !== 'totem') return res.status(403).json({ error: 'Acesso restrito ao totem de ponto' });
  next();
}

// Data/hora atuais no fuso de Brasília, no formato usado pelas tabelas do sistema
function agoraBR() {
  const now = new Date();
  const data = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Sao_Paulo', year: 'numeric', month: '2-digit', day: '2-digit' }).format(now);
  const hora = now.toLocaleTimeString('pt-BR', { timeZone: 'America/Sao_Paulo', hour12: false });
  return { data, hora };
}

async function proximoTipoPonto(userId) {
  const last = await dbGet('SELECT tipo FROM pontos_registros WHERE user_id = ? ORDER BY id DESC LIMIT 1', [userId]);
  if (!last || last.tipo === 'saida') return 'entrada';
  return 'saida';
}

// ===== Conformidade legal do ponto eletrônico (Portaria MTP nº 671/2021, art. 74 §2º da CLT) =====
// Hash gênese da cadeia — usado quando ainda não existe nenhum registro anterior
const NSR_GENESIS_HASH = '0'.repeat(64);

// Cada registro é encadeado ao hash do registro anterior (como um "livro-razão"
// local): qualquer alteração retroativa em um registro quebra a cadeia a partir
// dali, tornando adulteração detectável. Isso não substitui a assinatura digital
// ICP-Brasil exigida na norma (art. 88) — ver observação de pendência nas rotas
// abaixo e no painel /api/ponto/conformidade.
//
// A fórmula abaixo é a fórmula OFICIAL do campo nº 8 (código hash) do registro
// tipo "7" do leiaute do AFD (item 9 do documento "Leiaute do Arquivo Fonte de
// Dados - AFD.pdf", MTE): NSR + tipo + data/hora da marcação + CPF + data/hora
// de gravação + identificador do coletor + flag online/offline + hash SHA-256
// do registro anterior. Usar exatamente essa fórmula aqui significa que o
// hash_registro já gravado no banco É o mesmo valor que vai para o AFD — não
// precisa recalcular nada na hora de exportar.
function calcularHashRegistro({ nsr, data, hora, cpf, dataHoraGravacao, coletor, online, hashAnterior }) {
  return afdLayout.calcularHashOficialTipo7({
    nsr, dataMarcacao: data, horaMarcacao: hora, cpf, dataHoraGravacao, coletor, online, hashAnterior,
  });
}

async function registrarPontoComCadeia({ userId, tipo, data, hora, latitude, longitude, precisao, origem, registradoPor, ajusteId }) {
  const colaborador = await dbGet('SELECT u.cpf, u.empresa_id, e.cnpj as empresa_cnpj FROM users u LEFT JOIN empresas e ON u.empresa_id = e.id WHERE u.id = ?', [userId]);
  const cnpjEmpregador = (colaborador && colaborador.empresa_cnpj) || null;

  // NSR e encadeamento de hash calculados a partir do último registro de TODO o
  // sistema (não só do colaborador) — é assim que a Portaria 671/2021 exige que
  // funcione o Número Sequencial de Registro do REP.
  const ultimo = await dbGet('SELECT nsr, hash_registro FROM pontos_registros ORDER BY nsr DESC LIMIT 1');
  const nsr = ultimo && ultimo.nsr ? ultimo.nsr + 1 : 1;
  const hashAnterior = (ultimo && ultimo.hash_registro) || NSR_GENESIS_HASH;

  // "Data e hora de gravação do registro" (campo nº 5 do tipo "7") — é o
  // instante em que o servidor efetivamente grava, distinto da "data/hora da
  // marcação" (campo nº 3), que é o horário informado pelo cliente/totem.
  const dataHoraGravacao = afdLayout.dhFromDate(new Date());
  const coletor = afdLayout.coletorFromOrigem(origem);
  const online = '0'; // sistema sempre grava direto no servidor (sem modo offline)

  const hashRegistro = calcularHashRegistro({
    nsr, data, hora, cpf: colaborador ? colaborador.cpf : '', dataHoraGravacao, coletor, online, hashAnterior,
  });

  const result = await dbRun(
    `INSERT INTO pontos_registros
       (user_id, tipo, data, hora, latitude, longitude, precisao, origem, registrado_por, nsr, hash_registro, hash_anterior, cnpj_empregador, ajuste_id, data_hora_gravacao, coletor, online)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [userId, tipo, data, hora, latitude ?? null, longitude ?? null, precisao ?? null, origem, registradoPor ?? null, nsr, hashRegistro, hashAnterior, cnpjEmpregador, ajusteId ?? null, dataHoraGravacao, coletor, online]
  );
  return { id: result.lastID, nsr, hashRegistro };
}


function buildLoginToken(user) {
  const effectiveAdminType = user.role === 'admin' && !user.admin_type ? 'global' : user.admin_type;
  const modulos = user.modulos ? JSON.parse(user.modulos) : null;
  const token = jwt.sign(
    { id: user.id, cpf: user.cpf, role: user.role, name: user.name, empresa_id: user.empresa_id, admin_type: effectiveAdminType, modulos },
    JWT_SECRET, { expiresIn: '8h' }
  );
  return {
    token,
    user: { id: user.id, cpf: user.cpf, name: user.name, role: user.role, birth_date: user.birth_date, empresa_id: user.empresa_id, admin_type: effectiveAdminType, modulos },
    mustChangePassword: !!user.must_change_password,
  };
}

app.post('/api/login', (req, res) => {
  const { cpf, password } = req.body;
  if (!cpf || !password) return res.status(400).json({ error: 'Dados incompletos' });
  const stripped = cpf.replace(/\D/g, '');
  const normalizedCpf = stripped.length > 0 && /^\d+$/.test(stripped) ? stripped : cpf.trim();
  db.get('SELECT * FROM users WHERE cpf = ? OR cpf = ?', [normalizedCpf, cpf.trim()], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Credenciais inválidas' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Credenciais inválidas' });

    // Contas de totem (terminal de ponto por CPF) são um dispositivo fixo na
    // recepção — não exigimos MFA nem troca de senha obrigatória para elas.
    if (user.role === 'totem') {
      return res.json(buildLoginToken(user));
    }

    // ===== MFA (TOTP tipo Google Authenticator) =====
    if (user.mfa_enabled && user.mfa_secret) {
      // Não emite o token final ainda — só um token curto (5min) só para
      // permitir o /api/login/mfa-verify. Ele não serve para mais nada.
      const preToken = jwt.sign({ id: user.id, mfaPending: true }, JWT_SECRET, { expiresIn: '5m' });
      return res.json({ mfaRequired: true, preToken });
    }

    const result = buildLoginToken(user);
    // Usuário ainda não configurou o MFA (ex.: primeiro acesso) — o
    // frontend deve forçar a tela de cadastro do autenticador.
    result.mfaSetupRequired = true;
    res.json(result);
  });
});

// Passo 2 do login com MFA: confirma o código do autenticador e emite o token final
app.post('/api/login/mfa-verify', (req, res) => {
  const { preToken, code } = req.body;
  if (!preToken || !code) return res.status(400).json({ error: 'Dados incompletos' });
  let payload;
  try {
    payload = jwt.verify(preToken, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Sessão de login expirada. Faça login novamente.' });
  }
  if (!payload.mfaPending) return res.status(401).json({ error: 'Token inválido' });

  db.get('SELECT * FROM users WHERE id = ?', [payload.id], (err, user) => {
    if (err || !user || !user.mfa_secret) return res.status(401).json({ error: 'Usuário inválido' });
    if (!totp.verifyTOTP(user.mfa_secret, code)) {
      return res.status(401).json({ error: 'Código inválido. Verifique o app autenticador.' });
    }
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['Login com MFA', user.id, `Usuário ${user.name} autenticado com código do autenticador`]);
    res.json(buildLoginToken(user));
  });
});

// ===== Cadastro do MFA (Google Authenticator) — obrigatório no 1º acesso =====

// Etapa 1: gera um novo segredo e o QR code para escanear no app. Nada é
// salvo ainda — só é persistido depois de confirmar um código válido.
app.post('/api/mfa/setup', auth, async (req, res) => {
  try {
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

    const secret = totp.generateSecret();
    const otpauthUrl = totp.buildOtpAuthUrl({ secret, accountName: `${user.name} (${user.cpf})` });
    const qrCode = await QRCode.toDataURL(otpauthUrl, { margin: 1, scale: 6 });

    res.json({ secret, qrCode, otpauthUrl });
  } catch (e) {
    res.status(500).json({ error: 'Erro ao gerar MFA: ' + e.message });
  }
});

// Etapa 2: usuário digita o código de 6 dígitos gerado pelo app — se bater,
// o segredo é salvo e o MFA passa a ser exigido nos próximos logins.
app.post('/api/mfa/confirm', auth, async (req, res) => {
  const { secret, code } = req.body;
  if (!secret || !code) return res.status(400).json({ error: 'Dados incompletos' });
  if (!totp.verifyTOTP(secret, code)) {
    return res.status(400).json({ error: 'Código inválido. Confira o horário do celular e tente novamente.' });
  }
  try {
    await dbRun('UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?', [secret, req.user.id]);
    await dbRun('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['MFA ativado', req.user.id, `Usuário ${req.user.name} ativou o autenticador (MFA)`]);
    res.json({ success: true, message: 'Autenticação em duas etapas ativada com sucesso!' });
  } catch (e) {
    res.status(500).json({ error: 'Erro ao salvar MFA: ' + e.message });
  }
});

// Status do MFA do usuário logado
app.get('/api/mfa/status', auth, async (req, res) => {
  const user = await dbGet('SELECT mfa_enabled FROM users WHERE id = ?', [req.user.id]);
  res.json({ enabled: !!(user && user.mfa_enabled) });
});

// Desativar MFA — exige a senha atual por segurança
app.post('/api/mfa/disable', auth, async (req, res) => {
  const { password } = req.body;
  const user = await dbGet('SELECT * FROM users WHERE id = ?', [req.user.id]);
  if (!user || !bcrypt.compareSync(password || '', user.password)) {
    return res.status(401).json({ error: 'Senha incorreta' });
  }
  await dbRun('UPDATE users SET mfa_secret = NULL, mfa_enabled = 0 WHERE id = ?', [req.user.id]);
  await dbRun('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['MFA desativado', req.user.id, `Usuário ${user.name} desativou o autenticador (MFA)`]);
  res.json({ success: true, message: 'MFA desativado' });
});

// Admin: reseta o MFA de um usuário (ex.: perdeu o celular) — força novo cadastro no próximo login
app.post('/api/admin/mfa/reset', auth, adminOnly, async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId é obrigatório' });
  const result = await dbRun('UPDATE users SET mfa_secret = NULL, mfa_enabled = 0 WHERE id = ?', [userId]);
  if (result.changes === 0) return res.status(404).json({ error: 'Usuário não encontrado' });
  await dbRun('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['Reset de MFA (admin)', req.user.id, `Admin resetou o MFA do usuário ID ${userId}`]);
  res.json({ success: true, message: 'MFA resetado. O usuário deverá cadastrar novamente no próximo login.' });
});

app.post('/api/change-password', auth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id;
  if (!currentPassword || !newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: 'Dados inválidos. Mínimo 4 caracteres.' });
  }
  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'Usuário não encontrado' });
    if (!bcrypt.compareSync(currentPassword, user.password)) return res.status(401).json({ error: 'Senha atual incorreta' });
    const hashed = bcrypt.hashSync(newPassword, 10);
    db.run('UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?', [hashed, userId], function(err) {
      if (err) return res.status(500).json({ error: 'Erro ao atualizar senha' });
      db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['Troca de senha', userId, `Usuário ${user.name} trocou a senha`]);
      res.json({ success: true, message: 'Senha alterada com sucesso' });
    });
  });
});

app.post('/api/admin/change-user-password', auth, adminOnly, (req, res) => {
  const { userId, newPassword } = req.body;
  if (!userId || !newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: 'Dados inválidos. Mínimo 4 caracteres.' });
  }
  const hashed = bcrypt.hashSync(newPassword, 10);
  // Ao redefinir a senha, força o usuário a trocá-la no próximo acesso
  db.run('UPDATE users SET password = ?, must_change_password = 1 WHERE id = ?', [hashed, userId], function(err) {
    if (err) return res.status(500).json({ error: 'Erro ao atualizar senha' });
    if (this.changes === 0) return res.status(404).json({ error: 'Usuário não encontrado' });
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['Reset de senha admin', req.user.id, `Admin resetou senha do usuário ID ${userId}`]);
    res.json({ success: true, message: 'Senha redefinida com sucesso' });
  });
});

// ===================== EMPRESAS =====================
app.get('/api/empresas', auth, async (req, res) => {
  try {
    const rows = await dbAll('SELECT * FROM empresas ORDER BY nome');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/empresas', auth, checkPermission('empresas'), async (req, res) => {
  const { nome, cnpj, status, observacao } = req.body;
  if (!nome) return res.status(400).json({ error: 'Nome da empresa obrigatório' });
  try {
    const result = await dbRun('INSERT INTO empresas (nome, cnpj, status, observacao) VALUES (?, ?, ?, ?)', [nome, cnpj || null, status || 'ativo', observacao || null]);
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['Cadastro empresa', req.user.id, `Empresa: ${nome}`]);
    res.json({ id: result.lastID, nome, cnpj, status: status || 'ativo' });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) return res.status(409).json({ error: 'CNPJ já cadastrado' });
    res.status(500).json({ error: err.message });
  }
});
app.put('/api/empresas/:id', auth, checkPermission('empresas'), async (req, res) => {
  const { id } = req.params;
  const { nome, cnpj, status, observacao } = req.body;
  try {
    await dbRun('UPDATE empresas SET nome = ?, cnpj = ?, status = ?, observacao = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [nome, cnpj || null, status || 'ativo', observacao || null, id]);
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['Edição empresa', req.user.id, `Empresa ID ${id}`]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/empresas/:id', auth, checkPermission('exclusao'), async (req, res) => {
  const { id } = req.params;
  try {
    await dbRun('DELETE FROM empresas WHERE id = ?', [id]);
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['Exclusão empresa', req.user.id, `Empresa ID ${id}`]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===================== PERMISSÕES ADMIN =====================
app.get('/api/permissoes/:usuario_id', auth, adminOnly, async (req, res) => {
  try {
    const row = await dbGet('SELECT * FROM permissoes_admin WHERE usuario_id = ?', [req.params.usuario_id]);
    res.json(row || {});
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/permissoes', auth, adminOnly, async (req, res) => {
  const { usuario_id, usuarios, empresas, financeiro, relatorios, cadastro, edicao, exclusao } = req.body;
  try {
    // Garante que o usuário vira admin customizado ao salvar permissões
    await dbRun(
      `UPDATE users SET role='admin', admin_type='customizado'
       WHERE id=? AND cpf NOT IN ('admin','rh','financeiro')`,
      [usuario_id]
    );
    await dbRun(
      `INSERT INTO permissoes_admin
         (usuario_id, usuarios, empresas, financeiro, relatorios, cadastro, edicao, exclusao)
       VALUES (?,?,?,?,?,?,?,?)
       ON CONFLICT(usuario_id) DO UPDATE SET
         usuarios=excluded.usuarios, empresas=excluded.empresas,
         financeiro=excluded.financeiro, relatorios=excluded.relatorios,
         cadastro=excluded.cadastro, edicao=excluded.edicao,
         exclusao=excluded.exclusao, updated_at=CURRENT_TIMESTAMP`,
      [usuario_id, usuarios?1:0, empresas?1:0, financeiro?1:0,
       relatorios?1:0, cadastro?1:0, edicao?1:0, exclusao?1:0]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===================== USUÁRIOS =====================
app.get('/api/users', auth, adminComumOnly, (req, res) => {
  // type=all retorna todos incluindo admins customizados; padrão retorna só colaboradores
  const includeAdmins = req.query.type === 'all';
  const sql = includeAdmins
    ? `SELECT u.id, u.cpf, u.name, u.birth_date, u.role, u.created_at, u.empresa_id, u.admin_type, u.modulos, e.nome as empresa_nome
       FROM users u LEFT JOIN empresas e ON u.empresa_id = e.id
       WHERE u.cpf NOT IN ('admin','rh','financeiro') AND u.role != 'totem'
       ORDER BY u.role DESC, u.name`
    : `SELECT u.id, u.cpf, u.name, u.birth_date, u.role, u.created_at, u.empresa_id, u.admin_type, u.modulos, e.nome as empresa_nome
       FROM users u LEFT JOIN empresas e ON u.empresa_id = e.id
       WHERE u.role = 'user' ORDER BY u.name`;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});
app.post('/api/users', auth, adminComumOnly, (req, res) => {
  const { cpf, name, password, birth_date, empresa_id, admin_type, modulos } = req.body;
  if (!cpf || !name || !password) return res.status(400).json({ error: 'Dados incompletos' });
  const normalizedCpf = cpf.replace(/\D/g, '');
  const hashed = bcrypt.hashSync(password, 10);
  const modulosJson = modulos && modulos.length > 0 ? JSON.stringify(modulos) : null;
  db.run('INSERT INTO users (cpf, name, password, birth_date, role, empresa_id, admin_type, modulos, must_change_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)',
    [normalizedCpf, name, hashed, birth_date || null, 'user', empresa_id || null, admin_type || null, modulosJson],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) return res.status(409).json({ error: 'CPF já cadastrado' });
        return res.status(500).json({ error: err.message });
      }
      db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['Cadastro colaborador', req.user.id, `Cadastrado: ${name} (${normalizedCpf})`]);
      res.json({ id: this.lastID, cpf: normalizedCpf, name, birth_date, empresa_id, admin_type, modulos });
    }
  );
});
// ===================== IMPORTAÇÃO EM MASSA (EXCEL) =====================
// Aceita multipart/form-data com campo "file" (xlsx/xls) + campo "empresa_id_default" opcional.
// Colunas esperadas (nesta ordem, cabeçalho opcional):
//   A: colaborador | B: cpf | C: data_nascimento (DD/MM/AAAA ou AAAA-MM-DD) | D: senha | E: empresa (nome ou id)
const xlsxUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (['.xlsx', '.xls', '.csv'].includes(ext)) cb(null, true);
    else cb(new Error('Somente arquivos .xlsx, .xls ou .csv são aceitos'));
  }
});

app.post('/api/users/importar-excel', auth, adminComumOnly, xlsxUpload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });

  let XLSX;
  try { XLSX = require('xlsx'); }
  catch {
    return res.status(500).json({ error: 'Dependência "xlsx" não instalada. Execute: npm install xlsx' });
  }

  try {
    // 1. Parse da planilha
    const workbook = XLSX.read(req.file.buffer, { type: 'buffer', cellDates: true });
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const rows = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '' });

    if (!rows || rows.length === 0) return res.status(400).json({ error: 'Planilha vazia' });

    // Remove linha de cabeçalho se a primeira célula não parecer um CPF/nome válido
    // (detecta se col B da linha 1 contém algo com letra — indica cabeçalho)
    let dataRows = rows;
    const firstB = String(rows[0][1] || '').toLowerCase();
    if (['cpf', 'documento', 'login', 'col2', 'b'].includes(firstB) || /[a-z]/.test(firstB)) {
      dataRows = rows.slice(1);
    }

    // 2. Carrega lista de empresas para resolver nome → id
    const empresas = await dbAll('SELECT id, nome FROM empresas');
    const empresaMap = {}; // nome normalizado → id
    empresas.forEach(e => { empresaMap[e.nome.trim().toLowerCase()] = e.id; });

    const results = { inseridos: 0, ignorados: 0, erros: [] };

    for (let i = 0; i < dataRows.length; i++) {
      const row = dataRows[i];
      const linha = i + (dataRows === rows ? 1 : 2); // número humano

      // Extrai colunas
      const rawName      = String(row[0] || '').trim();
      const rawCpf       = String(row[1] || '').trim();
      const rawBirth     = row[2]; // pode ser Date (xlsx cellDates) ou string
      const rawPass      = String(row[3] || '').trim();
      const rawEmpresa   = String(row[4] || '').trim();

      // Validações básicas
      if (!rawName || !rawCpf || !rawPass) {
        results.erros.push({ linha, motivo: 'Campos obrigatórios ausentes (colaborador, CPF ou senha)', dados: rawName || '?' });
        results.ignorados++;
        continue;
      }

      // Normaliza CPF
      const normalizedCpf = rawCpf.replace(/\D/g, '');
      if (normalizedCpf.length !== 11) {
        results.erros.push({ linha, motivo: `CPF inválido: "${rawCpf}"`, dados: rawName });
        results.ignorados++;
        continue;
      }

      // Normaliza data de nascimento
      let birthDate = null;
      if (rawBirth) {
        if (rawBirth instanceof Date) {
          // xlsx parseou como Date nativo
          const y = rawBirth.getFullYear();
          const m = String(rawBirth.getMonth() + 1).padStart(2, '0');
          const d = String(rawBirth.getDate()).padStart(2, '0');
          birthDate = `${y}-${m}-${d}`;
        } else {
          const s = String(rawBirth).trim();
          // DD/MM/AAAA
          const dmY = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
          if (dmY) birthDate = `${dmY[3]}-${dmY[2].padStart(2,'0')}-${dmY[1].padStart(2,'0')}`;
          // AAAA-MM-DD
          else if (/^\d{4}-\d{2}-\d{2}$/.test(s)) birthDate = s;
          // Número serial do Excel (dias desde 1899-12-30)
          else if (/^\d+$/.test(s)) {
            const d = XLSX.SSF.parse_date_code(parseInt(s));
            if (d) birthDate = `${d.y}-${String(d.m).padStart(2,'0')}-${String(d.d).padStart(2,'0')}`;
          }
        }
      }

      // Resolve empresa
      let empresaId = req.body.empresa_id_default ? parseInt(req.body.empresa_id_default) : null;
      if (rawEmpresa) {
        // Tenta número direto
        if (/^\d+$/.test(rawEmpresa)) {
          empresaId = parseInt(rawEmpresa);
        } else {
          const found = empresaMap[rawEmpresa.toLowerCase()];
          if (found) empresaId = found;
          else {
            results.erros.push({ linha, motivo: `Empresa não encontrada: "${rawEmpresa}"`, dados: rawName });
            results.ignorados++;
            continue;
          }
        }
      }

      // Verifica se CPF já existe
      const existing = await dbGet('SELECT id FROM users WHERE cpf = ?', [normalizedCpf]);
      if (existing) {
        results.erros.push({ linha, motivo: `CPF já cadastrado: ${normalizedCpf}`, dados: rawName });
        results.ignorados++;
        continue;
      }

      // Insere
      const hashed = bcrypt.hashSync(rawPass, 10);
      try {
        await dbRun(
          'INSERT INTO users (cpf, name, password, birth_date, role, empresa_id, must_change_password) VALUES (?, ?, ?, ?, ?, ?, 1)',
          [normalizedCpf, rawName, hashed, birthDate, 'user', empresaId]
        );
        results.inseridos++;
      } catch (e) {
        results.erros.push({ linha, motivo: e.message, dados: rawName });
        results.ignorados++;
      }
    }

    db.run('INSERT INTO activities (action, user_id, details) VALUES (?,?,?)', [
      'Importação em massa',
      req.user.id,
      `${results.inseridos} colaborador(es) importado(s), ${results.ignorados} ignorado(s)`
    ]);

    res.json({
      success: true,
      inseridos: results.inseridos,
      ignorados: results.ignorados,
      erros: results.erros
    });

  } catch (err) {
    console.error('Erro importação Excel:', err);
    res.status(500).json({ error: 'Erro ao processar planilha: ' + err.message });
  }
});

app.put('/api/users/:id', auth, adminComumOnly, async (req, res) => {
  const { id } = req.params;
  const { name, empresa_id, role, admin_type, modulos, birth_date } = req.body;

  // Não deixa alterar os usuários de sistema fixos
  const systemUser = await dbGet('SELECT cpf FROM users WHERE id = ?', [id]);
  if (systemUser && ['admin','rh','financeiro'].includes(systemUser.cpf)) {
    return res.status(403).json({ error: 'Usuário de sistema não pode ser alterado por aqui' });
  }

  const modulosJson = modulos && modulos.length > 0 ? JSON.stringify(modulos) : null;
  const newRole = role === 'admin' ? 'admin' : 'user';
  const newAdminType = newRole === 'admin' ? (admin_type || 'global') : null;

  try {
    await dbRun(
      'UPDATE users SET name=?, empresa_id=?, role=?, admin_type=?, modulos=?, birth_date=? WHERE id=?',
      [name, empresa_id || null, newRole, newAdminType, modulosJson, birth_date || null, id]
    );

    // Se virou admin customizado: garante registro em permissoes_admin
    if (newRole === 'admin' && newAdminType === 'customizado') {
      await dbRun(
        `INSERT OR IGNORE INTO permissoes_admin (usuario_id) VALUES (?)`, [id]
      );
    }
    // Se deixou de ser admin: remove permissoes_admin
    if (newRole === 'user') {
      await dbRun('DELETE FROM permissoes_admin WHERE usuario_id = ?', [id]);
    }

    res.json({ success: true });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});
app.delete('/api/users/:id', auth, adminComumOnly, (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM users WHERE id = ? AND role = ?', [id, 'user'], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: 'Usuário não encontrado' });
    res.json({ success: true });
  });
});

// ===================== ANIVERSARIANTES =====================
app.get('/api/birthdays', auth, async (req, res) => {
  const now = new Date();
  const currentMonth = String(now.getMonth() + 1).padStart(2, '0');
  const currentDay = String(now.getDate()).padStart(2, '0');
  try {
    const [monthRows, todayRows] = await Promise.all([
      dbAll(`SELECT id, cpf, name, birth_date FROM users WHERE role = 'user' AND birth_date IS NOT NULL AND substr(birth_date,6,2) = ? ORDER BY substr(birth_date,9,2)`, [currentMonth]),
      dbAll(`SELECT id, cpf, name, birth_date FROM users WHERE role = 'user' AND birth_date IS NOT NULL AND substr(birth_date,6,2) = ? AND substr(birth_date,9,2) = ?`, [currentMonth, currentDay]),
    ]);
    res.json({ month: monthRows, today: todayRows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===================== HOLERITES =====================
app.get('/api/holerites', auth, (req, res) => {
  const user = req.user;
  let sql, params;
  if (user.role === 'admin') {
    sql = `SELECT h.*, u.name as user_name, u.cpf as user_cpf FROM holerites h JOIN users u ON h.user_id = u.id ORDER BY h.uploaded_at DESC`;
    params = [];
  } else {
    sql = `SELECT h.*, u.name as user_name, u.cpf as user_cpf FROM holerites h JOIN users u ON h.user_id = u.id WHERE h.user_id = ? ORDER BY h.uploaded_at DESC`;
    params = [user.id];
  }
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});
app.post('/api/holerites', auth, adminComumOnly, upload.single('file'), (req, res) => {
  const { user_id, month_year, deadline } = req.body;
  if (!user_id || !month_year) return res.status(400).json({ error: 'Dados incompletos' });
  const filename = req.file ? req.file.filename : null;
  const original_name = req.file ? req.file.originalname : null;
  db.run('INSERT INTO holerites (user_id, month_year, filename, original_name, status, deadline) VALUES (?, ?, ?, ?, ?, ?)', [user_id, month_year, filename, original_name, 'novo', deadline || null], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['Upload holerite', req.user.id, `Holerite ${month_year} para usuário ${user_id}`]);
    res.json({ id: this.lastID, user_id, month_year, status: 'novo', deadline });
  });
});

// ===================== FUNÇÃO DE NORMALIZAÇÃO =====================
function normalizeStr(str) {
  if (!str) return '';
  return str.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toUpperCase().replace(/\s+/g, ' ').trim();
}

// ===================== FUNÇÃO DE SCORE DE NOMES =====================
function nameScore(pdfName, dbName) {
  const pdf = normalizeStr(pdfName);
  const db = normalizeStr(dbName);
  if (!pdf || !db) return 0;
  if (pdf === db) return 100;
  if (db.includes(pdf) || pdf.includes(db)) return 90;
  const words = pdf.split(' ').filter(w => w.length >= 3);
  const matched = words.filter(w => db.includes(w));
  return words.length === 0 ? 0 : Math.round((matched.length / words.length) * 80);
}

// ===================== FUNÇÃO DE EXTRAÇÃO DE PÁGINAS =====================
function extractHoleritePages(pdfPath) {
  return new Promise((resolve, reject) => {
    const isWin = os.platform() === 'win32';
    // No Windows: tenta 'py' (Python Launcher) e depois 'python'.
    // No Linux/Mac: usa 'python3'.
    // IMPORTANTE: shell:false evita o bug no Windows onde o processo
    // recebe o diretorio em vez do script quando ha espacos no caminho.
    const pythonCandidates = isWin ? ['py', 'python'] : ['python3'];

    function tryNext(candidates) {
      if (candidates.length === 0) {
        return reject(new Error('Python nao encontrado. Instale e adicione ao PATH.'));
      }
      const cmd = candidates[0];
      const rest = candidates.slice(1);

      const proc = spawn(cmd, [PYTHON_SCRIPT, pdfPath], {
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: false,
        cwd: __dirname
      });

      let stdout = '';
      let stderr = '';
      proc.stdout.on('data', (d) => { stdout += d.toString(); });
      proc.stderr.on('data', (d) => { stderr += d.toString(); });

      proc.on('close', (code) => {
        if (code !== 0) {
          console.error('Erro Python (' + cmd + ') codigo ' + code + ':', stderr);
          if (rest.length > 0) return tryNext(rest);
          return reject(new Error('Python codigo ' + code + ': ' + (stderr.trim() || stdout.trim())));
        }
        try {
          const result = JSON.parse(stdout);
          if (result.error) return reject(new Error(result.error));
          resolve(result.pages);
        } catch (e) {
          console.error('JSON parse error:', stdout.slice(0, 300));
          reject(new Error('Falha ao parsear resposta Python: ' + e.message));
        }
      });

      proc.on('error', (err) => {
        console.error('Spawn error (' + cmd + '):', err.message);
        if (rest.length > 0) return tryNext(rest);
        reject(new Error('Nao foi possivel executar Python: ' + err.message));
      });
    }

    tryNext(pythonCandidates);
  });
}

// ===================== HOLERITES EM LOTE (PDF AGRUPADO) - CORRIGIDO =====================
app.post('/api/holerites/lote', auth, adminComumOnly, upload.single('file'), async (req, res) => {
  const { month_year, deadline } = req.body;
  if (!month_year) return res.status(400).json({ error: 'Mês/Ano obrigatório' });
  if (!req.file) return res.status(400).json({ error: 'PDF obrigatório' });
  
  try {
    const users = await dbAll("SELECT id, name, empresa_id FROM users WHERE role != 'admin'");
    const empresas = await dbAll("SELECT id, cnpj FROM empresas");
    const pages = await extractHoleritePages(req.file.path);
    
    const mainPdfBytes = fs.readFileSync(req.file.path);
    const mainPdfDoc = await PDFDocument.load(mainPdfBytes);
    
    const resultados = [];
    const naoEncontrados = [];

    for (const pageInfo of pages) {
      const i = pageInfo.page - 1;
      const pdfName = pageInfo.name;
      const pdfCnpj = pageInfo.cnpj;

      let empresaId = null;
      if (pdfCnpj) {
        const digits = pdfCnpj.replace(/\D/g, '');
        const emp = empresas.find(e => e.cnpj && e.cnpj.replace(/\D/g, '') === digits);
        if (emp) empresaId = emp.id;
      }

      const pool = (empresaId !== null) ? users.filter(u => u.empresa_id === empresaId) : users;
      const searchPool = pool.length > 0 ? pool : users;

      let bestUser = null, bestScore = 0;
      for (const user of searchPool) {
        const score = nameScore(pdfName, user.name);
        if (score > bestScore) { bestScore = score; bestUser = user; }
      }

      if (!bestUser || bestScore < 60) {
        naoEncontrados.push({
          pagina: pageInfo.page,
          nome_pdf: pdfName || '(não identificado)',
          cnpj_pdf: pdfCnpj || '',
          score: bestScore
        });
        continue;
      }

      const singleDoc = await PDFDocument.create();
      const [copied] = await singleDoc.copyPages(mainPdfDoc, [i]);
      singleDoc.addPage(copied);
      const singleBytes = await singleDoc.save();

      const filename = `${Date.now()}-${Math.floor(Math.random() * 1e6)}.pdf`;
      const safeName = normalizeStr(bestUser.name).replace(/ /g, '_');
      const original_name = `holerite-${month_year.replace('/', '_')}-${safeName}.pdf`;
      fs.writeFileSync(path.join(__dirname, 'uploads', filename), Buffer.from(singleBytes));

      await dbRun(
        'INSERT INTO holerites (user_id, month_year, filename, original_name, status, deadline) VALUES (?,?,?,?,?,?)',
        [bestUser.id, month_year, filename, original_name, 'novo', deadline || null]
      );
      db.run('INSERT INTO activities (action, user_id, details) VALUES (?,?,?)',
        ['Upload holerite lote', req.user.id, `Holerite ${month_year} → ${bestUser.name} (pág.${pageInfo.page}, match:${bestScore}%)`]
      );

      resultados.push({
        pagina: pageInfo.page,
        usuario: bestUser.name,
        userId: bestUser.id,
        nome_pdf: pdfName,
        cnpj_pdf: pdfCnpj,
        score: bestScore
      });
    }

    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);

    res.json({
      total_paginas: pages.length,
      enviados: resultados.length,
      nao_encontrados: naoEncontrados.length,
      resultados,
      naoEncontrados
    });
  } catch (err) {
    console.error('Erro no lote:', err);
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: 'Erro ao processar PDF: ' + err.message });
  }
});

// ===================== CONFIGURAÇÕES WHITE-LABEL =====================
// GET público: logo, cores, nome (necessário antes do login)
app.get('/api/config/public', (req, res) => {
  db.all(
    `SELECT chave, valor FROM configuracoes WHERE chave IN (
      'empresa_nome','empresa_logo_url','sistema_nome','sistema_badge',
      'cor_primaria','cor_sidebar','cor_acento'
    )`, [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      const cfg = Object.fromEntries((rows || []).map(r => [r.chave, r.valor]));
      res.json(cfg);
    }
  );
});

// GET todas as configurações (admin global)
app.get('/api/config', auth, (req, res) => {
  if (!req.user || req.user.role !== 'admin' || req.user.admin_type !== 'global') {
    return res.status(403).json({ error: 'Acesso restrito ao administrador global' });
  }
  db.all('SELECT chave, valor FROM configuracoes ORDER BY chave', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const cfg = Object.fromEntries((rows || []).map(r => [r.chave, r.valor]));
    res.json(cfg);
  });
});

// PUT atualizar configurações (admin global)
app.put('/api/config', auth, async (req, res) => {
  if (!req.user || req.user.role !== 'admin' || req.user.admin_type !== 'global') {
    return res.status(403).json({ error: 'Acesso restrito ao administrador global' });
  }
  const updates = req.body;
  if (!updates || typeof updates !== 'object') {
    return res.status(400).json({ error: 'Corpo da requisição inválido' });
  }
  try {
    for (const [chave, valor] of Object.entries(updates)) {
      await dbRun(
        `INSERT INTO configuracoes (chave, valor, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor, updated_at=excluded.updated_at`,
        [chave, String(valor ?? '')]
      );
    }
    // Reaplicar SMTP às variáveis de ambiente da sessão atual
    const reload = ['smtp_host','smtp_port','smtp_user','smtp_pass','smtp_from'];
    for (const k of reload) {
      if (updates[k] !== undefined) process.env[k.toUpperCase().replace('SMTP_','SMTP_')] = updates[k];
    }
    if (updates.smtp_host !== undefined) process.env.SMTP_HOST = updates.smtp_host;
    if (updates.smtp_port !== undefined) process.env.SMTP_PORT = updates.smtp_port;
    if (updates.smtp_user !== undefined) process.env.SMTP_USER = updates.smtp_user;
    if (updates.smtp_pass !== undefined) process.env.SMTP_PASS = updates.smtp_pass;
    if (updates.smtp_from !== undefined) process.env.SMTP_FROM = updates.smtp_from;

    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)',
      ['Configurações do sistema atualizadas', req.user.id, Object.keys(updates).join(', ')]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST testar SMTP (envia e-mail de teste)
app.post('/api/config/testar-smtp', auth, async (req, res) => {
  if (!req.user || req.user.role !== 'admin' || req.user.admin_type !== 'global') {
    return res.status(403).json({ error: 'Acesso restrito ao administrador global' });
  }
  const { smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from, email_destino } = req.body;
  if (!smtp_host || !email_destino) {
    return res.status(400).json({ error: 'Informe o servidor SMTP e o e-mail de destino' });
  }
  let nodemailer;
  try { nodemailer = require('nodemailer'); } catch {
    return res.status(500).json({ error: 'nodemailer não instalado. Execute npm install nodemailer.' });
  }
  const transporter = nodemailer.createTransport({
    host: smtp_host,
    port: parseInt(smtp_port || '587', 10),
    secure: String(smtp_port) === '465',
    auth: smtp_user ? { user: smtp_user, pass: smtp_pass } : undefined,
  });
  try {
    await transporter.sendMail({
      from: smtp_from || smtp_user,
      to: email_destino,
      subject: 'Teste de SMTP — Portal Corporativo',
      text: 'Se você recebeu este e-mail, a configuração SMTP está funcionando corretamente.',
    });
    res.json({ success: true, mensagem: `E-mail de teste enviado para ${email_destino}` });
  } catch (err) {
    res.status(500).json({ error: `Falha no envio: ${err.message}` });
  }
});

// ===================== PATRIMÔNIO =====================
// GET: admin vê todos os equipamentos; colaborador vê apenas os que estão sob sua responsabilidade
app.get('/api/patrimonio', auth, async (req, res) => {
  try {
    const sql = `
      SELECT p.*, u.name as nome_responsavel, u.cpf as cpf_responsavel
      FROM patrimonio p
      LEFT JOIN users u ON p.usuario_id = u.id
      WHERE p.ativo = 1 ${req.user.role !== 'admin' ? 'AND p.usuario_id = ?' : ''}
      ORDER BY p.equipamento ASC`;
    const params = req.user.role !== 'admin' ? [req.user.id] : [];
    const items = await dbAll(sql, params);
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Equipamentos com situação "estoque" (usado na aba Compras > Patrimônio em Estoque)
app.get('/api/patrimonio/estoque', auth, async (req, res) => {
  try {
    const items = await dbAll(
      `SELECT * FROM patrimonio WHERE ativo = 1 AND situacao = 'estoque' ORDER BY equipamento ASC`
    );
    res.json(items);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/patrimonio', auth, adminComumOnly, async (req, res) => {
  const {
    equipamento, serial_number, mac_address, numero_patrimonio,
    descricao, categoria, situacao, usuario_id, data_emprestimo, obs_emprestimo,
  } = req.body;

  if (!equipamento || !equipamento.trim()) {
    return res.status(400).json({ error: 'Informe o nome do equipamento' });
  }
  const sit = situacao === 'emprestado' ? 'emprestado' : 'estoque';
  if (sit === 'emprestado' && !usuario_id) {
    return res.status(400).json({ error: 'Selecione o colaborador responsável' });
  }

  try {
    const result = await dbRun(
      `INSERT INTO patrimonio
        (equipamento, serial_number, mac_address, numero_patrimonio, descricao, categoria, situacao, usuario_id, data_emprestimo, obs_emprestimo)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [equipamento.trim(), serial_number || null, mac_address || null, numero_patrimonio || null,
        descricao || null, categoria || null, sit,
        sit === 'emprestado' ? usuario_id : null,
        sit === 'emprestado' ? (data_emprestimo || null) : null,
        sit === 'emprestado' ? (obs_emprestimo || null) : null]
    );
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)',
      ['Patrimônio cadastrado', req.user.id, equipamento.trim()]);
    res.json({ success: true, id: result.lastID });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/patrimonio/:id', auth, adminComumOnly, async (req, res) => {
  const { id } = req.params;
  const {
    equipamento, serial_number, mac_address, numero_patrimonio,
    descricao, categoria, situacao, usuario_id, data_emprestimo, obs_emprestimo,
  } = req.body;

  if (!equipamento || !equipamento.trim()) {
    return res.status(400).json({ error: 'Informe o nome do equipamento' });
  }
  const sit = situacao === 'emprestado' ? 'emprestado' : 'estoque';
  if (sit === 'emprestado' && !usuario_id) {
    return res.status(400).json({ error: 'Selecione o colaborador responsável' });
  }

  try {
    const existing = await dbGet('SELECT id FROM patrimonio WHERE id = ?', [id]);
    if (!existing) return res.status(404).json({ error: 'Equipamento não encontrado' });

    await dbRun(
      `UPDATE patrimonio SET
        equipamento = ?, serial_number = ?, mac_address = ?, numero_patrimonio = ?,
        descricao = ?, categoria = ?, situacao = ?, usuario_id = ?, data_emprestimo = ?,
        obs_emprestimo = ?, updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [equipamento.trim(), serial_number || null, mac_address || null, numero_patrimonio || null,
        descricao || null, categoria || null, sit,
        sit === 'emprestado' ? usuario_id : null,
        sit === 'emprestado' ? (data_emprestimo || null) : null,
        sit === 'emprestado' ? (obs_emprestimo || null) : null,
        id]
    );
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)',
      ['Patrimônio atualizado', req.user.id, equipamento.trim()]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/patrimonio/:id', auth, adminComumOnly, async (req, res) => {
  const { id } = req.params;
  try {
    const existing = await dbGet('SELECT equipamento FROM patrimonio WHERE id = ?', [id]);
    if (!existing) return res.status(404).json({ error: 'Equipamento não encontrado' });

    await dbRun('DELETE FROM patrimonio WHERE id = ?', [id]);
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)',
      ['Patrimônio removido', req.user.id, existing.equipamento]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===================== ASSINATURA DE HOLERITE =====================
app.post('/api/holerites/:id/sign', auth, upload.single('file'), (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  const role = req.user.role;
  db.get('SELECT * FROM holerites WHERE id = ?', [id], (err, holerite) => {
    if (err || !holerite) return res.status(404).json({ error: 'Holerite não encontrado' });
    if (role !== 'admin' && holerite.user_id !== userId) return res.status(403).json({ error: 'Acesso negado' });
    const filename = req.file ? req.file.filename : holerite.filename;
    db.run('UPDATE holerites SET status = ?, filename = ?, signed_at = CURRENT_TIMESTAMP WHERE id = ?', ['assinado', filename, id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['Assinatura holerite', userId, `Holerite ID ${id} assinado`]);
      res.json({ success: true });
    });
  });
});
// ===================== ASSINATURA DIGITAL LOCAL (código por e-mail + RSA + QR) =====================
// Alternativa gratuita/local ao D4Sign: o colaborador confirma a identidade
// via código enviado por e-mail e o próprio sistema assina o documento
// (hash SHA-256 + RSA-PSS) e gera o PDF final com QR code de conferência.
const CODE_TTL_MS = 5 * 60 * 1000; // 5 minutos
const MAX_CODE_ATTEMPTS = 5;

function gerarCodigo() {
  return String(Math.floor(Math.random() * 1000000)).padStart(6, '0');
}
function gerarToken() {
  return crypto.randomBytes(16).toString('hex');
}

// Passo 1: solicitar código de confirmação por e-mail
// POST /api/holerites/:id/assinatura-local/solicitar-codigo   body: { email }
app.post('/api/holerites/:id/assinatura-local/solicitar-codigo', auth, async (req, res) => {
  const { id } = req.params;
  const { email } = req.body;
  const userId = req.user.id;
  const role = req.user.role;

  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Informe um e-mail válido' });
  }

  try {
    const holerite = await dbGet('SELECT * FROM holerites WHERE id = ?', [id]);
    if (!holerite) return res.status(404).json({ error: 'Holerite não encontrado' });
    if (role !== 'admin' && holerite.user_id !== userId) {
      return res.status(403).json({ error: 'Acesso negado' });
    }

    const code = gerarCodigo();
    const token = gerarToken();

    await dbRun(
      `INSERT INTO local_signature_codes (holerite_id, token, code, signer_name, signer_email)
       VALUES (?, ?, ?, ?, ?)`,
      [id, token, code, req.user.name, email]
    );

    await sendVerificationCode(email, code, req.user.name, holerite.original_name || `Holerite ${holerite.month_year}`);

    res.json({
      mensagem: `Código de confirmação enviado para ${email}.`,
      token,
      expira_em_segundos: CODE_TTL_MS / 1000,
    });
  } catch (err) {
    console.error('[assinatura-local/solicitar-codigo]', err);
    res.status(500).json({ error: 'Erro ao solicitar código de confirmação' });
  }
});

// Passo 2: confirmar código e assinar o documento
// POST /api/holerites/:id/assinatura-local/confirmar   body: { token, codigo }
app.post('/api/holerites/:id/assinatura-local/confirmar', auth, async (req, res) => {
  const { id } = req.params;
  const { token, codigo } = req.body;
  const userId = req.user.id;
  const role = req.user.role;

  if (!token || !codigo) return res.status(400).json({ error: 'Token e código são obrigatórios' });

  try {
    const holerite = await dbGet('SELECT * FROM holerites WHERE id = ?', [id]);
    if (!holerite) return res.status(404).json({ error: 'Holerite não encontrado' });
    if (role !== 'admin' && holerite.user_id !== userId) {
      return res.status(403).json({ error: 'Acesso negado' });
    }

    const rec = await dbGet(
      'SELECT * FROM local_signature_codes WHERE token = ? AND holerite_id = ?',
      [token, id]
    );
    if (!rec) return res.status(410).json({ error: 'Solicitação não encontrada. Peça um novo código.' });

    const idade = Date.now() - new Date(rec.created_at + 'Z').getTime();
    if (idade > CODE_TTL_MS) {
      await dbRun('DELETE FROM local_signature_codes WHERE id = ?', [rec.id]);
      return res.status(410).json({ error: 'Código expirado. Solicite um novo código.' });
    }

    if (rec.attempts >= MAX_CODE_ATTEMPTS) {
      await dbRun('DELETE FROM local_signature_codes WHERE id = ?', [rec.id]);
      return res.status(429).json({ error: 'Número máximo de tentativas excedido. Solicite um novo código.' });
    }

    if (String(codigo).trim() !== rec.code) {
      await dbRun('UPDATE local_signature_codes SET attempts = attempts + 1 WHERE id = ?', [rec.id]);
      const restantes = MAX_CODE_ATTEMPTS - (rec.attempts + 1);
      return res.status(401).json({ error: `Código incorreto. Tentativas restantes: ${restantes}` });
    }

    // código correto -> assina
    const originalPath = path.join(__dirname, 'uploads', holerite.filename);
    if (!fs.existsSync(originalPath)) {
      return res.status(404).json({ error: 'Arquivo original do holerite não encontrado' });
    }
    const dataBuffer = fs.readFileSync(originalPath);
    const sigResult = signatureEngine.sign(dataBuffer);

    const signedPdfBytes = await createSignedPdf(originalPath, {
      originalName: holerite.original_name || holerite.filename,
      signerName: rec.signer_name,
      signerEmail: rec.signer_email,
      digest: sigResult.digest_sha256,
      signedAt: sigResult.signed_at,
      algorithm: sigResult.algorithm,
      verificationLabel: 'Código de confirmação por e-mail',
    });

    const signedFilename = `assinado-local-${Date.now()}-${Math.floor(Math.random() * 1e6)}.pdf`;
    fs.writeFileSync(path.join(__dirname, 'uploads', signedFilename), signedPdfBytes);

    await dbRun(
      `INSERT INTO local_signatures (holerite_id, signer_name, signer_email, digest_sha256, signature, algorithm, signed_filename, verification_method)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(holerite_id) DO UPDATE SET
         signer_name=excluded.signer_name, signer_email=excluded.signer_email,
         digest_sha256=excluded.digest_sha256, signature=excluded.signature,
         algorithm=excluded.algorithm, signed_filename=excluded.signed_filename,
         verification_method=excluded.verification_method,
         signed_at=CURRENT_TIMESTAMP`,
      [id, rec.signer_name, rec.signer_email, sigResult.digest_sha256, sigResult.signature, sigResult.algorithm, signedFilename, 'email_code']
    );

    await dbRun(
      `UPDATE holerites SET status = 'assinado', filename = ?, signed_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [signedFilename, id]
    );

    await dbRun('DELETE FROM local_signature_codes WHERE id = ?', [rec.id]);
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)',
      ['Assinatura digital local', userId, `Holerite ID ${id} assinado por ${rec.signer_name} (${rec.signer_email})`]);

    res.json({
      mensagem: 'Documento confirmado e assinado com sucesso',
      assinatura: {
        digest_sha256: sigResult.digest_sha256,
        algorithm: sigResult.algorithm,
        signed_at: sigResult.signed_at,
        signer_name: rec.signer_name,
        signer_email: rec.signer_email,
      },
      arquivo_assinado: signedFilename,
    });
  } catch (err) {
    console.error('[assinatura-local/confirmar]', err);
    res.status(500).json({ error: 'Erro ao confirmar assinatura' });
  }
});

// Consulta os metadados de assinatura local de um holerite (para exibir/verificar)
app.get('/api/holerites/:id/assinatura-local', auth, async (req, res) => {
  const { id } = req.params;
  try {
    const holerite = await dbGet('SELECT * FROM holerites WHERE id = ?', [id]);
    if (!holerite) return res.status(404).json({ error: 'Holerite não encontrado' });
    if (req.user.role !== 'admin' && holerite.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Acesso negado' });
    }
    const sig = await dbGet('SELECT * FROM local_signatures WHERE holerite_id = ?', [id]);
    if (!sig) return res.status(404).json({ error: 'Este holerite ainda não possui assinatura digital local' });
    res.json(sig);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Identidade/certificado público do assinador local
app.get('/api/assinatura-local/certificado', auth, (req, res) => {
  res.json({
    identity: signatureEngine.getIdentity(),
    public_key_pem: signatureEngine.getPublicKeyPem(),
  });
});

// ===================== RECONHECIMENTO FACIAL (cadastro + assinatura) =====================
// O rosto NUNCA é "analisado" no servidor: o navegador (face-api.js) extrai
// um vetor numérico de 128 posições (descriptor) a partir da câmera, e é
// esse vetor que trafega e fica armazenado — nunca a foto crua é usada
// para comparação. A foto (selfie) é opcional e guardada só como evidência
// de auditoria, igual ao que já acontece com o hash/QR code do fluxo atual.

// Cadastro (1x) do rosto de referência do próprio usuário logado
app.post('/api/face/cadastrar', auth, async (req, res) => {
  const { descriptor, selfie } = req.body;
  if (!faceMatch.isValidDescriptor(descriptor)) {
    return res.status(400).json({ error: 'Descritor facial inválido. Tente capturar novamente com boa iluminação.' });
  }
  try {
    const photoFilename = saveBase64Image(selfie, 'face-ref');
    await dbRun(
      `INSERT INTO face_references (user_id, descriptor, photo_filename)
       VALUES (?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET
         descriptor = excluded.descriptor,
         photo_filename = COALESCE(excluded.photo_filename, face_references.photo_filename),
         updated_at = CURRENT_TIMESTAMP`,
      [req.user.id, JSON.stringify(descriptor), photoFilename]
    );
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)',
      ['Cadastro facial', req.user.id, 'Rosto cadastrado/atualizado para assinatura de holerites']);
    res.json({ success: true, mensagem: 'Rosto cadastrado com sucesso. Agora você pode assinar holerites por reconhecimento facial.' });
  } catch (err) {
    console.error('[face/cadastrar]', err);
    res.status(500).json({ error: 'Erro ao salvar cadastro facial' });
  }
});

// Verifica se o usuário logado já tem rosto cadastrado
app.get('/api/face/status', auth, async (req, res) => {
  try {
    const ref = await dbGet('SELECT id, updated_at FROM face_references WHERE user_id = ?', [req.user.id]);
    res.json({ cadastrado: !!ref, atualizado_em: ref ? ref.updated_at : null });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Remove o cadastro facial do usuário logado
app.delete('/api/face/cadastrar', auth, async (req, res) => {
  try {
    await dbRun('DELETE FROM face_references WHERE user_id = ?', [req.user.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Passo 1: iniciar assinatura facial (exige rosto já cadastrado)
app.post('/api/holerites/:id/assinatura-local/facial/solicitar', auth, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  const role = req.user.role;
  try {
    const holerite = await dbGet('SELECT * FROM holerites WHERE id = ?', [id]);
    if (!holerite) return res.status(404).json({ error: 'Holerite não encontrado' });
    if (role !== 'admin' && holerite.user_id !== userId) {
      return res.status(403).json({ error: 'Acesso negado' });
    }

    const faceRef = await dbGet('SELECT id FROM face_references WHERE user_id = ?', [userId]);
    if (!faceRef) {
      return res.status(412).json({
        error: 'Você ainda não cadastrou seu rosto neste dispositivo/conta.',
        precisa_cadastro: true,
      });
    }

    const token = gerarToken();
    await dbRun(
      `INSERT INTO local_signature_facial_requests (holerite_id, token, signer_name) VALUES (?, ?, ?)`,
      [id, token, req.user.name]
    );

    res.json({ token, mensagem: 'Posicione o rosto na câmera para confirmar a assinatura.', expira_em_segundos: CODE_TTL_MS / 1000 });
  } catch (err) {
    console.error('[assinatura-local/facial/solicitar]', err);
    res.status(500).json({ error: 'Erro ao iniciar assinatura facial' });
  }
});

// Passo 2: confirmar com o descriptor capturado e assinar o documento
app.post('/api/holerites/:id/assinatura-local/facial/confirmar', auth, async (req, res) => {
  const { id } = req.params;
  const { token, descriptor, selfie } = req.body;
  const userId = req.user.id;
  const role = req.user.role;

  if (!token || !faceMatch.isValidDescriptor(descriptor)) {
    return res.status(400).json({ error: 'Token e captura facial válida são obrigatórios' });
  }

  try {
    const holerite = await dbGet('SELECT * FROM holerites WHERE id = ?', [id]);
    if (!holerite) return res.status(404).json({ error: 'Holerite não encontrado' });
    if (role !== 'admin' && holerite.user_id !== userId) {
      return res.status(403).json({ error: 'Acesso negado' });
    }

    const rec = await dbGet(
      'SELECT * FROM local_signature_facial_requests WHERE token = ? AND holerite_id = ?',
      [token, id]
    );
    if (!rec) return res.status(410).json({ error: 'Solicitação não encontrada. Inicie a assinatura facial novamente.' });

    const idade = Date.now() - new Date(rec.created_at + 'Z').getTime();
    if (idade > CODE_TTL_MS) {
      await dbRun('DELETE FROM local_signature_facial_requests WHERE id = ?', [rec.id]);
      return res.status(410).json({ error: 'Solicitação expirada. Tente novamente.' });
    }
    if (rec.attempts >= MAX_CODE_ATTEMPTS) {
      await dbRun('DELETE FROM local_signature_facial_requests WHERE id = ?', [rec.id]);
      return res.status(429).json({ error: 'Número máximo de tentativas excedido. Inicie novamente.' });
    }

    const faceRef = await dbGet('SELECT * FROM face_references WHERE user_id = ?', [userId]);
    if (!faceRef) return res.status(412).json({ error: 'Cadastro facial não encontrado.', precisa_cadastro: true });

    const referenceDescriptor = JSON.parse(faceRef.descriptor);
    const { match, distance } = faceMatch.isMatch(referenceDescriptor, descriptor);

    if (!match) {
      await dbRun('UPDATE local_signature_facial_requests SET attempts = attempts + 1 WHERE id = ?', [rec.id]);
      const restantes = MAX_CODE_ATTEMPTS - (rec.attempts + 1);
      return res.status(401).json({ error: `Rosto não reconhecido. Tentativas restantes: ${restantes}`, distancia: distance });
    }

    // rosto confere -> assina
    const originalPath = path.join(__dirname, 'uploads', holerite.filename);
    if (!fs.existsSync(originalPath)) {
      return res.status(404).json({ error: 'Arquivo original do holerite não encontrado' });
    }
    const dataBuffer = fs.readFileSync(originalPath);
    const sigResult = signatureEngine.sign(dataBuffer);

    const selfieFilename = saveBase64Image(selfie, 'assinatura-facial');
    const verificationLabel = `Reconhecimento facial (distância ${distance.toFixed(3)} / limite ${faceMatch.THRESHOLD})`;

    const signedPdfBytes = await createSignedPdf(originalPath, {
      originalName: holerite.original_name || holerite.filename,
      signerName: rec.signer_name,
      signerEmail: `Verificado por reconhecimento facial (${req.user.cpf || req.user.name})`,
      digest: sigResult.digest_sha256,
      signedAt: sigResult.signed_at,
      algorithm: sigResult.algorithm,
      verificationLabel,
    });

    const signedFilename = `assinado-facial-${Date.now()}-${Math.floor(Math.random() * 1e6)}.pdf`;
    fs.writeFileSync(path.join(__dirname, 'uploads', signedFilename), signedPdfBytes);

    await dbRun(
      `INSERT INTO local_signatures (holerite_id, signer_name, signer_email, digest_sha256, signature, algorithm, signed_filename, verification_method, selfie_filename)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(holerite_id) DO UPDATE SET
         signer_name=excluded.signer_name, signer_email=excluded.signer_email,
         digest_sha256=excluded.digest_sha256, signature=excluded.signature,
         algorithm=excluded.algorithm, signed_filename=excluded.signed_filename,
         verification_method=excluded.verification_method, selfie_filename=excluded.selfie_filename,
         signed_at=CURRENT_TIMESTAMP`,
      [id, rec.signer_name, verificationLabel, sigResult.digest_sha256, sigResult.signature, sigResult.algorithm, signedFilename, 'facial', selfieFilename]
    );

    await dbRun(
      `UPDATE holerites SET status = 'assinado', filename = ?, signed_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [signedFilename, id]
    );

    await dbRun('DELETE FROM local_signature_facial_requests WHERE id = ?', [rec.id]);
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)',
      ['Assinatura digital facial', userId, `Holerite ID ${id} assinado por reconhecimento facial (distância ${distance.toFixed(3)})`]);

    res.json({
      mensagem: 'Rosto reconhecido. Documento assinado com sucesso.',
      assinatura: {
        digest_sha256: sigResult.digest_sha256,
        algorithm: sigResult.algorithm,
        signed_at: sigResult.signed_at,
        signer_name: rec.signer_name,
        distancia: distance,
      },
      arquivo_assinado: signedFilename,
    });
  } catch (err) {
    console.error('[assinatura-local/facial/confirmar]', err);
    res.status(500).json({ error: 'Erro ao confirmar assinatura facial' });
  }
});

app.delete('/api/holerites/:id', auth, adminComumOnly, (req, res) => {
  const { id } = req.params;
  db.get('SELECT filename FROM holerites WHERE id = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row && row.filename) {
      const fp = path.join(__dirname, 'uploads', row.filename);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
    db.run('DELETE FROM holerites WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    });
  });
});

// ===================== OCORRÊNCIAS =====================
app.get('/api/ocorrencias', auth, (req, res) => {
  const user = req.user;
  let sql, params;
  if (user.role === 'admin') {
    sql = `SELECT o.*, u.name as nome_colaborador FROM ocorrencias o JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC`;
    params = [];
  } else {
    sql = `SELECT o.*, u.name as nome_colaborador FROM ocorrencias o JOIN users u ON o.user_id = u.id WHERE o.user_id = ? ORDER BY o.created_at DESC`;
    params = [user.id];
  }
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});
app.post('/api/ocorrencias', auth, adminComumOnly, (req, res) => {
  const { user_id, tipo, data, obs } = req.body;
  if (!user_id || !tipo || !data) return res.status(400).json({ error: 'Dados incompletos' });
  db.run('INSERT INTO ocorrencias (user_id, tipo, data, obs) VALUES (?, ?, ?, ?)', [user_id, tipo, data, obs || null], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['Ocorrência registrada', req.user.id, `Tipo: ${tipo} para usuário ${user_id}`]);
    res.json({ id: this.lastID });
  });
});
app.post('/api/ocorrencias/:id/resolve', auth, adminComumOnly, (req, res) => {
  db.run('UPDATE ocorrencias SET status = ? WHERE id = ?', ['resolvido', req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});
app.delete('/api/ocorrencias/:id', auth, adminComumOnly, (req, res) => {
  db.run('DELETE FROM ocorrencias WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ===================== FÉRIAS =====================
app.get('/api/ferias', auth, (req, res) => {
  const user = req.user;
  let sql, params;
  if (user.role === 'admin') {
    sql = `SELECT f.*, u.name as nome_colaborador FROM ferias f JOIN users u ON f.user_id = u.id ORDER BY f.created_at DESC`;
    params = [];
  } else {
    sql = `SELECT f.*, u.name as nome_colaborador FROM ferias f JOIN users u ON f.user_id = u.id WHERE f.user_id = ? ORDER BY f.created_at DESC`;
    params = [user.id];
  }
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});
app.post('/api/ferias', auth, (req, res) => {
  const { data_inicio, data_fim, observacao } = req.body;
  if (!data_inicio || !data_fim) return res.status(400).json({ error: 'Datas incompletas' });
  db.run('INSERT INTO ferias (user_id, data_inicio, data_fim, observacao) VALUES (?, ?, ?, ?)', [req.user.id, data_inicio, data_fim, observacao || null], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID });
  });
});
app.post('/api/ferias/:id/aprovar', auth, adminComumOnly, (req, res) => {
  db.run('UPDATE ferias SET status = ? WHERE id = ?', ['aprovada', req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});
app.post('/api/ferias/:id/negar', auth, adminComumOnly, (req, res) => {
  db.run('UPDATE ferias SET status = ? WHERE id = ?', ['negada', req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});
app.delete('/api/ferias/:id', auth, adminComumOnly, (req, res) => {
  db.run('DELETE FROM ferias WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ===================== INFORMES =====================
app.get('/api/informes', auth, (req, res) => {
  const user = req.user;
  let sql, params;
  if (user.role === 'admin') {
    sql = `SELECT i.*, u.name as nome_colaborador FROM informes i LEFT JOIN users u ON i.user_id = u.id ORDER BY i.created_at DESC`;
    params = [];
  } else {
    sql = `SELECT i.*, u.name as nome_colaborador FROM informes i LEFT JOIN users u ON i.user_id = u.id WHERE i.user_id IS NULL OR i.user_id = ? ORDER BY i.created_at DESC`;
    params = [user.id];
  }
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});
app.post('/api/informes', auth, adminComumOnly, upload.single('file'), (req, res) => {
  const { ano, user_id } = req.body;
  if (!ano) return res.status(400).json({ error: 'Ano obrigatório' });
  const filename = req.file ? req.file.filename : null;
  const original_name = req.file ? req.file.originalname : null;
  const targetUserId = user_id === 'todos' || !user_id ? null : parseInt(user_id);
  db.run('INSERT INTO informes (ano, user_id, filename, original_name) VALUES (?, ?, ?, ?)', [ano, targetUserId, filename, original_name], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID });
  });
});
app.delete('/api/informes/:id', auth, adminComumOnly, (req, res) => {
  const { id } = req.params;
  db.get('SELECT filename FROM informes WHERE id = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row && row.filename) {
      const fp = path.join(__dirname, 'uploads', row.filename);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
    db.run('DELETE FROM informes WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    });
  });
});

// ===================== DOCUMENTOS =====================
app.get('/api/documentos', auth, (req, res) => {
  const user = req.user;
  let sql, params;
  if (user.role === 'admin') {
    sql = `SELECT d.*, u.name as nome_destinatario FROM documentos d LEFT JOIN users u ON d.user_id = u.id ORDER BY d.created_at DESC`;
    params = [];
  } else {
    sql = `SELECT d.*, u.name as nome_destinatario FROM documentos d LEFT JOIN users u ON d.user_id = u.id WHERE d.user_id IS NULL OR d.user_id = ? ORDER BY d.created_at DESC`;
    params = [user.id];
  }
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});
app.post('/api/documentos', auth, adminComumOnly, upload.single('file'), (req, res) => {
  const { titulo, categoria, user_id, obs } = req.body;
  if (!titulo) return res.status(400).json({ error: 'Título obrigatório' });
  const filename = req.file ? req.file.filename : null;
  const original_name = req.file ? req.file.originalname : null;
  const targetUserId = user_id === 'todos' || !user_id ? null : parseInt(user_id);
  db.run('INSERT INTO documentos (titulo, categoria, user_id, obs, filename, original_name) VALUES (?, ?, ?, ?, ?, ?)', [titulo, categoria || null, targetUserId, obs || null, filename, original_name], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID });
  });
});
app.delete('/api/documentos/:id', auth, adminComumOnly, (req, res) => {
  const { id } = req.params;
  db.get('SELECT filename FROM documentos WHERE id = ?', [id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row && row.filename) {
      const fp = path.join(__dirname, 'uploads', row.filename);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
    db.run('DELETE FROM documentos WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true });
    });
  });
});

// ===================== AVISOS =====================
app.get('/api/alerts', auth, (req, res) => {
  const user = req.user;
  let sql, params;
  if (user.role === 'admin') {
    sql = `SELECT a.*, u.name as target_name FROM alerts a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC`;
    params = [];
  } else {
    sql = `SELECT a.*, u.name as target_name, (SELECT COUNT(*) FROM alert_reads WHERE alert_id = a.id AND user_id = ?) as is_read FROM alerts a LEFT JOIN users u ON a.user_id = u.id WHERE a.type = 'geral' OR a.user_id = ? ORDER BY a.created_at DESC`;
    params = [user.id, user.id];
  }
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});
app.post('/api/alerts', auth, adminComumOnly, (req, res) => {
  const { title, message, type, user_id } = req.body;
  if (!title || !message) return res.status(400).json({ error: 'Dados incompletos' });
  db.run('INSERT INTO alerts (title, message, type, user_id) VALUES (?, ?, ?, ?)', [title, message, type || 'geral', type === 'pessoal' ? user_id : null], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID });
  });
});
app.post('/api/alerts/:id/read', auth, (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  db.run('INSERT OR IGNORE INTO alert_reads (alert_id, user_id) VALUES (?, ?)', [id, userId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});
app.delete('/api/alerts/:id', auth, adminComumOnly, (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM alerts WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ===================== ATIVIDADES =====================
app.get('/api/activities', auth, adminComumOnly, (req, res) => {
  db.all(`SELECT a.*, u.name as user_name FROM activities a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC LIMIT 50`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ===================== FINANCEIRO =====================
app.get('/api/financeiro', auth, financeiroOnly, async (req, res) => {
  try {
    let rows;
    if (req.user.role === 'admin') {
      rows = await dbAll(`SELECT f.*, u.name as usuario_nome, e.nome as empresa_nome FROM financeiro_uploads f JOIN users u ON f.usuario_id = u.id LEFT JOIN empresas e ON f.empresa_id = e.id ORDER BY f.created_at DESC`);
    } else {
      rows = await dbAll(`SELECT f.*, u.name as usuario_nome, e.nome as empresa_nome FROM financeiro_uploads f JOIN users u ON f.usuario_id = u.id LEFT JOIN empresas e ON f.empresa_id = e.id WHERE f.usuario_id = ? ORDER BY f.created_at DESC`, [req.user.id]);
    }
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/financeiro', auth, financeiroOnly, upload.single('file'), async (req, res) => {
  const { valor, data_pagamento, observacao } = req.body;
  if (!valor || !data_pagamento) return res.status(400).json({ error: 'Valor e data de pagamento obrigatórios' });
  const filename = req.file ? req.file.filename : null;
  const original_name = req.file ? req.file.originalname : null;
  try {
    const result = await dbRun('INSERT INTO financeiro_uploads (usuario_id, empresa_id, valor, data_pagamento, arquivo, original_name, observacao) VALUES (?, ?, ?, ?, ?, ?, ?)', [req.user.id, req.user.empresa_id || null, valor, data_pagamento, filename, original_name, observacao || null]);
    res.json({ id: result.lastID });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/financeiro/:id/status', auth, checkPermission('financeiro'), async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  if (!['pago','nao_pago','devedor'].includes(status)) return res.status(400).json({ error: 'Status inválido' });
  try {
    await dbRun('UPDATE financeiro_uploads SET status = ? WHERE id = ?', [status, id]);
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['Alteração status financeiro', req.user.id, `ID ${id} → ${status}`]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/financeiro/aviso', auth, checkPermission('financeiro'), async (req, res) => {
  const { user_id, title, message } = req.body;
  if (!user_id || !title || !message) return res.status(400).json({ error: 'Dados incompletos' });
  try {
    db.run('INSERT INTO alerts (title, message, type, user_id) VALUES (?, ?, ?, ?)', [title, message, 'pessoal', user_id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      db.run('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)', ['Aviso financeiro enviado', req.user.id, `Para usuário ${user_id}: ${title}`]);
      res.json({ id: this.lastID, success: true });
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/financeiro/:id', auth, checkPermission('exclusao'), async (req, res) => {
  const { id } = req.params;
  try {
    const row = await dbGet('SELECT arquivo FROM financeiro_uploads WHERE id = ?', [id]);
    if (row && row.arquivo) {
      const fp = path.join(__dirname, 'uploads', row.arquivo);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
    await dbRun('DELETE FROM financeiro_uploads WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===================== DASHBOARD =====================
app.get('/api/dashboard', auth, async (req, res) => {
  const user = req.user;
  const today = new Date().toISOString().split('T')[0];
  try {
    if (user.role === 'admin') {
      const [total, pendentes, assinados, colab, novos, vencidos, proximos] = await Promise.all([
        dbGet('SELECT COUNT(*) as v FROM holerites'),
        dbGet("SELECT COUNT(*) as v FROM holerites WHERE status != 'assinado'"),
        dbGet("SELECT COUNT(*) as v FROM holerites WHERE status = 'assinado'"),
        dbGet("SELECT COUNT(*) as v FROM users WHERE role = 'user'"),
        dbGet("SELECT COUNT(*) as v FROM holerites WHERE status = 'novo'"),
        dbGet("SELECT COUNT(*) as v FROM holerites WHERE status != 'assinado' AND deadline < ?", [today]),
        dbGet("SELECT COUNT(*) as v FROM holerites WHERE status != 'assinado' AND deadline >= ? AND deadline <= date(?, '+3 days')", [today, today]),
      ]);
      res.json({
        total: total?.v || 0, pendentes: pendentes?.v || 0, assinados: assinados?.v || 0,
        colaboradores: colab?.v || 0, novos: novos?.v || 0, vencidos: vencidos?.v || 0, proximos: proximos?.v || 0,
      });
    } else {
      const id = user.id;
      const [total, pendentes, assinados, novos, vencidos, proximos] = await Promise.all([
        dbGet('SELECT COUNT(*) as v FROM holerites WHERE user_id = ?', [id]),
        dbGet("SELECT COUNT(*) as v FROM holerites WHERE user_id = ? AND status != 'assinado'", [id]),
        dbGet("SELECT COUNT(*) as v FROM holerites WHERE user_id = ? AND status = 'assinado'", [id]),
        dbGet("SELECT COUNT(*) as v FROM holerites WHERE user_id = ? AND status = 'novo'", [id]),
        dbGet("SELECT COUNT(*) as v FROM holerites WHERE user_id = ? AND status != 'assinado' AND deadline < ?", [id, today]),
        dbGet("SELECT COUNT(*) as v FROM holerites WHERE user_id = ? AND status != 'assinado' AND deadline >= ? AND deadline <= date(?, '+3 days')", [id, today, today]),
      ]);
      res.json({ total: total?.v || 0, pendentes: pendentes?.v || 0, assinados: assinados?.v || 0, novos: novos?.v || 0, vencidos: vencidos?.v || 0, proximos: proximos?.v || 0 });
    }
  } catch (err) { console.error('Dashboard error:', err); res.status(500).json({ error: 'Erro ao carregar dashboard' }); }
});


// ===================== AJUSTES DE PONTO (solicitações do colaborador) =====================
db.run(`CREATE TABLE IF NOT EXISTS ajustes_ponto (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  tipo TEXT NOT NULL,
  data TEXT NOT NULL,
  obs TEXT,
  resposta_rh TEXT,
  status TEXT DEFAULT 'pendente',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`);

// Colaborador: lista seus próprios ajustes | Admin: lista todos
app.get('/api/ajustes-ponto', auth, async (req, res) => {
  try {
    let rows;
    if (req.user.role === 'admin') {
      rows = await dbAll(
        `SELECT a.*, u.name as nome_colaborador FROM ajustes_ponto a
         JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC`
      );
    } else {
      rows = await dbAll(
        `SELECT a.*, u.name as nome_colaborador FROM ajustes_ponto a
         JOIN users u ON a.user_id = u.id
         WHERE a.user_id = ? ORDER BY a.created_at DESC`,
        [req.user.id]
      );
    }
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Colaborador cria solicitação de ajuste/ocorrência
app.post('/api/ajustes-ponto', auth, async (req, res) => {
  const { tipo, data, hora, obs } = req.body;
  if (!tipo || !data) return res.status(400).json({ error: 'Tipo e data são obrigatórios' });
  try {
    const result = await dbRun(
      'INSERT INTO ajustes_ponto (user_id, tipo, data, hora, obs) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, tipo, data, hora || null, obs || null]
    );
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?,?,?)',
      ['Solicitação ajuste ponto', req.user.id, `Tipo: ${tipo} em ${data}`]);
    res.json({ id: result.lastID });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Tipos de ajuste que representam uma marcação faltante e por isso, ao serem
// aprovados, geram um NOVO registro corretivo na cadeia de ponto (nunca
// alteram um registro existente — exigência da Portaria MTP 671/2021).
const AJUSTE_PARA_TIPO_PONTO = {
  ajuste_entrada: 'entrada',
  esqueci_marcar: 'entrada',
  ajuste_saida: 'saida',
  hora_extra: 'saida',
};

// Admin responde/resolve um ajuste
app.put('/api/ajustes-ponto/:id', auth, adminComumOnly, async (req, res) => {
  const { status, resposta_rh } = req.body;
  const valid = ['pendente', 'aprovado', 'negado', 'em_analise'];
  if (!valid.includes(status)) return res.status(400).json({ error: 'Status inválido' });
  try {
    const ajuste = await dbGet('SELECT * FROM ajustes_ponto WHERE id = ?', [req.params.id]);
    if (!ajuste) return res.status(404).json({ error: 'Ajuste não encontrado' });

    await dbRun(
      'UPDATE ajustes_ponto SET status = ?, resposta_rh = ? WHERE id = ?',
      [status, resposta_rh || null, req.params.id]
    );

    let registroGerado = null;
    // Ao aprovar um ajuste com horário informado, cria um registro corretivo
    // real na cadeia de ponto — o pedido em si nunca é "convertido" num
    // registro existente, e o original (se houver) permanece intocado.
    if (status === 'aprovado' && ajuste.hora && AJUSTE_PARA_TIPO_PONTO[ajuste.tipo]) {
      registroGerado = await registrarPontoComCadeia({
        userId: ajuste.user_id,
        tipo: AJUSTE_PARA_TIPO_PONTO[ajuste.tipo],
        data: ajuste.data,
        hora: ajuste.hora,
        origem: 'ajuste_rh',
        registradoPor: req.user.id,
        ajusteId: ajuste.id,
      });
    }

    db.run('INSERT INTO activities (action, user_id, details) VALUES (?,?,?)',
      ['Resposta ajuste ponto', req.user.id, `Ajuste #${req.params.id} → ${status}` + (registroGerado ? ` — gerou registro corretivo NSR ${registroGerado.nsr}` : '')]);
    res.json({ success: true, registro_corretivo: registroGerado });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/ajustes-ponto/:id', auth, adminComumOnly, async (req, res) => {
  try {
    await dbRun('DELETE FROM ajustes_ponto WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===================== PONTO ELETRÔNICO (batidas de ponto) =====================

// Colaborador bate o próprio ponto pelo portal (logado com seu usuário)
app.post('/api/ponto/bater', auth, async (req, res) => {
  if (req.user.role === 'totem') return res.status(403).json({ error: 'Use o totem com o CPF do colaborador' });
  const { latitude, longitude, precisao } = req.body;
  try {
    const tipo = await proximoTipoPonto(req.user.id);
    const { data, hora } = agoraBR();
    const registro = await registrarPontoComCadeia({
      userId: req.user.id, tipo, data, hora, latitude, longitude, precisao, origem: 'portal',
    });
    await dbRun('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)',
      [`Ponto: ${tipo}`, req.user.id, `${req.user.name} registrou ${tipo} às ${hora} (portal) — NSR ${registro.nsr}`]);
    res.json({ success: true, id: registro.id, nsr: registro.nsr, tipo, data, hora });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Totem de recepção: colaborador digita o CPF no teclado numérico do totem
app.post('/api/ponto/bater-cpf', auth, somenteTotem, async (req, res) => {
  const { cpf, latitude, longitude, precisao } = req.body;
  if (!cpf) return res.status(400).json({ error: 'Informe o CPF' });
  const normalizedCpf = cpf.replace(/\D/g, '') || cpf.trim();
  try {
    const colaborador = await dbGet('SELECT * FROM users WHERE cpf = ? AND role != ?', [normalizedCpf, 'totem']);
    if (!colaborador) return res.status(404).json({ error: 'CPF não encontrado' });

    const tipo = await proximoTipoPonto(colaborador.id);
    const { data, hora } = agoraBR();
    const registro = await registrarPontoComCadeia({
      userId: colaborador.id, tipo, data, hora, latitude, longitude, precisao, origem: 'totem', registradoPor: req.user.id,
    });
    await dbRun('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)',
      [`Ponto: ${tipo}`, colaborador.id, `${colaborador.name} registrou ${tipo} às ${hora} (totem) — NSR ${registro.nsr}`]);
    res.json({ success: true, id: registro.id, nsr: registro.nsr, tipo, data, hora, nome: colaborador.name });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Batidas de hoje do usuário logado (para o botão "Bater Ponto" saber o status atual)
app.get('/api/ponto/hoje', auth, async (req, res) => {
  try {
    const { data } = agoraBR();
    const rows = await dbAll(
      'SELECT * FROM pontos_registros WHERE user_id = ? AND data = ? ORDER BY id ASC',
      [req.user.id, data]
    );
    const proximoTipo = await proximoTipoPonto(req.user.id);
    res.json({ registros: rows, proximoTipo });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Histórico de batidas: admin vê todos (com filtros opcionais), colaborador vê só os seus
app.get('/api/ponto', auth, async (req, res) => {
  try {
    if (req.user.role === 'admin') {
      const { user_id, data_inicio, data_fim } = req.query;
      let sql = `SELECT p.*, u.name as nome_colaborador FROM pontos_registros p
                 JOIN users u ON p.user_id = u.id WHERE 1=1`;
      const params = [];
      if (user_id) { sql += ' AND p.user_id = ?'; params.push(user_id); }
      if (data_inicio) { sql += ' AND p.data >= ?'; params.push(data_inicio); }
      if (data_fim) { sql += ' AND p.data <= ?'; params.push(data_fim); }
      sql += ' ORDER BY p.data DESC, p.hora DESC LIMIT 500';
      const rows = await dbAll(sql, params);
      res.json(rows);
    } else {
      const rows = await dbAll(
        'SELECT * FROM pontos_registros WHERE user_id = ? ORDER BY data DESC, hora DESC LIMIT 100',
        [req.user.id]
      );
      res.json(rows);
    }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== Comprovante de marcação (recibo do trabalhador — Portaria MTP 671/2021) =====
app.get('/api/ponto/comprovante/:id', auth, async (req, res) => {
  try {
    const reg = await dbGet(
      `SELECT p.*, u.name as nome_colaborador, u.cpf as cpf_colaborador
       FROM pontos_registros p JOIN users u ON p.user_id = u.id WHERE p.id = ?`,
      [req.params.id]
    );
    if (!reg) return res.status(404).json({ error: 'Registro não encontrado' });
    if (req.user.role !== 'admin' && req.user.id !== reg.user_id) {
      return res.status(403).json({ error: 'Você só pode ver seus próprios comprovantes' });
    }
    res.json({
      nsr: reg.nsr,
      colaborador: reg.nome_colaborador,
      cpf: reg.cpf_colaborador,
      cnpj_empregador: reg.cnpj_empregador,
      tipo: reg.tipo,
      data: reg.data,
      hora: reg.hora,
      origem: reg.origem,
      hash_registro: reg.hash_registro,
      hash_anterior: reg.hash_anterior,
      // Pendências conhecidas e sinalizadas explicitamente (não implementadas
      // ainda por decisão do cliente):
      // 1) Assinatura digital do registro com certificado ICP-Brasil, prevista
      //    na norma para valor de prova plena perante fiscalização/Justiça do
      //    Trabalho — o hash em cadeia acima já garante detecção de qualquer
      //    adulteração retroativa, mas não substitui a assinatura ICP-Brasil.
      // 2) Registro do programa (software) no INPI — trâmite administrativo
      //    de propriedade intelectual, não bloqueia o uso do sistema.
      assinatura_icp_brasil: 'pendente',
      registro_inpi_software: 'pendente',
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== Espelho de ponto do período (colaborador vê o seu; admin pode informar user_id) =====
app.get('/api/ponto/espelho', auth, async (req, res) => {
  try {
    const userId = req.user.role === 'admin' && req.query.user_id ? req.query.user_id : req.user.id;
    const { data_inicio, data_fim } = req.query;
    let sql = `SELECT p.*, u.name as nome_colaborador, u.cpf as cpf_colaborador
               FROM pontos_registros p JOIN users u ON p.user_id = u.id WHERE p.user_id = ?`;
    const params = [userId];
    if (data_inicio) { sql += ' AND p.data >= ?'; params.push(data_inicio); }
    if (data_fim) { sql += ' AND p.data <= ?'; params.push(data_fim); }
    sql += ' ORDER BY p.data ASC, p.hora ASC';
    const registros = await dbAll(sql, params);
    res.json({ registros });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== AFD — Arquivo Fonte de Dados =====
// Leiaute posicional OFICIAL do MTE ("Leiaute do Arquivo Fonte de Dados -
// AFD.pdf", anexo referenciado pelo art. 81 da Portaria MTP nº 671/2021),
// específico para REP-P (Registrador Eletrônico de Ponto via Programa):
//   - Registro tipo "1": Cabeçalho (identificação do empregador)
//   - Registro tipo "7": Marcação de ponto (REP-P — não confundir com o
//     tipo "3", que é exclusivo de REP-C/REP-A)
//   - Registro tipo "9": Trailer (totais por tipo de registro)
//   - Linha final: placeholder de assinatura digital (ver ATENÇÃO abaixo)
// Formato: texto ISO-8859-1, uma linha por registro terminando em \r\n,
// campos de largura fixa (sem delimitador), ordenados por NSR.
//
// ⚠️ ATENÇÃO: o art. 88 da Portaria 671/2021 exige que a assinatura
// eletrônica do REP-P use certificado ICP-Brasil (padrão CAdES, arquivo
// .p7s destacado). Este endpoint gera o AFD no leiaute correto, mas SEM
// acompanhar um .p7s real — a linha de assinatura é só o placeholder que
// o próprio leiaute exige nessa situação. Ver /api/ponto/conformidade.
app.get('/api/ponto/afd', auth, adminOnly, async (req, res) => {
  try {
    const { data_inicio, data_fim, user_id } = req.query;
    let sql = `SELECT p.*, u.name as nome_colaborador, u.cpf as cpf_colaborador
               FROM pontos_registros p JOIN users u ON p.user_id = u.id WHERE 1=1`;
    const params = [];
    if (data_inicio) { sql += ' AND p.data >= ?'; params.push(data_inicio); }
    if (data_fim) { sql += ' AND p.data <= ?'; params.push(data_fim); }
    if (user_id) { sql += ' AND p.user_id = ?'; params.push(user_id); }
    sql += ' ORDER BY p.nsr ASC';
    const registros = await dbAll(sql, params);

    const empresa = await dbGet(`SELECT nome, cnpj FROM empresas LIMIT 1`);
    const cnpjEmpresa = (empresa && empresa.cnpj) || '';
    const nomeEmpresa = (empresa && empresa.nome) || 'EMPRESA NAO CADASTRADA';

    const configRows = await dbAll(
      `SELECT chave, valor FROM configuracoes WHERE chave IN ('ponto_numero_registro_inpi','ponto_cnpj_desenvolvedor')`
    );
    const configMap = Object.fromEntries(configRows.map(r => [r.chave, r.valor]));
    const numeroRegistroInpi = configMap.ponto_numero_registro_inpi || '99999999999999999';
    const cnpjDesenvolvedor = configMap.ponto_cnpj_desenvolvedor || cnpjEmpresa;

    const agora = new Date();
    const dataHoraGeracao = afdLayout.dhFromDate(agora);
    const dataInicial = registros.length ? registros[0].data : (data_inicio || afdLayout.dataFmt(dataHoraGeracao));
    const dataFinal = registros.length ? registros[registros.length - 1].data : (data_fim || afdLayout.dataFmt(dataHoraGeracao));

    const linhas = [];

    // Registro tipo "1" — Cabeçalho
    linhas.push(afdLayout.registroTipo1({
      cnpjEmpregador: cnpjEmpresa,
      nomeEmpregador: nomeEmpresa,
      numeroRegistroInpi,
      dataInicial,
      dataFinal,
      dataHoraGeracao,
      cnpjDesenvolvedor,
    }));

    // Registro tipo "7" — uma linha por marcação (REP-P)
    registros.forEach(r => {
      linhas.push(afdLayout.registroTipo7({
        nsr: r.nsr,
        dataMarcacao: r.data,
        horaMarcacao: r.hora,
        cpf: r.cpf_colaborador,
        dataHoraGravacao: r.data_hora_gravacao || afdLayout.dhFmt(r.data, r.hora),
        coletor: r.coletor || afdLayout.coletorFromOrigem(r.origem),
        online: r.online || '0',
        hashRegistro: r.hash_registro || '',
      }));
    });

    // Registro tipo "9" — Trailer (todas as marcações contam como tipo "7")
    linhas.push(afdLayout.registroTipo9({ qtdTipo7: registros.length }));

    // Linha de assinatura digital (placeholder — ver ATENÇÃO no cabeçalho da rota)
    linhas.push(afdLayout.linhaAssinaturaPlaceholder());

    const conteudo = linhas.join('\r\n') + '\r\n';
    const conteudoLatin1 = Buffer.from(conteudo, 'latin1'); // ISO-8859-1 exigido pelo leiaute

    const cnpjLimpo = cnpjEmpresa.replace(/\D/g, '') || 'SEMCNPJ';
    const nomeArquivo = `AFD${numeroRegistroInpi}${cnpjLimpo}REP_P.txt`;

    await dbRun('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)',
      ['AFD exportado', req.user.id, `Admin exportou AFD com ${registros.length} registro(s) — assinatura ICP-Brasil (.p7s) pendente`]);

    res.setHeader('Content-Type', 'text/plain; charset=ISO-8859-1');
    res.setHeader('Content-Disposition', `attachment; filename="${nomeArquivo}"`);
    res.send(conteudoLatin1);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===== Verificação de integridade da cadeia de hashes (detecta adulteração) =====
app.get('/api/ponto/verificar-integridade', auth, adminOnly, async (req, res) => {
  try {
    const registros = await dbAll(
      `SELECT p.*, u.cpf as cpf_colaborador FROM pontos_registros p JOIN users u ON p.user_id = u.id ORDER BY p.nsr ASC`
    );
    let hashEsperado = NSR_GENESIS_HASH;
    let integro = true;
    let primeiraFalha = null;
    for (const r of registros) {
      const recalculado = calcularHashRegistro({
        nsr: r.nsr, data: r.data, hora: r.hora, cpf: r.cpf_colaborador,
        dataHoraGravacao: r.data_hora_gravacao || afdLayout.dhFmt(r.data, r.hora),
        coletor: r.coletor || afdLayout.coletorFromOrigem(r.origem),
        online: r.online || '0',
        hashAnterior: hashEsperado,
      });
      if (recalculado !== r.hash_registro) {
        integro = false;
        primeiraFalha = r.nsr;
        break;
      }
      hashEsperado = r.hash_registro;
    }
    res.json({ integro, total_registros: registros.length, primeira_falha_nsr: primeiraFalha });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// ===== Painel de conformidade legal do módulo de Ponto (Portaria MTP 671/2021) =====
app.get('/api/ponto/conformidade', auth, adminOnly, (req, res) => {
  res.json({
    norma: 'Portaria MTP nº 671/2021 (REP-P — Registrador Eletrônico de Ponto por Programa)',
    itens: [
      { item: 'Identificação do empregador (CNPJ) em cada marcação', status: 'implementado' },
      { item: 'Identificação do trabalhador (CPF) em cada marcação', status: 'implementado' },
      { item: 'Marcação sem bloqueio/restrição de horário', status: 'implementado' },
      { item: 'Trabalhador com acesso irrestrito ao próprio espelho de ponto', status: 'implementado' },
      { item: 'Comprovante de marcação para o trabalhador', status: 'implementado' },
      { item: 'Vedação à alteração/exclusão de registros (append-only + cadeia de hash)', status: 'implementado' },
      { item: 'Correções via processo formal, gerando novo registro corretivo auditável', status: 'implementado' },
      { item: 'Número Sequencial de Registro (NSR)', status: 'implementado' },
      { item: 'Exportação do AFD no leiaute posicional oficial do MTE (tipo "7" para REP-P, CRC-16/KERMIT, ISO-8859-1)', status: 'implementado' },
      { item: 'Retenção dos registros (sem exclusão automática/pelo sistema)', status: 'implementado' },
      { item: 'Assinatura eletrônica do AFD com certificado ICP-Brasil (padrão CAdES, arquivo .p7s)', status: 'pendente', motivo: 'exigência do art. 88 da Portaria 671/2021 — depende da contratação de um provedor de certificado ICP-Brasil (ex.: BirdID, VIDaaS, Certisign Cloud); sem isso o AFD gerado NÃO está juridicamente completo mesmo com o leiaute correto' },
      { item: 'Registro do programa (software) no INPI', status: 'pendente', motivo: 'trâmite administrativo de propriedade intelectual — o número de registro deve ser cadastrado em configuracoes.ponto_numero_registro_inpi assim que obtido' },
    ],
  });
});

app.get('/api/admin/totem', auth, adminOnly, async (req, res) => {
  try {
    const rows = await dbAll(`SELECT id, cpf, name, created_at FROM users WHERE role = 'totem' ORDER BY name`);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/totem', auth, adminOnly, async (req, res) => {
  const { cpf, name, password } = req.body;
  if (!cpf || !name || !password) return res.status(400).json({ error: 'Dados incompletos' });
  const normalizedCpf = cpf.replace(/\D/g, '') || cpf.trim();
  const hashed = bcrypt.hashSync(password, 10);
  try {
    const result = await dbRun(
      `INSERT INTO users (cpf, name, password, role) VALUES (?, ?, ?, 'totem')`,
      [normalizedCpf, name, hashed]
    );
    await dbRun('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)',
      ['Totem de ponto criado', req.user.id, `Totem "${name}" (CPF de acesso: ${normalizedCpf}) criado`]);
    res.json({ id: result.lastID, cpf: normalizedCpf, name });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) return res.status(409).json({ error: 'Esse CPF/código já está em uso' });
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/totem/:id', auth, adminOnly, async (req, res) => {
  try {
    const result = await dbRun(`DELETE FROM users WHERE id = ? AND role = 'totem'`, [req.params.id]);
    if (result.changes === 0) return res.status(404).json({ error: 'Totem não encontrado' });
    await dbRun('INSERT INTO activities (action, user_id, details) VALUES (?, ?, ?)',
      ['Totem de ponto removido', req.user.id, `Totem ID ${req.params.id} removido`]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===================== CONTROLE INTERNO (canal anônimo de compliance) =====================
db.run(`CREATE TABLE IF NOT EXISTS controle_interno (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  categoria TEXT NOT NULL,
  mensagem TEXT NOT NULL,
  status TEXT DEFAULT 'novo',
  resposta_admin TEXT,
  protocolo TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Qualquer usuário autenticado envia — sem gravar user_id (anônimo)
app.post('/api/controle-interno', auth, async (req, res) => {
  const { categoria, mensagem } = req.body;
  if (!categoria || !mensagem || mensagem.trim().length < 10) {
    return res.status(400).json({ error: 'Categoria e mensagem (mín. 10 caracteres) são obrigatórios' });
  }
  // Protocolo aleatório — permite ao colaborador acompanhar sem se identificar
  const protocolo = 'CI-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2,5).toUpperCase();
  try {
    const result = await dbRun(
      'INSERT INTO controle_interno (categoria, mensagem, protocolo) VALUES (?, ?, ?)',
      [categoria, mensagem.trim(), protocolo]
    );
    // Não registra activities (preserva anonimato)
    res.json({ id: result.lastID, protocolo });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Colaborador consulta seu protocolo sem se identificar
app.get('/api/controle-interno/protocolo/:protocolo', auth, async (req, res) => {
  try {
    const row = await dbGet(
      'SELECT id, categoria, status, resposta_admin, protocolo, created_at FROM controle_interno WHERE protocolo = ?',
      [req.params.protocolo]
    );
    if (!row) return res.status(404).json({ error: 'Protocolo não encontrado' });
    res.json(row);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Somente admin global vê todas as denúncias (sem nome do denunciante)
app.get('/api/controle-interno', auth, async (req, res) => {
  if (req.user.admin_type !== 'global') return res.status(403).json({ error: 'Acesso restrito ao administrador global' });
  try {
    const rows = await dbAll('SELECT * FROM controle_interno ORDER BY created_at DESC');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin responde uma denúncia
app.put('/api/controle-interno/:id', auth, async (req, res) => {
  if (req.user.admin_type !== 'global') return res.status(403).json({ error: 'Acesso restrito ao administrador global' });
  const { status, resposta_admin } = req.body;
  const valid = ['novo', 'em_analise', 'encerrado'];
  if (!valid.includes(status)) return res.status(400).json({ error: 'Status inválido' });
  try {
    await dbRun(
      'UPDATE controle_interno SET status = ?, resposta_admin = ? WHERE id = ?',
      [status, resposta_admin || null, req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/controle-interno/:id', auth, async (req, res) => {
  if (req.user.admin_type !== 'global') return res.status(403).json({ error: 'Acesso restrito ao administrador global' });
  try {
    await dbRun('DELETE FROM controle_interno WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ===================== COMPRAS / ESTOQUE =====================

// Tabelas (migration segura)
db.run(`CREATE TABLE IF NOT EXISTS produtos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL, descricao TEXT, categoria TEXT,
  unidade TEXT DEFAULT 'un', estoque_atual REAL DEFAULT 0,
  estoque_minimo REAL DEFAULT 0, preco_unitario REAL DEFAULT 0,
  ativo INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);
db.run(`CREATE TABLE IF NOT EXISTS solicitacoes_compra (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  solicitante_id INTEGER NOT NULL, titulo TEXT NOT NULL,
  prioridade TEXT DEFAULT 'normal', status TEXT DEFAULT 'pendente',
  observacao TEXT, aprovado_por INTEGER, aprovado_em DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (solicitante_id) REFERENCES users(id)
)`);
db.run(`CREATE TABLE IF NOT EXISTS solicitacao_itens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  solicitacao_id INTEGER NOT NULL, produto_id INTEGER,
  descricao TEXT NOT NULL, quantidade REAL NOT NULL,
  unidade TEXT DEFAULT 'un', preco_estimado REAL DEFAULT 0,
  FOREIGN KEY (solicitacao_id) REFERENCES solicitacoes_compra(id)
)`);
db.run(`CREATE TABLE IF NOT EXISTS movimentacoes_estoque (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  produto_id INTEGER NOT NULL, tipo TEXT NOT NULL,
  quantidade REAL NOT NULL, solicitacao_id INTEGER,
  usuario_id INTEGER, obs TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (produto_id) REFERENCES produtos(id)
)`);

// --- Produtos ---
app.get('/api/produtos', auth, adminComumOnly, async (req, res) => {
  try {
    const rows = await dbAll('SELECT * FROM produtos ORDER BY nome');
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/produtos', auth, adminComumOnly, async (req, res) => {
  const { nome, descricao, categoria, unidade, estoque_atual, estoque_minimo, preco_unitario } = req.body;
  if (!nome) return res.status(400).json({ error: 'Nome obrigatório' });
  try {
    const result = await dbRun(
      'INSERT INTO produtos (nome, descricao, categoria, unidade, estoque_atual, estoque_minimo, preco_unitario) VALUES (?,?,?,?,?,?,?)',
      [nome, descricao||null, categoria||null, unidade||'un', estoque_atual||0, estoque_minimo||0, preco_unitario||0]
    );
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?,?,?)', ['Produto cadastrado', req.user.id, nome]);
    res.json({ id: result.lastID });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/produtos/:id', auth, adminComumOnly, async (req, res) => {
  const { nome, descricao, categoria, unidade, estoque_atual, estoque_minimo, preco_unitario, ativo } = req.body;
  try {
    await dbRun(
      'UPDATE produtos SET nome=?, descricao=?, categoria=?, unidade=?, estoque_atual=?, estoque_minimo=?, preco_unitario=?, ativo=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
      [nome, descricao||null, categoria||null, unidade||'un', estoque_atual||0, estoque_minimo||0, preco_unitario||0, ativo===false?0:1, req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/produtos/:id', auth, adminComumOnly, async (req, res) => {
  try {
    await dbRun('DELETE FROM produtos WHERE id=?', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Movimentação manual de estoque
app.post('/api/produtos/:id/movimentar', auth, adminComumOnly, async (req, res) => {
  const { tipo, quantidade, obs } = req.body;
  const prodId = req.params.id;
  if (!tipo || !quantidade) return res.status(400).json({ error: 'Tipo e quantidade obrigatórios' });
  try {
    const prod = await dbGet('SELECT * FROM produtos WHERE id=?', [prodId]);
    if (!prod) return res.status(404).json({ error: 'Produto não encontrado' });
    const delta = tipo === 'entrada' ? Math.abs(quantidade) : -Math.abs(quantidade);
    const novoEstoque = Math.max(0, prod.estoque_atual + delta);
    await dbRun('UPDATE produtos SET estoque_atual=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', [novoEstoque, prodId]);
    await dbRun(
      'INSERT INTO movimentacoes_estoque (produto_id, tipo, quantidade, usuario_id, obs) VALUES (?,?,?,?,?)',
      [prodId, tipo, Math.abs(quantidade), req.user.id, obs||null]
    );
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?,?,?)', ['Movimentação estoque', req.user.id, `${tipo} de ${quantidade} em ${prod.nome}`]);
    res.json({ success: true, estoque_atual: novoEstoque });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/produtos/:id/movimentacoes', auth, adminComumOnly, async (req, res) => {
  try {
    const rows = await dbAll(
      `SELECT m.*, u.name as usuario_nome FROM movimentacoes_estoque m LEFT JOIN users u ON m.usuario_id = u.id WHERE m.produto_id=? ORDER BY m.created_at DESC LIMIT 50`,
      [req.params.id]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- Solicitações de Compra ---
app.get('/api/solicitacoes', auth, hasModulo('compras'), async (req, res) => {
  try {
    let rows;
    if (req.user.role === 'admin') {
      rows = await dbAll(
        `SELECT s.*, u.name as solicitante_nome, a.name as aprovador_nome FROM solicitacoes_compra s JOIN users u ON s.solicitante_id=u.id LEFT JOIN users a ON s.aprovado_por=a.id ORDER BY s.created_at DESC`
      );
    } else {
      rows = await dbAll(
        `SELECT s.*, u.name as solicitante_nome, a.name as aprovador_nome FROM solicitacoes_compra s JOIN users u ON s.solicitante_id=u.id LEFT JOIN users a ON s.aprovado_por=a.id WHERE s.solicitante_id=? ORDER BY s.created_at DESC`,
        [req.user.id]
      );
    }
    // Carrega itens de cada solicitação
    for (const s of rows) {
      s.itens = await dbAll('SELECT * FROM solicitacao_itens WHERE solicitacao_id=?', [s.id]);
    }
    res.json(rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/solicitacoes', auth, hasModulo('compras'), async (req, res) => {
  const { titulo, prioridade, observacao, itens } = req.body;
  if (!titulo || !itens || itens.length === 0) return res.status(400).json({ error: 'Título e pelo menos 1 item obrigatórios' });
  try {
    const result = await dbRun(
      'INSERT INTO solicitacoes_compra (solicitante_id, titulo, prioridade, observacao) VALUES (?,?,?,?)',
      [req.user.id, titulo, prioridade||'normal', observacao||null]
    );
    const solId = result.lastID;
    for (const item of itens) {
      await dbRun(
        'INSERT INTO solicitacao_itens (solicitacao_id, produto_id, descricao, quantidade, unidade, preco_estimado) VALUES (?,?,?,?,?,?)',
        [solId, item.produto_id||null, item.descricao, item.quantidade, item.unidade||'un', item.preco_estimado||0]
      );
    }
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?,?,?)', ['Solicitação de compra', req.user.id, `"${titulo}" (${itens.length} item(s))`]);
    res.json({ id: solId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/solicitacoes/:id/status', auth, adminComumOnly, async (req, res) => {
  const { status, observacao } = req.body;
  const validStatus = ['pendente','aprovada','recusada','em_andamento','concluida'];
  if (!validStatus.includes(status)) return res.status(400).json({ error: 'Status inválido' });
  try {
    const sol = await dbGet('SELECT * FROM solicitacoes_compra WHERE id=?', [req.params.id]);
    if (!sol) return res.status(404).json({ error: 'Solicitação não encontrada' });

    const aprovadoEm = ['aprovada','concluida'].includes(status) ? new Date().toISOString() : sol.aprovado_em;
    const aprovadoPor = ['aprovada','concluida'].includes(status) ? req.user.id : sol.aprovado_por;

    await dbRun(
      'UPDATE solicitacoes_compra SET status=?, observacao=COALESCE(?,observacao), aprovado_por=?, aprovado_em=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
      [status, observacao||null, aprovadoPor, aprovadoEm, req.params.id]
    );

    // Se concluída, baixa estoque dos itens que têm produto_id
    if (status === 'concluida') {
      const itens = await dbAll('SELECT * FROM solicitacao_itens WHERE solicitacao_id=?', [req.params.id]);
      for (const item of itens) {
        if (item.produto_id) {
          const prod = await dbGet('SELECT * FROM produtos WHERE id=?', [item.produto_id]);
          if (prod) {
            const novo = Math.max(0, prod.estoque_atual + item.quantidade);
            await dbRun('UPDATE produtos SET estoque_atual=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', [novo, item.produto_id]);
            await dbRun(
              'INSERT INTO movimentacoes_estoque (produto_id, tipo, quantidade, solicitacao_id, usuario_id, obs) VALUES (?,?,?,?,?,?)',
              [item.produto_id, 'entrada', item.quantidade, req.params.id, req.user.id, `Compra - Solicitação #${req.params.id}`]
            );
          }
        }
      }
    }

    db.run('INSERT INTO activities (action, user_id, details) VALUES (?,?,?)', ['Status solicitação', req.user.id, `Solicitação #${req.params.id} → ${status}`]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/solicitacoes/:id', auth, adminComumOnly, async (req, res) => {
  try {
    await dbRun('DELETE FROM solicitacao_itens WHERE solicitacao_id=?', [req.params.id]);
    await dbRun('DELETE FROM solicitacoes_compra WHERE id=?', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Dashboard compras (contadores)
app.get('/api/compras/dashboard', auth, adminComumOnly, async (req, res) => {
  try {
    const [totalSol, pendentes, aprovadas, produtos, alertaEstoque] = await Promise.all([
      dbGet('SELECT COUNT(*) as v FROM solicitacoes_compra'),
      dbGet("SELECT COUNT(*) as v FROM solicitacoes_compra WHERE status='pendente'"),
      dbGet("SELECT COUNT(*) as v FROM solicitacoes_compra WHERE status='aprovada'"),
      dbGet('SELECT COUNT(*) as v FROM produtos WHERE ativo=1'),
      dbGet('SELECT COUNT(*) as v FROM produtos WHERE ativo=1 AND estoque_atual <= estoque_minimo'),
    ]);
    res.json({
      totalSolicitacoes: totalSol?.v||0,
      pendentes: pendentes?.v||0,
      aprovadas: aprovadas?.v||0,
      totalProdutos: produtos?.v||0,
      alertaEstoque: alertaEstoque?.v||0,
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});


// ============================================================
// D4SIGN — ASSINATURA ELETRÔNICA (Documentação oficial ajuda.d4sign.com.br)
// Fluxo: upload → createlist → sendtosigner → embed → webhook
// ------------------------------------------------------------
// Variáveis obrigatórias no .env:
//   D4SIGN_TOKEN_API   = seu tokenAPI
//   D4SIGN_CRYPT_KEY   = seu cryptKey
//   D4SIGN_UUID_SAFE   = uuid do cofre onde os PDFs ficam
//   D4SIGN_BASE_URL    = https://sandbox.d4sign.com.br/api/v1  (testes)
//                     ou https://secure.d4sign.com.br/api/v1   (produção)
//   APP_URL            = URL pública do servidor (para webhook)
// ============================================================

const D4_TOKEN = process.env.D4SIGN_TOKEN_API || '';
const D4_CRYPT = process.env.D4SIGN_CRYPT_KEY  || '';
const D4_SAFE  = process.env.D4SIGN_UUID_SAFE  || '';
const D4_BASE  = (process.env.D4SIGN_BASE_URL  || 'https://sandbox.d4sign.com.br/api/v1').replace(/\/$/, '');
const APP_URL  = (process.env.APP_URL           || 'http://localhost:3000').replace(/\/$/, '');

// Tabela para rastrear cada envelope D4Sign vinculado a um holerite
db.run(`CREATE TABLE IF NOT EXISTS d4sign_docs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  holerite_id   INTEGER NOT NULL UNIQUE,
  uuid_doc      TEXT,
  key_signer    TEXT,
  signer_email  TEXT,
  status        TEXT    DEFAULT 'pendente',
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  signed_at     DATETIME,
  FOREIGN KEY (holerite_id) REFERENCES holerites(id)
)`);

// ── Helper: chama a API D4Sign (JSON) ───────────────────────────────────────
// Parâmetros tokenAPI e cryptKey sempre na query string, conforme a documentação.
async function d4fetch(endpoint, method = 'GET', body = null) {
  const url  = `${D4_BASE}${endpoint}?tokenAPI=${encodeURIComponent(D4_TOKEN)}&cryptKey=${encodeURIComponent(D4_CRYPT)}`;
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const resp = await fetch(url, opts);
  const text = await resp.text();
  try { return JSON.parse(text); } catch { return { _raw: text }; }
}

// ── 1. Enviar holerite para assinatura via D4Sign ───────────────────────────
// POST /api/holerites/:id/d4sign/enviar   (somente admin)
// Executa: upload PDF → cadastrar signatário → registrar webhook → enviar para fase de assinatura
app.post('/api/holerites/:id/d4sign/enviar', auth, adminComumOnly, async (req, res) => {
  const { id } = req.params;
  const { signer_email, signer_name, signer_cpf, signer_birthday } = req.body;

  if (!signer_email) return res.status(400).json({ error: 'E-mail do signatário obrigatório' });
  if (!D4_TOKEN)     return res.status(500).json({ error: 'Configure D4SIGN_TOKEN_API no .env' });
  if (!D4_SAFE)      return res.status(500).json({ error: 'Configure D4SIGN_UUID_SAFE no .env' });

  try {
    // Busca holerite + colaborador
    const hol = await dbGet(
      `SELECT h.*, u.name AS nome_colab, u.cpf AS cpf_colab, u.birth_date
       FROM holerites h JOIN users u ON h.user_id = u.id WHERE h.id = ?`, [id]
    );
    if (!hol)                 return res.status(404).json({ error: 'Holerite não encontrado' });
    if (hol.status === 'assinado') return res.status(400).json({ error: 'Holerite já assinado' });

    const pdfPath = path.join(__dirname, 'uploads', hol.filename);
    if (!fs.existsSync(pdfPath)) return res.status(404).json({ error: 'Arquivo PDF não encontrado no servidor' });

    // Verifica envelope já existente e ainda válido
    const existente = await dbGet('SELECT * FROM d4sign_docs WHERE holerite_id = ?', [id]);
    if (existente?.uuid_doc && existente.status === 'aguardando') {
      return res.json({ uuid_doc: existente.uuid_doc, key_signer: existente.key_signer,
        signer_email: existente.signer_email, ja_existia: true });
    }

    // ── Passo 1: Upload do PDF (multipart/form-data conforme documentação) ──
    let FormData, nodeFetch;
    try { FormData = require('form-data'); } catch {
      return res.status(500).json({ error: 'Execute: npm install form-data' });
    }
    try { nodeFetch = fetch; } catch { nodeFetch = require('node-fetch'); }

    const form = new FormData();
    form.append('file', fs.createReadStream(pdfPath), {
      filename: hol.original_name || `Holerite_${hol.month_year}.pdf`,
      contentType: 'application/pdf'
    });

    const uploadUrl = `${D4_BASE}/documents/${D4_SAFE}/upload?tokenAPI=${encodeURIComponent(D4_TOKEN)}&cryptKey=${encodeURIComponent(D4_CRYPT)}`;
    const uploadResp = await nodeFetch(uploadUrl, {
      method: 'POST',
      body: form,
      headers: form.getHeaders ? form.getHeaders() : {}
    });
    const uploadData = await uploadResp.json();

    if (!uploadData.uuid) {
      console.error('[D4Sign upload]', uploadData);
      return res.status(502).json({ error: 'Falha no upload para D4Sign', detalhes: uploadData });
    }
    const uuidDoc = uploadData.uuid;

    // ── Passo 2: Cadastrar signatário (createlist) ──────────────────────────
    // act:"1" = Assinar | skipemail:"1" = não envia e-mail (usaremos EMBED)
    const cpfLimpo   = (signer_cpf  || hol.cpf_colab  || '').replace(/\D/g, '');
    const nomeAssina = signer_name  || hol.nome_colab || '';
    const nascimento = signer_birthday || (hol.birth_date
      ? new Date(hol.birth_date + 'T00:00:00').toLocaleDateString('pt-BR') : '');

    const signerResp = await d4fetch(`/documents/${uuidDoc}/createlist`, 'POST', {
      signers: [{
        email:                 signer_email,
        act:                   '1',
        foreign:               '0',
        certificadoicpbr:      '0',
        assinatura_presencial: '0',
        embed_methodauth:      'email',
        skipemail:             '1',
        ...(nomeAssina && { display_name: nomeAssina }),
        ...(cpfLimpo   && { documentation: cpfLimpo }),
        ...(nascimento && { birthday: nascimento })
      }]
    });

    // key_signer pode vir como array ou objeto direto
    const signerData = Array.isArray(signerResp) ? signerResp[0] : signerResp;
    const keySigner  = signerData?.key_signer || '';

    // ── Passo 3: Registrar webhook ──────────────────────────────────────────
    // Endpoint: POST /documents/{UUID}/webhooks  (com 's' — documentação oficial)
    const webhookUrl = `${APP_URL}/api/d4sign/webhook`;
    await d4fetch(`/documents/${uuidDoc}/webhooks`, 'POST', { url: webhookUrl });

    // ── Passo 4: Enviar para fase "Aguardando Assinaturas" ──────────────────
    // skip_email:"1" obrigatório quando usa EMBED (documentação: "DEVERÁ ser definido como 1")
    await d4fetch(`/documents/${uuidDoc}/sendtosigner`, 'POST', {
      message:    `Prezado(a) ${nomeAssina}, seu holerite de ${hol.month_year} aguarda assinatura eletrônica.`,
      skip_email: '1',
      workflow:   '0'
    });

    // ── Salva no banco ──────────────────────────────────────────────────────
    if (existente) {
      await dbRun(
        `UPDATE d4sign_docs SET uuid_doc=?, key_signer=?, signer_email=?, status='aguardando', signed_at=NULL
         WHERE holerite_id=?`,
        [uuidDoc, keySigner, signer_email, id]
      );
    } else {
      await dbRun(
        `INSERT INTO d4sign_docs (holerite_id, uuid_doc, key_signer, signer_email, status)
         VALUES (?, ?, ?, ?, 'aguardando')`,
        [id, uuidDoc, keySigner, signer_email]
      );
    }
    await dbRun(`UPDATE holerites SET status='aguardando' WHERE id=?`, [id]);
    db.run('INSERT INTO activities (action, user_id, details) VALUES (?,?,?)',
      ['D4Sign enviado', req.user.id, `Holerite #${id} uuid_doc:${uuidDoc}`]);

    res.json({ success: true, uuid_doc: uuidDoc, key_signer: keySigner, signer_email });
  } catch (err) {
    console.error('[D4Sign enviar]', err);
    res.status(500).json({ error: err.message });
  }
});

// ── 2. Dados para montar o EMBED no portal do colaborador ───────────────────
// GET /api/holerites/:id/d4sign/embed-url
app.get('/api/holerites/:id/d4sign/embed-url', auth, async (req, res) => {
  const { id } = req.params;
  try {
    const [d4doc, hol, user] = await Promise.all([
      dbGet('SELECT * FROM d4sign_docs WHERE holerite_id = ?', [id]),
      dbGet('SELECT user_id, month_year FROM holerites WHERE id = ?', [id]),
      dbGet('SELECT name, cpf, birth_date FROM users WHERE id = ?', [req.user.id])
    ]);

    if (!d4doc?.uuid_doc)
      return res.status(404).json({ error: 'Este holerite ainda não foi enviado para a D4Sign. Solicite ao RH.' });
    if (d4doc.status === 'assinado')
      return res.status(400).json({ error: 'Este holerite já está assinado.' });

    if (req.user.role !== 'admin' && hol?.user_id !== req.user.id)
      return res.status(403).json({ error: 'Sem permissão para assinar este documento' });

    const cpfLimpo   = (user?.cpf || '').replace(/\D/g, '');
    const nascimento = user?.birth_date
      ? new Date(user.birth_date + 'T00:00:00').toLocaleDateString('pt-BR') : '';

    res.json({
      uuid_doc:      d4doc.uuid_doc,
      key_signer:    d4doc.key_signer  || '',
      signer_email:  d4doc.signer_email,
      signer_name:   user?.name        || '',
      signer_cpf:    cpfLimpo,
      signer_birthday: nascimento,
      month_year:    hol?.month_year   || '',
      // EMBED host conforme documentação oficial
      embed_host:    'https://secure.d4sign.com.br/embed/viewblob',
      status:        d4doc.status
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── 3. Webhook D4Sign (postback em multipart/form-data) ─────────────────────
// POST /api/d4sign/webhook
// IMPORTANTE: a documentação oficial diz que o disparo ocorre em formato
// multipart/form-data (não application/x-www-form-urlencoded), por isso o
// parser precisa ser o multer (sem storage de arquivo, só os campos do form).
// type_post: "1" = finalizado | "2" = e-mail não entregue | "3" = cancelado | "4" = assinatura de um signatário (parcial)
const d4webhookParser = multer(); // reaproveita o multer já importado no topo do arquivo
app.post('/api/d4sign/webhook',
  d4webhookParser.none(),   // parseia multipart/form-data sem arquivo anexo
  async (req, res) => {
    res.sendStatus(200); // responder 200 imediatamente (D4Sign faz até 7 tentativas em 27h)
    try {
      const uuid    = req.body?.uuid     || req.body?.uuid_document || '';
      const typePost = String(req.body?.type_post || '');

      if (!uuid) return;
      console.log(`[D4Sign webhook] uuid=${uuid} type_post=${typePost}`);

      if (typePost === '1') {
        // Documento FINALIZADO — todas as partes assinaram
        await dbRun(
          `UPDATE d4sign_docs SET status='assinado', signed_at=CURRENT_TIMESTAMP WHERE uuid_doc=?`,
          [uuid]
        );
        const d4doc = await dbGet('SELECT holerite_id FROM d4sign_docs WHERE uuid_doc=?', [uuid]);
        if (d4doc) {
          await dbRun(
            `UPDATE holerites SET status='assinado', signed_at=CURRENT_TIMESTAMP WHERE id=?`,
            [d4doc.holerite_id]
          );
          console.log(`✅ D4Sign: holerite #${d4doc.holerite_id} finalizado`);
        }
      } else if (typePost === '3') {
        // Documento CANCELADO
        await dbRun(`UPDATE d4sign_docs SET status='cancelado' WHERE uuid_doc=?`, [uuid]);
        const d4doc = await dbGet('SELECT holerite_id FROM d4sign_docs WHERE uuid_doc=?', [uuid]);
        if (d4doc) {
          await dbRun(`UPDATE holerites SET status='novo' WHERE id=?`, [d4doc.holerite_id]);
        }
      } else if (typePost === '2') {
        // E-mail NÃO ENTREGUE ao signatário — não é cancelamento, só um alerta
        const emailDestino = req.body?.email || '';
        console.warn(`[D4Sign webhook] E-mail não entregue — uuid ${uuid} email=${emailDestino}`);
        db.run('INSERT INTO activities (action, user_id, details) VALUES (?,?,?)',
          ['D4Sign e-mail não entregue', null, `uuid_doc:${uuid} email:${emailDestino}`]);
      } else if (typePost === '4') {
        // Assinatura de UM signatário (ainda não finalizado o documento inteiro)
        console.log(`[D4Sign webhook] Assinatura parcial registrada — uuid ${uuid}`);
      }
    } catch (err) {
      console.error('[D4Sign webhook erro]', err.message);
    }
  }
);

// ── 4. Cancelar envelope D4Sign ─────────────────────────────────────────────
// POST /api/holerites/:id/d4sign/cancelar  (somente admin)
app.post('/api/holerites/:id/d4sign/cancelar', auth, adminComumOnly, async (req, res) => {
  const { id } = req.params;
  try {
    const d4doc = await dbGet('SELECT uuid_doc FROM d4sign_docs WHERE holerite_id=?', [id]);
    if (!d4doc?.uuid_doc) return res.status(404).json({ error: 'Envelope D4Sign não encontrado' });

    await d4fetch(`/documents/${d4doc.uuid_doc}/cancel`, 'POST',
      { comment: req.body.motivo || 'Cancelado pelo administrador' });

    await dbRun(`UPDATE d4sign_docs SET status='cancelado' WHERE holerite_id=?`, [id]);
    await dbRun(`UPDATE holerites SET status='novo' WHERE id=?`, [id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── 5. Download do PDF assinado via D4Sign ──────────────────────────────────
// GET /api/holerites/:id/d4sign/download
// Gera a URL temporária de download e faz proxy para o cliente
app.get('/api/holerites/:id/d4sign/download', auth, async (req, res) => {
  const { id } = req.params;
  try {
    const [d4doc, hol] = await Promise.all([
      dbGet('SELECT * FROM d4sign_docs WHERE holerite_id=?', [id]),
      dbGet('SELECT user_id, month_year FROM holerites WHERE id=?', [id])
    ]);
    if (!d4doc?.uuid_doc) return res.status(404).json({ error: 'Envelope D4Sign não encontrado' });
    if (req.user.role !== 'admin' && hol?.user_id !== req.user.id)
      return res.status(403).json({ error: 'Sem permissão' });

    // POST /documents/{uuid}/download retorna { url, name }
    const dlData = await d4fetch(`/documents/${d4doc.uuid_doc}/download`, 'POST',
      { type: 'pdf', language: 'pt' });

    if (!dlData.url) return res.status(502).json({ error: 'D4Sign não retornou URL de download', detalhes: dlData });

    let nodeFetch;
    try { nodeFetch = fetch; } catch { nodeFetch = require('node-fetch'); }

    const pdfResp = await nodeFetch(dlData.url);
    const fname   = `holerite_assinado_${(hol?.month_year || '').replace(/\//g, '-')}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    pdfResp.body.pipe(res);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── 6. Status do envelope D4Sign (para polling opcional) ────────────────────
// GET /api/holerites/:id/d4sign/status
app.get('/api/holerites/:id/d4sign/status', auth, async (req, res) => {
  const { id } = req.params;
  try {
    const d4doc = await dbGet('SELECT * FROM d4sign_docs WHERE holerite_id=?', [id]);
    if (!d4doc) return res.json({ enviado: false });

    // statusId da D4Sign: 1=processando 2=ag.signatarios 3=ag.assinaturas 4=finalizado 5=arquivado 6=cancelado
    const live    = await d4fetch(`/documents/${d4doc.uuid_doc}`).catch(() => null);
    const idMap   = { '4': 'assinado', '6': 'cancelado', '3': 'aguardando', '2': 'aguardando', '1': 'processando' };
    const novoSt  = idMap[live?.statusId];
    if (novoSt && novoSt !== d4doc.status) {
      await dbRun(`UPDATE d4sign_docs SET status=? WHERE uuid_doc=?`, [novoSt, d4doc.uuid_doc]);
      if (novoSt === 'assinado') {
        await dbRun(`UPDATE holerites SET status='assinado', signed_at=CURRENT_TIMESTAMP WHERE id=?`, [id]);
      }
    }
    res.json({ enviado: true, status: novoSt || d4doc.status, uuid_doc: d4doc.uuid_doc, signed_at: d4doc.signed_at });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Servidor acessível na rede: http://<SEU_IP>:${PORT}`);
});