const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  // ===== TABELAS BASE =====
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cpf TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    birth_date TEXT,
    role TEXT DEFAULT 'user',
    empresa_id INTEGER DEFAULT NULL,
    admin_type TEXT DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS holerites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    month_year TEXT NOT NULL,
    filename TEXT, original_name TEXT,
    status TEXT DEFAULT 'novo',
    deadline TEXT,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    signed_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL, message TEXT NOT NULL,
    type TEXT DEFAULT 'geral', user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS alert_reads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
    read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL, user_id INTEGER, details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // ===== TABELAS DO SISTEMA =====
  db.run(`CREATE TABLE IF NOT EXISTS empresas (
    id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL,
    cnpj TEXT UNIQUE, status TEXT DEFAULT 'ativo', observacao TEXT,
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
    usuario_id INTEGER NOT NULL, empresa_id INTEGER,
    valor REAL NOT NULL, data_pagamento TEXT NOT NULL,
    arquivo TEXT, original_name TEXT,
    status TEXT DEFAULT 'nao_pago', observacao TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES users(id),
    FOREIGN KEY (empresa_id) REFERENCES empresas(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS ocorrencias (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL, tipo TEXT NOT NULL, data TEXT NOT NULL,
    obs TEXT, status TEXT DEFAULT 'pendente',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS ferias (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    data_inicio TEXT NOT NULL, data_fim TEXT NOT NULL,
    observacao TEXT, status TEXT DEFAULT 'pendente',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS informes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ano TEXT NOT NULL, user_id INTEGER,
    filename TEXT, original_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS documentos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    titulo TEXT NOT NULL, categoria TEXT, user_id INTEGER, obs TEXT,
    filename TEXT, original_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // ===== TABELAS COMPRAS / ESTOQUE =====
  db.run(`CREATE TABLE IF NOT EXISTS produtos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    descricao TEXT,
    categoria TEXT,
    unidade TEXT DEFAULT 'un',
    estoque_atual REAL DEFAULT 0,
    estoque_minimo REAL DEFAULT 0,
    preco_unitario REAL DEFAULT 0,
    ativo INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS solicitacoes_compra (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    solicitante_id INTEGER NOT NULL,
    titulo TEXT NOT NULL,
    prioridade TEXT DEFAULT 'normal',
    status TEXT DEFAULT 'pendente',
    observacao TEXT,
    aprovado_por INTEGER,
    aprovado_em DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (solicitante_id) REFERENCES users(id),
    FOREIGN KEY (aprovado_por) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS solicitacao_itens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    solicitacao_id INTEGER NOT NULL,
    produto_id INTEGER,
    descricao TEXT NOT NULL,
    quantidade REAL NOT NULL,
    unidade TEXT DEFAULT 'un',
    preco_estimado REAL DEFAULT 0,
    FOREIGN KEY (solicitacao_id) REFERENCES solicitacoes_compra(id),
    FOREIGN KEY (produto_id) REFERENCES produtos(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS movimentacoes_estoque (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    produto_id INTEGER NOT NULL,
    tipo TEXT NOT NULL,
    quantidade REAL NOT NULL,
    solicitacao_id INTEGER,
    usuario_id INTEGER,
    obs TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (produto_id) REFERENCES produtos(id),
    FOREIGN KEY (solicitacao_id) REFERENCES solicitacoes_compra(id),
    FOREIGN KEY (usuario_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS patrimonio (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    equipamento       TEXT NOT NULL,
    serial_number     TEXT,
    mac_address       TEXT,
    numero_patrimonio TEXT,
    descricao         TEXT,
    categoria         TEXT,
    situacao          TEXT DEFAULT 'estoque',
    usuario_id        INTEGER,
    data_emprestimo   TEXT,
    obs_emprestimo    TEXT,
    ativo             INTEGER DEFAULT 1,
    created_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES users(id)
  )`);

  // ===== MIGRATIONS =====
  // ── Tabela D4Sign: rastreia envelopes de assinatura ──────────────────────
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

  // ── Assinatura digital local (código por e-mail + RSA + QR code) ─────────
  db.run(`CREATE TABLE IF NOT EXISTS local_signature_codes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    holerite_id   INTEGER NOT NULL,
    token         TEXT NOT NULL UNIQUE,
    code          TEXT NOT NULL,
    signer_name   TEXT NOT NULL,
    signer_email  TEXT NOT NULL,
    attempts      INTEGER DEFAULT 0,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (holerite_id) REFERENCES holerites(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS local_signatures (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    holerite_id         INTEGER NOT NULL UNIQUE,
    signer_name         TEXT NOT NULL,
    signer_email        TEXT NOT NULL,
    digest_sha256       TEXT NOT NULL,
    signature           TEXT NOT NULL,
    algorithm           TEXT DEFAULT 'RSA-PSS-SHA256',
    signed_filename     TEXT,
    verification_method TEXT DEFAULT 'email_code',
    selfie_filename      TEXT,
    signed_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (holerite_id) REFERENCES holerites(id)
  )`);

  // ── Reconhecimento facial: rosto de referência de cada usuário ───────────
  db.run(`CREATE TABLE IF NOT EXISTS face_references (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL UNIQUE,
    descriptor      TEXT NOT NULL,
    photo_filename  TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  // ── Solicitações de assinatura pendentes de confirmação facial ───────────
  db.run(`CREATE TABLE IF NOT EXISTS local_signature_facial_requests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    holerite_id   INTEGER NOT NULL,
    token         TEXT NOT NULL UNIQUE,
    signer_name   TEXT NOT NULL,
    attempts      INTEGER DEFAULT 0,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (holerite_id) REFERENCES holerites(id)
  )`);

  // ── Configurações white-label e SMTP ─────────────────────────────────────
  db.run(`CREATE TABLE IF NOT EXISTS configuracoes (
    chave TEXT PRIMARY KEY,
    valor TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Inserir valores padrão (apenas se não existirem)
  const configPadroes = [
    ['empresa_nome',     'Minha Empresa'],
    ['empresa_logo_url', ''],
    ['sistema_nome',     'Portal Corporativo'],
    ['sistema_badge',    'ERP'],
    ['cor_primaria',     '#0057FF'],
    ['cor_sidebar',      '#0A1628'],
    ['cor_acento',       '#00C2FF'],
    ['smtp_host',        ''],
    ['smtp_port',        '587'],
    ['smtp_user',        ''],
    ['smtp_pass',        ''],
    ['smtp_from',        ''],
    ['smtp_from_name',   ''],
    ['integracao_d4sign_token',     ''],
    ['integracao_d4sign_crypt',     ''],
    ['integracao_d4sign_safe',      ''],
    ['integracao_webhook_url',      ''],
    ['integracao_webhook_secret',   ''],
  ];
  configPadroes.forEach(([chave, valor]) => {
    db.run(`INSERT OR IGNORE INTO configuracoes (chave, valor) VALUES (?, ?)`, [chave, valor]);
  });

  const migrations = [
    `ALTER TABLE users ADD COLUMN birth_date TEXT`,
    `ALTER TABLE holerites ADD COLUMN deadline TEXT`,
    `ALTER TABLE holerites ADD COLUMN uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP`,
    `ALTER TABLE holerites ADD COLUMN signed_at DATETIME`,
    `ALTER TABLE users ADD COLUMN empresa_id INTEGER DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN admin_type TEXT DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN modulos TEXT DEFAULT NULL`,
    `ALTER TABLE local_signatures ADD COLUMN verification_method TEXT DEFAULT 'email_code'`,
    `ALTER TABLE local_signatures ADD COLUMN selfie_filename TEXT`,
    `ALTER TABLE users ADD COLUMN mfa_secret TEXT DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0`,
    `ALTER TABLE pontos_registros ADD COLUMN nsr INTEGER`,
    `ALTER TABLE pontos_registros ADD COLUMN hash_registro TEXT`,
    `ALTER TABLE pontos_registros ADD COLUMN hash_anterior TEXT`,
    `ALTER TABLE pontos_registros ADD COLUMN cnpj_empregador TEXT`,
    `ALTER TABLE pontos_registros ADD COLUMN ajuste_id INTEGER`,
    // Campos exigidos pelo leiaute oficial do AFD (registro tipo "7" — REP-P):
    `ALTER TABLE pontos_registros ADD COLUMN data_hora_gravacao TEXT`,  // campo nº5: distinto da data/hora da marcação
    `ALTER TABLE pontos_registros ADD COLUMN coletor TEXT`,             // campo nº6: '02'=browser, '04'=dispositivo (totem)
    `ALTER TABLE pontos_registros ADD COLUMN online TEXT DEFAULT '0'`,  // campo nº7: '0'=online, '1'=offline
    // Nº de registro do software no INPI (art. 89 §4º) e CNPJ do fabricante/
    // desenvolvedor (campo nº7 e nº13 do registro tipo "1" do AFD) — ainda
    // pendentes de preenchimento real, ver /api/ponto/conformidade.
    `INSERT OR IGNORE INTO configuracoes (chave, valor) VALUES ('ponto_numero_registro_inpi', '')`,
    `INSERT OR IGNORE INTO configuracoes (chave, valor) VALUES ('ponto_cnpj_desenvolvedor', '')`,
    `ALTER TABLE ajustes_ponto ADD COLUMN hora TEXT`
  ];
  migrations.forEach(sql => db.run(sql, () => {}));

  // ===== ADMIN PADRÃO (global) =====
  const adminPassword = bcrypt.hashSync('admin123', 10);
  db.run(
    `INSERT OR IGNORE INTO users (id, cpf, name, password, role, admin_type)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [1, 'admin', 'Administrador Mestre', adminPassword, 'admin', 'global'],
    (err) => {
      if (err) console.log('Erro ao criar admin padrão:', err.message);
      else {
        db.run(`UPDATE users SET admin_type = 'global' WHERE id = 1 AND role = 'admin'`);
        console.log('✅ Admin padrão verificado (global)');
      }
    }
  );

  // ===== USUÁRIO RH (acesso geral, exceto financeiro) =====
  const rhPassword = bcrypt.hashSync('rh123', 10);
  db.run(
    `INSERT OR IGNORE INTO users (id, cpf, name, password, role, admin_type)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [2, 'rh', 'RH', rhPassword, 'admin', 'rh'],
    (err) => {
      if (err) console.log('Erro ao criar usuário RH:', err.message);
      else {
        db.run(`UPDATE users SET admin_type = 'rh' WHERE id = 2`);
        console.log('✅ Usuário RH verificado');
      }
    }
  );

  // ===== USUÁRIO FINANCEIRO (acesso somente ao módulo financeiro) =====
  const finPassword = bcrypt.hashSync('fin123', 10);
  db.run(
    `INSERT OR IGNORE INTO users (id, cpf, name, password, role, admin_type)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [3, 'financeiro', 'Financeiro', finPassword, 'admin', 'financeiro'],
    (err) => {
      if (err) console.log('Erro ao criar usuário Financeiro:', err.message);
      else {
        db.run(`UPDATE users SET admin_type = 'financeiro' WHERE id = 3`);
        // Garante permissão de financeiro na tabela permissoes_admin
        db.run(
          `INSERT OR IGNORE INTO permissoes_admin (usuario_id, financeiro) VALUES (3, 1)`,
          () => db.run(`UPDATE permissoes_admin SET financeiro = 1 WHERE usuario_id = 3`)
        );
        console.log('✅ Usuário Financeiro verificado');
      }
    }
  );
});


  // ===== AJUSTES DE PONTO (solicitações do colaborador) =====
  db.run(`CREATE TABLE IF NOT EXISTS ajustes_ponto (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    tipo TEXT NOT NULL,
    data TEXT NOT NULL,
    hora TEXT,
    obs TEXT,
    resposta_rh TEXT,
    status TEXT DEFAULT 'pendente',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  // ===== CONTROLE INTERNO (canal anônimo de compliance) =====
  db.run(`CREATE TABLE IF NOT EXISTS controle_interno (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    categoria TEXT NOT NULL,
    mensagem TEXT NOT NULL,
    status TEXT DEFAULT 'novo',
    resposta_admin TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // ===== PONTO ELETRÔNICO (batidas de ponto) =====
  // Registrado pelo próprio colaborador (origem='portal') ou pelo totem
  // de CPF na recepção (origem='totem', operado por uma conta role='totem').
  db.run(`CREATE TABLE IF NOT EXISTS pontos_registros (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    tipo          TEXT NOT NULL,             -- 'entrada' | 'saida'
    data          TEXT NOT NULL,             -- YYYY-MM-DD
    hora          TEXT NOT NULL,             -- HH:MM:SS
    latitude      REAL,
    longitude     REAL,
    precisao      REAL,
    origem        TEXT DEFAULT 'portal',     -- 'portal' | 'totem'
    registrado_por INTEGER,                  -- id da conta totem que operou (quando origem='totem')
    nsr           INTEGER,                   -- Número Sequencial de Registro (Portaria MTP 671/2021)
    hash_registro TEXT,                      -- hash SHA-256 do registro, encadeado ao anterior (garante integridade/imutabilidade)
    hash_anterior TEXT,                      -- hash do registro anterior na cadeia (NSR - 1)
    cnpj_empregador TEXT,                    -- CNPJ da empresa do colaborador no momento da batida
    ajuste_id     INTEGER,                   -- vincula ao pedido de ajuste que originou este registro corretivo (RH aprovou)
    data_hora_gravacao TEXT,                 -- campo nº5 do registro tipo "7" do AFD (distinto da data/hora da marcação)
    coletor       TEXT,                      -- campo nº6 do AFD: '02'=browser, '04'=dispositivo (totem)
    online        TEXT DEFAULT '0',          -- campo nº7 do AFD: '0'=online, '1'=offline
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

module.exports = db;