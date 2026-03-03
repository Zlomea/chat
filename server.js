const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const path       = require('path');
const fs         = require('fs');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const multer     = require('multer');
const initSqlJs  = require('sql.js');

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'bloom-secret-change-in-prod';
const DB_PATH    = process.env.DB_PATH  || path.join(__dirname, 'bloom.db');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// ─── Uploads dir ──────────────────────────────────────────────────────────────
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ─── Multer (disk storage) ────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS_DIR),
  filename:    (_, file, cb) => cb(null, `${Date.now()}_${Math.random().toString(36).slice(2)}${path.extname(file.originalname)}`),
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ─── SQLite (sql.js — pure JS, no native deps) ────────────────────────────────
let db;

async function initDB() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }

  db.run(`PRAGMA journal_mode = WAL;`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id       TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now') * 1000)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS conversations (
    id         TEXT PRIMARY KEY,
    type       TEXT NOT NULL DEFAULT 'dm',
    name       TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now') * 1000)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS members (
    conv_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    PRIMARY KEY (conv_id, user_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id         TEXT PRIMARY KEY,
    conv_id    TEXT NOT NULL,
    sender_id  TEXT NOT NULL,
    type       TEXT NOT NULL DEFAULT 'text',
    text       TEXT,
    url        TEXT,
    deleted    INTEGER DEFAULT 0,
    edited     INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now') * 1000)
  )`);

  // Persist to disk every 30 s
  setInterval(saveDB, 30_000);
  console.log('✅ DB ready:', DB_PATH);
}

function saveDB() {
  try {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  } catch (e) {
    console.error('DB save error:', e.message);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function uid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }

function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) { const r = stmt.getAsObject(); stmt.free(); return r; }
  stmt.free(); return null;
}

function dbAll(sql, params = []) {
  const rows = [];
  const stmt = db.prepare(sql);
  stmt.bind(params);
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function dbRun(sql, params = []) {
  db.run(sql, params);
  saveDB();  // persist immediately on writes
}

function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(t, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

function verifySocket(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

// ─── Express + Socket.IO ──────────────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  // Increase ping timeout for Railway's proxy
  pingTimeout:  60000,
  pingInterval: 25000,
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));

// ─── Auth routes ──────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { name, username, password } = req.body || {};
  if (!name || !username || !password) return res.status(400).json({ error: 'Missing fields' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
  const clean = username.toLowerCase().replace(/[^a-z0-9_]/g, '');
  if (dbGet('SELECT id FROM users WHERE username = ?', [clean]))
    return res.status(400).json({ error: 'Username taken' });
  const hash = await bcrypt.hash(password, 10);
  const id = uid();
  dbRun('INSERT INTO users (id,name,username,password) VALUES (?,?,?,?)', [id, name, clean, hash]);
  const token = jwt.sign({ id, name, username: clean }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id, name, username: clean } });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  const user = dbGet('SELECT * FROM users WHERE username = ?', [username.toLowerCase()]);
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, name: user.name, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, name: user.name, username: user.username } });
});

// ─── User routes ──────────────────────────────────────────────────────────────
app.get('/api/users/search', authMiddleware, (req, res) => {
  const q = (req.query.q || '').trim();
  if (q.length < 2) return res.json([]);
  const rows = dbAll(
    `SELECT id, name, username FROM users
     WHERE (name LIKE ? OR username LIKE ?) AND id != ?
     LIMIT 20`,
    [`%${q}%`, `%${q}%`, req.user.id]
  );
  res.json(rows);
});

app.put('/api/users/profile', authMiddleware, async (req, res) => {
  const { name, username } = req.body || {};
  if (!name || !username) return res.status(400).json({ error: 'Missing fields' });
  const clean = username.toLowerCase().replace(/[^a-z0-9_]/g, '');
  const conflict = dbGet('SELECT id FROM users WHERE username = ? AND id != ?', [clean, req.user.id]);
  if (conflict) return res.status(400).json({ error: 'Username taken' });
  dbRun('UPDATE users SET name = ?, username = ? WHERE id = ?', [name, clean, req.user.id]);
  res.json({ ok: true });
});

// ─── Conversation routes ───────────────────────────────────────────────────────
app.get('/api/conversations', authMiddleware, (req, res) => {
  const convs = dbAll(
    `SELECT c.id, c.type, c.name, c.created_at,
            MAX(m.created_at) as last_message_at,
            (SELECT m2.text FROM messages m2 WHERE m2.conv_id = c.id AND m2.deleted = 0 ORDER BY m2.created_at DESC LIMIT 1) as last_message
     FROM conversations c
     JOIN members mb ON mb.conv_id = c.id AND mb.user_id = ?
     LEFT JOIN messages m ON m.conv_id = c.id
     GROUP BY c.id
     ORDER BY last_message_at DESC NULLS LAST`,
    [req.user.id]
  );

  const result = convs.map(c => {
    const members = dbAll('SELECT user_id FROM members WHERE conv_id = ?', [c.id]).map(r => r.user_id);
    let other_name = null;
    if (c.type === 'dm') {
      const otherId = members.find(m => m !== req.user.id);
      const other = otherId ? dbGet('SELECT name FROM users WHERE id = ?', [otherId]) : null;
      other_name = other?.name || null;
    }
    return { ...c, members, other_name };
  });

  res.json(result);
});

app.post('/api/conversations/dm', authMiddleware, (req, res) => {
  const { targetUserId } = req.body || {};
  if (!targetUserId) return res.status(400).json({ error: 'Missing targetUserId' });

  // Check existing DM
  const existing = dbGet(
    `SELECT c.id FROM conversations c
     JOIN members m1 ON m1.conv_id = c.id AND m1.user_id = ?
     JOIN members m2 ON m2.conv_id = c.id AND m2.user_id = ?
     WHERE c.type = 'dm'`,
    [req.user.id, targetUserId]
  );
  if (existing) return res.json({ id: existing.id });

  const id = uid();
  dbRun('INSERT INTO conversations (id, type) VALUES (?, ?)', [id, 'dm']);
  dbRun('INSERT INTO members (conv_id, user_id) VALUES (?, ?)', [id, req.user.id]);
  dbRun('INSERT INTO members (conv_id, user_id) VALUES (?, ?)', [id, targetUserId]);
  res.json({ id });
});

app.post('/api/conversations/group', authMiddleware, (req, res) => {
  const { name, memberIds } = req.body || {};
  if (!name || !memberIds?.length) return res.status(400).json({ error: 'Missing fields' });

  const id = uid();
  dbRun('INSERT INTO conversations (id, type, name) VALUES (?, ?, ?)', [id, 'group', name]);
  const allMembers = [req.user.id, ...memberIds.filter(m => m !== req.user.id)];
  for (const uid_ of allMembers)
    dbRun('INSERT OR IGNORE INTO members (conv_id, user_id) VALUES (?, ?)', [id, uid_]);
  res.json({ id });
});

// ─── Message routes ────────────────────────────────────────────────────────────
app.get('/api/messages/:convId', authMiddleware, (req, res) => {
  const member = dbGet('SELECT 1 FROM members WHERE conv_id = ? AND user_id = ?', [req.params.convId, req.user.id]);
  if (!member) return res.status(403).json({ error: 'Not a member' });

  const msgs = dbAll(
    `SELECT m.*, u.name as sender_name
     FROM messages m JOIN users u ON u.id = m.sender_id
     WHERE m.conv_id = ?
     ORDER BY m.created_at ASC
     LIMIT 200`,
    [req.params.convId]
  );
  res.json(msgs.map(m => ({ ...m, deleted: !!m.deleted, edited: !!m.edited })));
});

app.put('/api/messages/:id', authMiddleware, (req, res) => {
  const { text } = req.body || {};
  if (!text) return res.status(400).json({ error: 'Missing text' });
  const msg = dbGet('SELECT * FROM messages WHERE id = ? AND sender_id = ?', [req.params.id, req.user.id]);
  if (!msg) return res.status(404).json({ error: 'Not found' });
  dbRun('UPDATE messages SET text = ?, edited = 1 WHERE id = ?', [text, req.params.id]);
  const updated = { ...msg, text, edited: true };
  io.to(msg.conv_id).emit('message:updated', updated);
  res.json({ ok: true });
});

app.delete('/api/messages/:id', authMiddleware, (req, res) => {
  const msg = dbGet('SELECT * FROM messages WHERE id = ? AND sender_id = ?', [req.params.id, req.user.id]);
  if (!msg) return res.status(404).json({ error: 'Not found' });
  dbRun('UPDATE messages SET deleted = 1, text = NULL, url = NULL WHERE id = ?', [req.params.id]);
  io.to(msg.conv_id).emit('message:updated', { ...msg, deleted: true, text: null });
  res.json({ ok: true });
});

// ─── File Upload ──────────────────────────────────────────────────────────────
app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: `/uploads/${req.file.filename}` });
});

// ─── Socket.IO ────────────────────────────────────────────────────────────────
const onlineUsers = new Map(); // uid → Set of socket ids

io.use((socket, next) => {
  const user = verifySocket(socket.handshake.auth?.token);
  if (!user) return next(new Error('Unauthorized'));
  socket.user = user;
  next();
});

io.on('connection', (socket) => {
  const uid = socket.user.id;

  // Track online
  if (!onlineUsers.has(uid)) onlineUsers.set(uid, new Set());
  onlineUsers.get(uid).add(socket.id);
  io.emit('user:online', { uid, online: true });

  // Auto-join all conv rooms
  const convs = dbAll('SELECT conv_id FROM members WHERE user_id = ?', [uid]);
  for (const { conv_id } of convs) socket.join(conv_id);

  socket.on('join:conv', (convId) => {
    const member = dbGet('SELECT 1 FROM members WHERE conv_id = ? AND user_id = ?', [convId, uid]);
    if (member) socket.join(convId);
  });

  socket.on('message:send', (data) => {
    const { convId, text, type, url } = data || {};
    if (!convId) return;

    const member = dbGet('SELECT 1 FROM members WHERE conv_id = ? AND user_id = ?', [convId, uid]);
    if (!member) return;

    const sender = dbGet('SELECT name FROM users WHERE id = ?', [uid]);
    const msgId  = uid() + uid();

    if (type === 'text') {
      if (!text?.trim()) return;
      dbRun('INSERT INTO messages (id,conv_id,sender_id,type,text) VALUES (?,?,?,?,?)',
        [msgId, convId, uid, 'text', text.trim()]);
    } else if ((type === 'image' || type === 'video') && url) {
      dbRun('INSERT INTO messages (id,conv_id,sender_id,type,url) VALUES (?,?,?,?,?)',
        [msgId, convId, uid, type, url]);
    } else return;

    const msg = {
      id: msgId, conv_id: convId, sender_id: uid,
      sender_name: sender?.name || 'Unknown',
      type, text: type === 'text' ? text.trim() : null,
      url: url || null, deleted: false, edited: false,
      created_at: Date.now(),
    };
    io.to(convId).emit('message:new', msg);
  });

  socket.on('typing:start', ({ convId }) => {
    if (!convId) return;
    socket.to(convId).emit('typing:start', { uid, name: socket.user.name, convId });
  });

  socket.on('typing:stop', ({ convId }) => {
    if (!convId) return;
    socket.to(convId).emit('typing:stop', { uid, convId });
  });

  socket.on('disconnect', () => {
    const set = onlineUsers.get(uid);
    if (set) {
      set.delete(socket.id);
      if (!set.size) {
        onlineUsers.delete(uid);
        io.emit('user:online', { uid, online: false });
      }
    }
  });
});

// ─── Health check (Railway uses this) ────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true }));

// ─── SPA fallback ─────────────────────────────────────────────────────────────
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ─── Start ────────────────────────────────────────────────────────────────────
initDB().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`🌸 Ostagarm running on port ${PORT}`);
  });
}).catch(err => {
  console.error('Failed to start:', err);
  process.exit(1);
});