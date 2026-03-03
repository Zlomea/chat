const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'bloom_secret_key_2024';
const DB_PATH = path.join(__dirname, 'bloom.db');

// ── Uploads folder ──────────────────────────────────────
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage_multer = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => cb(null, Date.now() + '_' + Math.random().toString(36).slice(2) + path.extname(file.originalname))
});
const upload = multer({ storage: storage_multer, limits: { fileSize: 50 * 1024 * 1024 } });

// ── sql.js DB ────────────────────────────────────────────
let db;

async function initDB() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS conversations (
      id TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      name TEXT,
      created_by TEXT,
      created_at INTEGER DEFAULT 0,
      last_message TEXT DEFAULT '',
      last_message_at INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS conversation_members (
      conv_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      PRIMARY KEY (conv_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      conv_id TEXT NOT NULL,
      sender_id TEXT NOT NULL,
      sender_name TEXT NOT NULL,
      type TEXT DEFAULT 'text',
      text TEXT,
      url TEXT,
      deleted INTEGER DEFAULT 0,
      edited INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT 0,
      edited_at INTEGER
    );
  `);

  saveDB();
  console.log('Database ready');
}

function saveDB() {
  try {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  } catch (e) {
    console.error('DB save error:', e.message);
  }
}

function dbAll(sql, params = []) {
  try {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  } catch (e) {
    console.error('dbAll error:', e.message);
    return [];
  }
}

function dbGet(sql, params = []) {
  return dbAll(sql, params)[0] || null;
}

function dbRun(sql, params = []) {
  try {
    db.run(sql, params);
    saveDB();
  } catch (e) {
    console.error('dbRun error:', e.message);
  }
}

function nanoid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

// ── Middleware ───────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadDir));

function auth(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── Auth ─────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { name, username, password } = req.body || {};
  if (!name || !username || !password) return res.status(400).json({ error: 'All fields required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username must be 3+ characters' });
  if (dbGet('SELECT id FROM users WHERE username = ?', [username.toLowerCase()]))
    return res.status(400).json({ error: 'Username already taken' });
  const hash = await bcrypt.hash(password, 10);
  const id = nanoid();
  dbRun('INSERT INTO users (id,name,username,password,created_at) VALUES (?,?,?,?,?)',
    [id, name, username.toLowerCase(), hash, Date.now()]);
  const token = jwt.sign({ uid: id, username: username.toLowerCase(), name }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id, name, username: username.toLowerCase() } });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = dbGet('SELECT * FROM users WHERE username = ?', [(username || '').toLowerCase()]);
  if (!user) return res.status(400).json({ error: 'User not found' });
  if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ error: 'Wrong password' });
  const token = jwt.sign({ uid: user.id, username: user.username, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, name: user.name, username: user.username } });
});

// ── Users ─────────────────────────────────────────────────
app.get('/api/users/search', auth, (req, res) => {
  const q = '%' + (req.query.q || '') + '%';
  res.json(dbAll('SELECT id,name,username FROM users WHERE (username LIKE ? OR name LIKE ?) AND id != ? LIMIT 10', [q, q, req.user.uid]));
});

app.put('/api/users/profile', auth, async (req, res) => {
  const { name, username } = req.body || {};
  if (!name || !username) return res.status(400).json({ error: 'Fields required' });
  if (dbGet('SELECT id FROM users WHERE username = ? AND id != ?', [username.toLowerCase(), req.user.uid]))
    return res.status(400).json({ error: 'Username taken' });
  dbRun('UPDATE users SET name=?,username=? WHERE id=?', [name, username.toLowerCase(), req.user.uid]);
  res.json({ ok: true });
});

// ── Conversations ─────────────────────────────────────────
app.get('/api/conversations', auth, (req, res) => {
  const memberships = dbAll('SELECT conv_id FROM conversation_members WHERE user_id = ?', [req.user.uid]);
  const result = [];
  for (const { conv_id } of memberships) {
    const conv = dbGet('SELECT * FROM conversations WHERE id = ?', [conv_id]);
    if (!conv) continue;
    conv.members = dbAll('SELECT user_id FROM conversation_members WHERE conv_id = ?', [conv_id]).map(m => m.user_id);
    if (conv.type === 'dm') {
      const otherId = conv.members.find(m => m !== req.user.uid);
      if (otherId) {
        const other = dbGet('SELECT name FROM users WHERE id = ?', [otherId]);
        if (other) conv.other_name = other.name;
      }
    }
    result.push(conv);
  }
  result.sort((a, b) => (b.last_message_at || 0) - (a.last_message_at || 0));
  res.json(result);
});

app.post('/api/conversations/dm', auth, (req, res) => {
  const { targetUserId } = req.body || {};
  const myConvs = dbAll('SELECT conv_id FROM conversation_members WHERE user_id = ?', [req.user.uid]);
  for (const { conv_id } of myConvs) {
    const conv = dbGet('SELECT id FROM conversations WHERE id = ? AND type = ?', [conv_id, 'dm']);
    if (conv && dbGet('SELECT 1 FROM conversation_members WHERE conv_id = ? AND user_id = ?', [conv_id, targetUserId]))
      return res.json({ id: conv_id, existing: true });
  }
  const id = nanoid();
  dbRun('INSERT INTO conversations (id,type,created_by,created_at,last_message_at) VALUES (?,?,?,?,?)',
    [id, 'dm', req.user.uid, Date.now(), Date.now()]);
  dbRun('INSERT INTO conversation_members (conv_id,user_id) VALUES (?,?)', [id, req.user.uid]);
  dbRun('INSERT INTO conversation_members (conv_id,user_id) VALUES (?,?)', [id, targetUserId]);
  res.json({ id, existing: false });
});

app.post('/api/conversations/group', auth, (req, res) => {
  const { name, memberIds } = req.body || {};
  if (!name || !memberIds?.length) return res.status(400).json({ error: 'Name and members required' });
  const id = nanoid();
  dbRun('INSERT INTO conversations (id,type,name,created_by,created_at,last_message_at) VALUES (?,?,?,?,?,?)',
    [id, 'group', name, req.user.uid, Date.now(), Date.now()]);
  for (const uid of [req.user.uid, ...memberIds.filter(m => m !== req.user.uid)]) {
    dbRun('INSERT OR IGNORE INTO conversation_members (conv_id,user_id) VALUES (?,?)', [id, uid]);
  }
  res.json({ id });
});

// ── Messages ──────────────────────────────────────────────
app.get('/api/messages/:convId', auth, (req, res) => {
  if (!dbGet('SELECT 1 FROM conversation_members WHERE conv_id=? AND user_id=?', [req.params.convId, req.user.uid]))
    return res.status(403).json({ error: 'Not a member' });
  res.json(dbAll('SELECT * FROM messages WHERE conv_id=? ORDER BY created_at ASC', [req.params.convId]));
});

app.put('/api/messages/:msgId', auth, (req, res) => {
  const msg = dbGet('SELECT * FROM messages WHERE id=? AND sender_id=?', [req.params.msgId, req.user.uid]);
  if (!msg) return res.status(403).json({ error: 'Not your message' });
  dbRun('UPDATE messages SET text=?,edited=1,edited_at=? WHERE id=?', [req.body.text, Date.now(), req.params.msgId]);
  io.to(msg.conv_id).emit('message:updated', dbGet('SELECT * FROM messages WHERE id=?', [req.params.msgId]));
  res.json({ ok: true });
});

app.delete('/api/messages/:msgId', auth, (req, res) => {
  const msg = dbGet('SELECT * FROM messages WHERE id=? AND sender_id=?', [req.params.msgId, req.user.uid]);
  if (!msg) return res.status(403).json({ error: 'Not your message' });
  dbRun('UPDATE messages SET deleted=1,text=NULL,url=NULL WHERE id=?', [req.params.msgId]);
  io.to(msg.conv_id).emit('message:updated', dbGet('SELECT * FROM messages WHERE id=?', [req.params.msgId]));
  res.json({ ok: true });
});

// ── Upload ────────────────────────────────────────────────
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: '/uploads/' + req.file.filename });
});

// ── Socket.io ─────────────────────────────────────────────
const onlineUsers = new Map();

io.use((socket, next) => {
  try { socket.user = jwt.verify(socket.handshake.auth.token, JWT_SECRET); next(); }
  catch { next(new Error('Unauthorized')); }
});

io.on('connection', (socket) => {
  const uid = socket.user.uid;
  onlineUsers.set(uid, socket.id);
  io.emit('user:online', { uid, online: true });

  // Auto-join all rooms
  dbAll('SELECT conv_id FROM conversation_members WHERE user_id=?', [uid])
    .forEach(({ conv_id }) => socket.join(conv_id));

  socket.on('join:conv', (convId) => {
    if (dbGet('SELECT 1 FROM conversation_members WHERE conv_id=? AND user_id=?', [convId, uid]))
      socket.join(convId);
  });

  socket.on('message:send', (data, cb) => {
    const { convId, text, type, url } = data;
    if (!dbGet('SELECT 1 FROM conversation_members WHERE conv_id=? AND user_id=?', [convId, uid])) return;
    const id = nanoid();
    const now = Date.now();
    const preview = type === 'image' ? '🖼️ Image' : type === 'video' ? '🎥 Video' : (text || '').substring(0, 60);
    dbRun('INSERT INTO messages (id,conv_id,sender_id,sender_name,type,text,url,created_at) VALUES (?,?,?,?,?,?,?,?)',
      [id, convId, uid, socket.user.name, type || 'text', text || null, url || null, now]);
    dbRun('UPDATE conversations SET last_message=?,last_message_at=? WHERE id=?', [preview, now, convId]);
    const msg = dbGet('SELECT * FROM messages WHERE id=?', [id]);
    io.to(convId).emit('message:new', msg);
    if (cb) cb({ ok: true, id });
  });

  socket.on('typing:start', ({ convId }) => socket.to(convId).emit('typing:start', { uid, name: socket.user.name, convId }));
  socket.on('typing:stop',  ({ convId }) => socket.to(convId).emit('typing:stop',  { uid, convId }));

  socket.on('disconnect', () => {
    onlineUsers.delete(uid);
    io.emit('user:online', { uid, online: false });
  });
});

// ── Start ─────────────────────────────────────────────────
initDB().then(() => {
  server.listen(PORT, () => {
    console.log(`\n🌸 Bloom is running!`);
    console.log(`   Open this in your browser: http://localhost:${PORT}\n`);
  });
});
