const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const db = new Database(path.join(__dirname, 'game.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS mails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user TEXT NOT NULL,
    to_user TEXT NOT NULL,
    subject TEXT,
    content TEXT,
    code TEXT,
    is_read INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS saves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    data TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

const adminCheck = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
if (!adminCheck) {
  const adminHash = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)').run('admin', adminHash);
}

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ success: false, message: '用户名和密码不能为空' });
  if (username.length < 2 || username.length > 20) return res.json({ success: false, message: '用户名长度2-20位' });
  if (password.length < 4) return res.json({ success: false, message: '密码至少4位' });
  try {
    const existing = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (existing) return res.json({ success: false, message: '用户名已存在' });
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hash);
    res.json({ success: true, message: '注册成功', username });
  } catch (e) {
    res.json({ success: false, message: '注册失败: ' + e.message });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ success: false, message: '用户名和密码不能为空' });
  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) return res.json({ success: false, message: '用户不存在' });
    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) return res.json({ success: false, message: '密码错误' });
    res.json({ success: true, message: '登录成功', username: user.username, is_admin: user.is_admin === 1 });
  } catch (e) {
    res.json({ success: false, message: '登录失败: ' + e.message });
  }
});

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === 'admin123' || password === 'eggduel2026') {
    return res.json({ success: true, message: '管理员登录成功', is_admin: true });
  }
  res.json({ success: false, message: '管理员密码错误' });
});

app.get('/api/admin/users', (req, res) => {
  try {
    const users = db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC').all();
    res.json({ success: true, users });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/api/mail/send', (req, res) => {
  const { from, to, subject, content, code } = req.body;
  if (!to) return res.json({ success: false, message: '收件人不能为空' });
  try {
    db.prepare('INSERT INTO mails (from_user, to_user, subject, content, code) VALUES (?, ?, ?, ?, ?)')
      .run(from || '系统', to, subject || '', content || '', code || '');
    res.json({ success: true, message: '邮件已发送' });
  } catch (e) {
    res.json({ success: false, message: '发送失败: ' + e.message });
  }
});

app.get('/api/mail/list', (req, res) => {
  const { username } = req.query;
  if (!username) return res.json({ success: false, message: '用户名不能为空' });
  try {
    const mails = db.prepare('SELECT * FROM mails WHERE to_user = ? ORDER BY created_at DESC').all(username);
    const unread = db.prepare('SELECT COUNT(*) as count FROM mails WHERE to_user = ? AND is_read = 0').get(username);
    res.json({ success: true, mails, unread: unread.count });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/api/mail/read', (req, res) => {
  const { id } = req.body;
  try {
    db.prepare('UPDATE mails SET is_read = 1 WHERE id = ?').run(id);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/api/save', (req, res) => {
  const { username, data } = req.body;
  if (!username) return res.json({ success: false, message: '用户名不能为空' });
  try {
    const existing = db.prepare('SELECT * FROM saves WHERE username = ?').get(username);
    if (existing) {
      db.prepare('UPDATE saves SET data = ?, updated_at = CURRENT_TIMESTAMP WHERE username = ?')
        .run(JSON.stringify(data || {}), username);
    } else {
      db.prepare('INSERT INTO saves (username, data) VALUES (?, ?)').run(username, JSON.stringify(data || {}));
    }
    res.json({ success: true, message: '存档已保存' });
  } catch (e) {
    res.json({ success: false, message: '保存失败: ' + e.message });
  }
});

app.get('/api/save', (req, res) => {
  const { username } = req.query;
  if (!username) return res.json({ success: false, message: '用户名不能为空' });
  try {
    const save = db.prepare('SELECT * FROM saves WHERE username = ?').get(username);
    if (save) {
      res.json({ success: true, data: JSON.parse(save.data || '{}') });
    } else {
      res.json({ success: true, data: {} });
    }
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ success: true, message: '服务器运行中', time: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`术式对决服务器已启动: http://localhost:${PORT}`);
});
