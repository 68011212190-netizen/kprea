require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const db = require('./db');

const app = express();
const GENRES = ['โรแมนติก', 'ฟีลกู๊ด', 'ดราม่า', 'คอมเมดี้', 'ย้อนยุค', 'แฟนตาซี', 'ระทึกขวัญ', 'แอ็กชัน'];

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 864e5 }
}));

// ---------- Middleware กลาง ----------
app.use((req, res, next) => {
  // โหลดผู้ใช้จาก DB ทุกครั้ง เพื่อให้การเปลี่ยนบทบาท/ลบผู้ใช้มีผลทันที
  if (req.session.user) {
    req.session.user = db.prepare('SELECT id,name,email,role FROM users WHERE id=?').get(req.session.user.id) || null;
  }
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString('hex');
  res.locals.csrf = req.session.csrf;
  res.locals.user = req.session.user;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  res.locals.title = '';
  res.locals.q = '';
  res.locals.GENRES = GENRES;
  res.locals.page = req.path;
  if (req.method === 'POST' && req.body._csrf !== req.session.csrf) {
    return res.status(403).render('error', { message: 'โทเคนความปลอดภัยไม่ถูกต้อง กรุณาโหลดหน้าใหม่แล้วลองอีกครั้ง' });
  }
  next();
});

const flash = (req, type, msg) => { req.session.flash = { type, msg }; };
const requireLogin = (req, res, next) => {
  if (!req.session.user) { flash(req, 'error', 'กรุณาเข้าสู่ระบบก่อน'); return res.redirect('/login'); }
  next();
};
const requireAdmin = (req, res, next) => {
  if (!req.session.user) { flash(req, 'error', 'กรุณาเข้าสู่ระบบก่อน'); return res.redirect('/login'); }
  if (req.session.user.role !== 'admin') return res.status(403).render('error', { message: 'หน้านี้สำหรับผู้ดูแลระบบเท่านั้น' });
  next();
};

// ---------- หน้าแรก / ค้นหา ----------
const LIST_SQL = `SELECT s.*, u.name AS owner,
  (SELECT COUNT(*) FROM comments c WHERE c.series_id = s.id) AS comment_count
  FROM series s JOIN users u ON u.id = s.user_id`;

app.get('/', (req, res) => {
  const q = (req.query.q || '').trim();
  const genre = GENRES.includes(req.query.genre) ? req.query.genre : '';
  const rows = db.prepare(`${LIST_SQL}
    WHERE (? = '' OR s.title LIKE '%' || ? || '%') AND (? = '' OR s.genre = ?)
    ORDER BY s.id DESC`).all(q, q, genre, genre);
  res.render('index', { title: 'หน้าแรก', list: rows, q, genre });
});

// ---------- สมัคร / เข้าสู่ระบบ ----------
app.get('/register', (req, res) => res.render('register', { title: 'สมัครสมาชิก', errors: [], f: {} }));
app.post('/register', (req, res) => {
  const f = { name: (req.body.name || '').trim(), email: (req.body.email || '').trim().toLowerCase() };
  const pw = req.body.password || '';
  const errors = [];
  if (f.name.length < 2 || f.name.length > 40) errors.push('ชื่อต้องมี 2-40 ตัวอักษร');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(f.email)) errors.push('รูปแบบอีเมลไม่ถูกต้อง');
  if (pw.length < 8) errors.push('รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร');
  if (pw !== req.body.confirm) errors.push('รหัสผ่านทั้งสองช่องไม่ตรงกัน');
  if (!errors.length && db.prepare('SELECT 1 FROM users WHERE email=?').get(f.email)) errors.push('อีเมลนี้ถูกใช้งานแล้ว');
  if (errors.length) return res.status(400).render('register', { title: 'สมัครสมาชิก', errors, f });
  const info = db.prepare("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'user')")
    .run(f.name, f.email, bcrypt.hashSync(pw, 10));
  req.session.regenerate(() => {
    req.session.user = { id: info.lastInsertRowid };
    flash(req, 'ok', 'สมัครสมาชิกสำเร็จ ยินดีต้อนรับ 🌸');
    res.redirect('/');
  });
});

const attempts = new Map(); // กันเดารหัสผ่านแบบง่ายๆ
app.get('/login', (req, res) => res.render('login', { title: 'เข้าสู่ระบบ', errors: [], email: '' }));
app.post('/login', (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const key = req.ip + email;
  const a = attempts.get(key) || { n: 0, t: Date.now() };
  if (Date.now() - a.t > 15 * 60e3) { a.n = 0; a.t = Date.now(); }
  if (a.n >= 8) return res.status(429).render('login', { title: 'เข้าสู่ระบบ', errors: ['ลองผิดหลายครั้งเกินไป กรุณารอ 15 นาที'], email });
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !bcrypt.compareSync(req.body.password || '', u.password_hash)) {
    attempts.set(key, { n: a.n + 1, t: a.t });
    return res.status(401).render('login', { title: 'เข้าสู่ระบบ', errors: ['อีเมลหรือรหัสผ่านไม่ถูกต้อง'], email });
  }
  attempts.delete(key);
  req.session.regenerate(() => {
    req.session.user = { id: u.id };
    flash(req, 'ok', `ยินดีต้อนรับกลับมา ${u.name} 💕`);
    res.redirect(u.role === 'admin' ? '/admin' : '/');
  });
});
app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

// ---------- CRUD ซีรีย์ (มีเจ้าของ) ----------
function parseSeries(b) {
  const s = {
    title: (b.title || '').trim(), genre: (b.genre || '').trim(), year: parseInt(b.year) || '',
    rating: parseInt(b.rating) || 0, image_url: (b.image_url || '').trim(), review: (b.review || '').trim()
  };
  const errors = [];
  if (!s.title || s.title.length > 100) errors.push('ชื่อซีรีย์ต้องมี 1-100 ตัวอักษร');
  if (!GENRES.includes(s.genre)) errors.push('กรุณาเลือกหมวดหมู่');
  if (s.rating < 1 || s.rating > 5) errors.push('คะแนนต้องอยู่ระหว่าง 1-5');
  if (s.year && (s.year < 1990 || s.year > 2100)) errors.push('ปีที่ออกอากาศไม่ถูกต้อง');
  if (s.image_url && !/^https?:\/\//i.test(s.image_url)) errors.push('ลิงก์รูปต้องขึ้นต้นด้วย http:// หรือ https://');
  if (s.review.length < 10 || s.review.length > 2000) errors.push('รีวิวต้องมี 10-2000 ตัวอักษร');
  return { s, errors };
}

app.get('/my', requireLogin, (req, res) => {
  const rows = db.prepare(`${LIST_SQL} WHERE s.user_id=? ORDER BY s.id DESC`).all(req.session.user.id);
  res.render('my', { title: 'ซีรีย์ของฉัน', list: rows });
});

app.get('/series/new', requireLogin, (req, res) =>
  res.render('series_form', { title: 'เพิ่มซีรีย์', s: { rating: 5 }, errors: [], action: '/series', edit: false }));
app.post('/series', requireLogin, (req, res) => {
  const { s, errors } = parseSeries(req.body);
  if (errors.length) return res.status(400).render('series_form', { title: 'เพิ่มซีรีย์', s, errors, action: '/series', edit: false });
  const info = db.prepare('INSERT INTO series (user_id,title,genre,year,rating,image_url,review) VALUES (?,?,?,?,?,?,?)')
    .run(req.session.user.id, s.title, s.genre, s.year || null, s.rating, s.image_url, s.review);
  flash(req, 'ok', 'เพิ่มซีรีย์เรียบร้อย ✨');
  res.redirect('/series/' + info.lastInsertRowid);
});

function getSeries(id) { return db.prepare(`${LIST_SQL} WHERE s.id=?`).get(id); }

app.get('/series/:id', (req, res) => {
  const s = getSeries(req.params.id);
  if (!s) return res.status(404).render('error', { message: 'ไม่พบซีรีย์ที่ต้องการ' });
  const comments = db.prepare(`SELECT c.*, u.name FROM comments c JOIN users u ON u.id=c.user_id
    WHERE c.series_id=? ORDER BY c.id DESC`).all(s.id);
  res.render('series_show', { title: s.title, s, comments, errors: [] });
});

// แก้ไข: เจ้าของเท่านั้น
function ownerOnly(req, res, next) {
  const s = db.prepare('SELECT * FROM series WHERE id=?').get(req.params.id);
  if (!s) return res.status(404).render('error', { message: 'ไม่พบซีรีย์ที่ต้องการ' });
  if (s.user_id !== req.session.user.id) return res.status(403).render('error', { message: 'คุณไม่มีสิทธิ์แก้ไขข้อมูลของผู้อื่น' });
  req.series = s; next();
}
app.get('/series/:id/edit', requireLogin, ownerOnly, (req, res) =>
  res.render('series_form', { title: 'แก้ไขซีรีย์', s: req.series, errors: [], action: `/series/${req.series.id}/edit`, edit: true }));
app.post('/series/:id/edit', requireLogin, ownerOnly, (req, res) => {
  const { s, errors } = parseSeries(req.body);
  const action = `/series/${req.series.id}/edit`;
  if (errors.length) return res.status(400).render('series_form', { title: 'แก้ไขซีรีย์', s, errors, action, edit: true });
  db.prepare('UPDATE series SET title=?,genre=?,year=?,rating=?,image_url=?,review=? WHERE id=?')
    .run(s.title, s.genre, s.year || null, s.rating, s.image_url, s.review, req.series.id);
  flash(req, 'ok', 'บันทึกการแก้ไขแล้ว');
  res.redirect('/series/' + req.series.id);
});

// ลบ: เจ้าของ หรือ admin
app.post('/series/:id/delete', requireLogin, (req, res) => {
  const s = db.prepare('SELECT * FROM series WHERE id=?').get(req.params.id);
  if (!s) return res.status(404).render('error', { message: 'ไม่พบซีรีย์ที่ต้องการ' });
  const u = req.session.user;
  if (s.user_id !== u.id && u.role !== 'admin') return res.status(403).render('error', { message: 'คุณไม่มีสิทธิ์ลบข้อมูลของผู้อื่น' });
  db.prepare('DELETE FROM series WHERE id=?').run(s.id);
  flash(req, 'ok', 'ลบซีรีย์แล้ว');
  res.redirect(req.body.back === 'admin' && u.role === 'admin' ? '/admin/series' : '/my');
});

// ---------- ฟอร์มที่ 2: ความคิดเห็น ----------
app.post('/series/:id/comments', requireLogin, (req, res) => {
  const s = getSeries(req.params.id);
  if (!s) return res.status(404).render('error', { message: 'ไม่พบซีรีย์ที่ต้องการ' });
  const body = (req.body.body || '').trim();
  if (body.length < 2 || body.length > 500) {
    const comments = db.prepare(`SELECT c.*, u.name FROM comments c JOIN users u ON u.id=c.user_id WHERE c.series_id=? ORDER BY c.id DESC`).all(s.id);
    return res.status(400).render('series_show', { title: s.title, s, comments, errors: ['ความคิดเห็นต้องมี 2-500 ตัวอักษร'] });
  }
  db.prepare('INSERT INTO comments (series_id,user_id,body) VALUES (?,?,?)').run(s.id, req.session.user.id, body);
  flash(req, 'ok', 'ส่งความคิดเห็นแล้ว 💬');
  res.redirect('/series/' + s.id);
});
app.post('/comments/:id/delete', requireLogin, (req, res) => {
  const c = db.prepare('SELECT * FROM comments WHERE id=?').get(req.params.id);
  if (!c) return res.status(404).render('error', { message: 'ไม่พบความคิดเห็น' });
  const u = req.session.user;
  if (c.user_id !== u.id && u.role !== 'admin') return res.status(403).render('error', { message: 'คุณไม่มีสิทธิ์ลบความคิดเห็นนี้' });
  db.prepare('DELETE FROM comments WHERE id=?').run(c.id);
  flash(req, 'ok', 'ลบความคิดเห็นแล้ว');
  res.redirect('/series/' + c.series_id);
});

// ---------- ติดต่อเรา (ฟอร์มที่ 3) ----------
app.get('/contact', (req, res) => res.render('contact', { title: 'ติดต่อเรา', errors: [], f: {} }));
app.post('/contact', (req, res) => {
  const u = req.session.user;
  const f = { name: (req.body.name || (u && u.name) || '').trim(), email: (req.body.email || (u && u.email) || '').trim(),
    subject: (req.body.subject || '').trim(), body: (req.body.body || '').trim() };
  const errors = [];
  if (!f.name) errors.push('กรุณากรอกชื่อ');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(f.email)) errors.push('รูปแบบอีเมลไม่ถูกต้อง');
  if (!f.subject || f.subject.length > 100) errors.push('กรุณากรอกหัวข้อ (ไม่เกิน 100 ตัวอักษร)');
  if (f.body.length < 10 || f.body.length > 1000) errors.push('ข้อความต้องมี 10-1000 ตัวอักษร');
  if (errors.length) return res.status(400).render('contact', { title: 'ติดต่อเรา', errors, f });
  db.prepare('INSERT INTO messages (user_id,name,email,subject,body) VALUES (?,?,?,?,?)')
    .run(u ? u.id : null, f.name, f.email, f.subject, f.body);
  flash(req, 'ok', 'ส่งข้อความถึงทีมงานแล้ว ขอบคุณค่ะ 💌');
  res.redirect('/contact');
});

// ---------- ผู้ดูแลระบบ ----------
app.get('/admin', requireAdmin, (req, res) => {
  const c = t => db.prepare(`SELECT COUNT(*) c FROM ${t}`).get().c;
  const stats = { users: c('users'), series: c('series'), comments: c('comments'), messages: c('messages') };
  const latest = db.prepare(`${LIST_SQL} ORDER BY s.id DESC LIMIT 5`).all();
  res.render('admin/dashboard', { title: 'แดชบอร์ดผู้ดูแล', stats, latest });
});
app.get('/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare(`SELECT u.*, (SELECT COUNT(*) FROM series s WHERE s.user_id=u.id) AS series_count
    FROM users u ORDER BY u.id`).all();
  res.render('admin/users', { title: 'จัดการผู้ใช้', users });
});
app.post('/admin/users/:id/role', requireAdmin, (req, res) => {
  const id = +req.params.id;
  if (id === req.session.user.id) { flash(req, 'error', 'ไม่สามารถเปลี่ยนบทบาทของตัวเองได้'); return res.redirect('/admin/users'); }
  const role = req.body.role === 'admin' ? 'admin' : 'user';
  db.prepare('UPDATE users SET role=? WHERE id=?').run(role, id);
  flash(req, 'ok', 'เปลี่ยนบทบาทแล้ว');
  res.redirect('/admin/users');
});
app.post('/admin/users/:id/delete', requireAdmin, (req, res) => {
  const id = +req.params.id;
  if (id === req.session.user.id) { flash(req, 'error', 'ไม่สามารถลบบัญชีของตัวเองได้'); return res.redirect('/admin/users'); }
  db.prepare('DELETE FROM users WHERE id=?').run(id);
  flash(req, 'ok', 'ลบผู้ใช้แล้ว');
  res.redirect('/admin/users');
});
app.get('/admin/series', requireAdmin, (req, res) =>
  res.render('admin/series', { title: 'จัดการซีรีย์ทั้งหมด', list: db.prepare(`${LIST_SQL} ORDER BY s.id DESC`).all() }));
app.get('/admin/messages', requireAdmin, (req, res) =>
  res.render('admin/messages', { title: 'ข้อความจากผู้ใช้', list: db.prepare('SELECT * FROM messages ORDER BY id DESC').all() }));
app.post('/admin/messages/:id/delete', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM messages WHERE id=?').run(req.params.id);
  flash(req, 'ok', 'ลบข้อความแล้ว');
  res.redirect('/admin/messages');
});

app.use((req, res) => res.status(404).render('error', { message: 'ไม่พบหน้าที่คุณต้องการ' }));
app.use((err, req, res, next) => { console.error(err); res.status(500).render('error', { message: 'เกิดข้อผิดพลาดภายในระบบ' }); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🌸 ซีรีย์เกาหลี รันที่ http://localhost:${PORT}`));
