const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const dir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dir, { recursive: true });
const db = new Database(path.join(dir, 'app.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS series (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  genre TEXT NOT NULL,
  year INTEGER,
  rating INTEGER NOT NULL,
  image_url TEXT,
  review TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  series_id INTEGER NOT NULL REFERENCES series(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

// ---- สร้างบัญชี admin อัตโนมัติ (ถ้ายังไม่มี) ----
const adminEmail = (process.env.ADMIN_EMAIL || 'admin@kseries.com').toLowerCase();
const adminPass = process.env.ADMIN_PASSWORD || 'Admin@12345';
let admin = db.prepare('SELECT * FROM users WHERE email = ?').get(adminEmail);
if (!admin) {
  const info = db.prepare("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,'admin')")
    .run('ผู้ดูแลระบบ', adminEmail, bcrypt.hashSync(adminPass, 10));
  admin = { id: info.lastInsertRowid };
  console.log(`✔ สร้างแอดมินแล้ว: ${adminEmail} / ${adminPass}`);
}

// ---- ข้อมูลตัวอย่าง ----
if (db.prepare('SELECT COUNT(*) c FROM series').get().c === 0) {
  const ins = db.prepare('INSERT INTO series (user_id,title,genre,year,rating,image_url,review) VALUES (?,?,?,?,?,?,?)');
  ins.run(admin.id, 'Our Beloved Summer', 'โรแมนติก', 2021, 5, '', 'เรื่องราวความรักของอดีตแฟนเก่าที่ต้องกลับมาเจอกันผ่านสารคดี ภาพสวย เพลงเพราะ ดูแล้วอบอุ่นหัวใจมาก เหมาะกับวันที่อยากพักใจ');
  ins.run(admin.id, 'Hometown Cha-Cha-Cha', 'ฟีลกู๊ด', 2021, 5, '', 'หมู่บ้านริมทะเลที่ผู้คนใจดี ดูแล้วยิ้มตามทั้งเรื่อง เป็นซีรีย์เยียวยาใจที่แนะนำสุดๆ');
  ins.run(admin.id, 'Reply 1988', 'ดราม่า', 2015, 5, '', 'มิตรภาพและครอบครัวของเพื่อนบ้านในซอยเดียวกัน ตลกและซึ้งปนกันอย่างลงตัว ดูจบแล้วคิดถึงเลย');
}

module.exports = db;
