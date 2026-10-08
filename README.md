# 🌸 ซีรีย์เกาหลี (Korean Series Web App)

เว็บแอปแนะนำ/รีวิวซีรีย์เกาหลี ธีมพาสเทลสไตล์เกาหลี เน้นความสบายใจ
สร้างด้วย **Node.js + Express + EJS + SQLite**

## ฟีเจอร์ตามโจทย์
| ข้อ | ฟีเจอร์ | อยู่ที่ |
|---|---|---|
| 1 | สมัครสมาชิก/เข้าสู่ระบบ + แฮชรหัสผ่านด้วย **bcrypt** (cost 10) | `server.js` `/register` `/login` |
| 2 | 2 บทบาท `user` / `admin` | middleware `requireAdmin` |
| 3 | CRUD ซีรีย์ที่มีเจ้าของ — **แก้ไขได้เฉพาะเจ้าของ**, ลบได้โดยเจ้าของหรือ admin | `ownerOnly` ใน `server.js` |
| 4 | ฟอร์มบันทึกลง DB และแสดงผล: ฟอร์มซีรีย์, ฟอร์มความคิดเห็น, ฟอร์มติดต่อเรา, ฟอร์มสมัคร | `/series`, `/series/:id/comments`, `/contact` |
| 5 | หน้าผู้ดูแล: แดชบอร์ด, จัดการผู้ใช้ (เปลี่ยนบทบาท/ลบ), จัดการซีรีย์, ดูข้อความ | `/admin/*` |

เสริม: CSRF token ทุกฟอร์ม, escape ข้อมูลด้วย EJS, จำกัดการเดารหัสผ่าน, session cookie แบบ httpOnly

## 🔑 บัญชีแอดมินเริ่มต้น (สร้างอัตโนมัติเมื่อรันครั้งแรก)
- อีเมล: `admin@kseries.com`
- รหัสผ่าน: `Admin@12345`

> เปลี่ยนได้ผ่านตัวแปร `ADMIN_EMAIL` / `ADMIN_PASSWORD` **ก่อนรันครั้งแรก** และควรเปลี่ยนรหัสก่อนใช้งานจริง

## รันในเครื่อง
```bash
npm install
cp .env.example .env    # แก้ SESSION_SECRET
npm start               # เปิด http://localhost:3000
```

## อัปขึ้น GitHub และ Deploy
```bash
git init && git add . && git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/<ชื่อคุณ>/<repo>.git
git push -u origin main
```
> GitHub Pages รันเว็บที่มี backend/ฐานข้อมูลไม่ได้ ให้ใช้ GitHub เก็บโค้ด แล้ว deploy ที่ **Render** (มี `render.yaml` ให้แล้ว):
> Render → New → Blueprint (หรือ Web Service) → เลือก repo นี้ → Deploy

⚠️ ฐานข้อมูล SQLite บน Render แพ็กเกจฟรีจะรีเซ็ตเมื่อ redeploy หากต้องการเก็บถาวรให้เพิ่ม Disk แล้วตั้ง `DATA_DIR` ชี้ไปที่ path ของ disk

## โครงสร้างไฟล์
```
server.js   เส้นทางและตรรกะทั้งหมด
db.js       สร้างตาราง + seed admin + ข้อมูลตัวอย่าง
views/      หน้าเว็บ (EJS) + views/admin หน้าผู้ดูแล
public/css  สไตล์ธีมเกาหลี
```
