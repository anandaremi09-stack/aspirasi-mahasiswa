# Aspirasi Mahasiswa Fakultas

Website full-stack untuk pengelolaan aspirasi & keluhan mahasiswa.

## Stack
- Frontend: React + Vite
- Backend: Node.js + Express
- Database: MySQL
- Auth: JWT + bcrypt
- Upload: Multer
- Chart: Recharts

## 1. Persiapan
Pastikan Node.js 20+ dan MySQL sudah terpasang.

Buat database:
```sql
CREATE DATABASE aspirasi_mahasiswa CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Import `database/schema.sql` ke database tersebut.

## 2. Backend
```bash
cd backend
npm install
copy .env.example .env
```
Linux/macOS:
```bash
cp .env.example .env
```

Edit `.env`, lalu:
```bash
npm run dev
```

Backend berjalan di `http://localhost:5000`.

## 3. Frontend
Buka terminal baru:
```bash
cd frontend
npm install
copy .env.example .env
```
Linux/macOS:
```bash
cp .env.example .env
```

Lalu:
```bash
npm run dev
```

Frontend berjalan di alamat yang ditampilkan Vite.

## Akun admin demo
Setelah backend aktif:
```bash
cd backend
npm run seed:admin
```

Default:
- Email: `admin@fakultas.ac.id`
- Password: `Admin123!`

Segera ganti password setelah login.

## Catatan keamanan
Project ini sudah menerapkan hashing password, validasi server, JWT httpOnly cookie, CSRF double-submit token, rate limit login, RBAC, Helmet, pembatasan upload, dan parameterized SQL.

Untuk production gunakan HTTPS, secret JWT yang kuat, database terkelola, storage file yang aman, email provider untuk reset password, dan audit logging.
