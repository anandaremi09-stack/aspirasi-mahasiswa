import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { z } from 'zod';
import { pool } from './db.js';
import { csrfMiddleware } from './middleware/csrf.js';
import { requireAuth, requireRole } from './middleware/auth.js';
import { upload } from './middleware/upload.js';
import { randomToken, sha256 } from './utils.js';

dotenv.config();
const app = express();
app.use(helmet());
app.use(cors({origin: process.env.FRONTEND_URL, credentials:true}));
app.use(express.json({limit:'1mb'}));
app.use(cookieParser());
app.use(csrfMiddleware);
app.use('/uploads', express.static('uploads', {index:false}));

const loginLimiter = rateLimit({windowMs:15*60*1000, max:10, standardHeaders:true, legacyHeaders:false});

function issueAuth(res, user) {
  const token = jwt.sign(
    {id:user.id, role:user.role, nama:user.nama, email:user.email},
    process.env.JWT_SECRET,
    {expiresIn:'2h'}
  );
  res.cookie('access_token', token, {
    httpOnly:true,
    sameSite:'lax',
    secure:process.env.COOKIE_SECURE === 'true',
    maxAge:2*60*60*1000
  });
}

const registerSchema = z.object({
  nama:z.string().trim().min(2).max(150),
  nim:z.string().trim().min(3).max(30),
  email:z.string().email().max(190),
  program_studi:z.string().trim().max(120),
  password:z.string().min(8).max(100),
  konfirmasi_password:z.string()
}).refine(v=>v.password===v.konfirmasi_password,{path:['konfirmasi_password'],message:'Password tidak sama'});

app.get('/api/csrf', (req,res)=>res.json({csrfToken:req.cookies.csrf_token}));

app.post('/api/auth/register', async (req,res)=>{
  const parsed=registerSchema.safeParse(req.body);
  if(!parsed.success) return res.status(400).json({message:'Data registrasi tidak valid',errors:parsed.error.flatten()});
  const {nama,nim,email,program_studi,password}=parsed.data;
  try {
    const [existing]=await pool.query('SELECT id FROM users WHERE nim=? OR email=? LIMIT 1',[nim,email]);
    if(existing.length) return res.status(409).json({message:'NIM atau email sudah terdaftar'});
    const hash=await bcrypt.hash(password,12);
    await pool.query('INSERT INTO users (nama,nim,email,password_hash,program_studi) VALUES (?,?,?,?,?)',[nama,nim,email,hash,program_studi]);
    res.status(201).json({message:'Registrasi berhasil'});
  } catch(e){res.status(500).json({message:'Gagal membuat akun'});}
});

app.post('/api/auth/login', loginLimiter, async (req,res)=>{
  const schema=z.object({identifier:z.string().trim().min(3),password:z.string().min(1)});
  const parsed=schema.safeParse(req.body);
  if(!parsed.success) return res.status(400).json({message:'Data login tidak valid'});
  const [rows]=await pool.query('SELECT * FROM users WHERE email=? OR nim=? LIMIT 1',[parsed.data.identifier,parsed.data.identifier]);
  if(!rows.length || !(await bcrypt.compare(parsed.data.password,rows[0].password_hash)))
    return res.status(401).json({message:'Email/NIM atau password salah'});
  issueAuth(res,rows[0]);
  res.json({user:{id:rows[0].id,nama:rows[0].nama,email:rows[0].email,nim:rows[0].nim,program_studi:rows[0].program_studi,role:rows[0].role}});
});

app.post('/api/auth/logout',(req,res)=>{
  res.clearCookie('access_token');
  res.json({message:'Logout berhasil'});
});

app.get('/api/auth/me', requireAuth, async (req,res)=>{
  const [rows]=await pool.query('SELECT id,nama,nim,email,program_studi,role,created_at FROM users WHERE id=?',[req.user.id]);
  if(!rows.length) return res.status(401).json({message:'User tidak ditemukan'});
  res.json({user:rows[0]});
});

app.post('/api/auth/forgot-password', async (req,res)=>{
  const email=String(req.body.email||'').trim().toLowerCase();
  const [rows]=await pool.query('SELECT id FROM users WHERE email=? LIMIT 1',[email]);
  // Selalu respons sama agar email terdaftar tidak dapat ditebak.
  if(rows.length){
    const raw=randomToken(), hash=sha256(raw);
    await pool.query('INSERT INTO password_resets (user_id,token_hash,expires_at) VALUES (?,?,DATE_ADD(NOW(),INTERVAL 30 MINUTE))',[rows[0].id,hash]);
    console.log(`[DEV RESET TOKEN] ${raw}`);
  }
  res.json({message:'Jika email terdaftar, instruksi reset telah dibuat.'});
});

app.post('/api/auth/reset-password', async (req,res)=>{
  const schema=z.object({token:z.string().min(20),password:z.string().min(8).max(100)});
  const parsed=schema.safeParse(req.body);
  if(!parsed.success) return res.status(400).json({message:'Data reset tidak valid'});
  const [rows]=await pool.query('SELECT * FROM password_resets WHERE token_hash=? AND used_at IS NULL AND expires_at>NOW() LIMIT 1',[sha256(parsed.data.token)]);
  if(!rows.length) return res.status(400).json({message:'Token reset tidak valid atau kedaluwarsa'});
  const hash=await bcrypt.hash(parsed.data.password,12);
  await pool.query('UPDATE users SET password_hash=? WHERE id=?',[hash,rows[0].user_id]);
  await pool.query('UPDATE password_resets SET used_at=NOW() WHERE id=?',[rows[0].id]);
  res.json({message:'Password berhasil diubah'});
});

app.get('/api/categories', async (_,res)=>{
  const [rows]=await pool.query('SELECT id,nama_kategori FROM categories WHERE is_active=1 ORDER BY nama_kategori');
  res.json(rows);
});

app.post('/api/categories', requireAuth, requireRole('admin','super_admin'), async (req,res)=>{
  const name=String(req.body.nama_kategori||'').trim();
  if(name.length<2 || name.length>100) return res.status(400).json({message:'Nama kategori tidak valid'});
  try { await pool.query('INSERT INTO categories (nama_kategori) VALUES (?)',[name]); res.status(201).json({message:'Kategori dibuat'}); }
  catch { res.status(409).json({message:'Kategori sudah ada'}); }
});

app.post('/api/complaints', requireAuth, requireRole('mahasiswa'), upload.single('lampiran'), async (req,res)=>{
  const schema=z.object({
    judul:z.string().trim().min(5).max(200),
    kategori_id:z.coerce.number().int().positive(),
    deskripsi:z.string().trim().min(10).max(10000),
    is_anonim:z.enum(['true','false']).default('false')
  });
  const parsed=schema.safeParse(req.body);
  if(!parsed.success) return res.status(400).json({message:'Data aspirasi tidak valid'});
  const file=req.file ? `/uploads/${req.file.filename}` : null;
  const [result]=await pool.query(
    'INSERT INTO complaints (user_id,judul,kategori_id,deskripsi,lampiran_url,is_anonim) VALUES (?,?,?,?,?,?)',
    [req.user.id,parsed.data.judul,parsed.data.kategori_id,parsed.data.deskripsi,file,parsed.data.is_anonim==='true']
  );
  res.status(201).json({id:result.insertId,message:'Aspirasi berhasil dikirim'});
});

app.get('/api/complaints/mine', requireAuth, requireRole('mahasiswa'), async (req,res)=>{
  const [rows]=await pool.query(
    `SELECT c.id,c.judul,c.deskripsi,c.status,c.is_anonim,c.lampiran_url,c.created_at,c.updated_at,
            cat.nama_kategori AS kategori
     FROM complaints c JOIN categories cat ON cat.id=c.kategori_id
     WHERE c.user_id=? ORDER BY c.created_at DESC`,[req.user.id]);
  res.json(rows);
});

app.get('/api/complaints/:id', requireAuth, async (req,res)=>{
  const id=Number(req.params.id);
  if(!Number.isInteger(id)) return res.status(400).json({message:'ID tidak valid'});
  const [rows]=await pool.query(
    `SELECT c.*,cat.nama_kategori AS kategori,u.nama,u.nim,u.email,u.program_studi
     FROM complaints c JOIN categories cat ON cat.id=c.kategori_id
     LEFT JOIN users u ON u.id=c.user_id WHERE c.id=? LIMIT 1`,[id]);
  if(!rows.length) return res.status(404).json({message:'Aspirasi tidak ditemukan'});
  const item=rows[0];
  if(req.user.role==='mahasiswa' && item.user_id!==req.user.id) return res.status(403).json({message:'Akses ditolak'});
  if(item.is_anonim && req.user.role==='mahasiswa') { item.nama=null; item.nim=null; item.email=null; }
  const [responses]=await pool.query(
    `SELECT r.id,r.isi_tanggapan,r.created_at,u.nama AS admin_nama
     FROM responses r JOIN users u ON u.id=r.admin_id WHERE r.complaint_id=? ORDER BY r.created_at ASC`,[id]);
  res.json({...item,responses});
});

app.get('/api/admin/complaints', requireAuth, requireRole('admin','super_admin'), async (req,res)=>{
  const {status,kategori_id,prodi,from,to}=req.query;
  let sql=`SELECT c.id,c.judul,c.status,c.is_anonim,c.created_at,c.updated_at,
                  cat.nama_kategori AS kategori,u.nama,u.nim,u.program_studi
           FROM complaints c JOIN categories cat ON cat.id=c.kategori_id
           LEFT JOIN users u ON u.id=c.user_id WHERE 1=1`;
  const args=[];
  if(status){sql+=' AND c.status=?';args.push(status);}
  if(kategori_id){sql+=' AND c.kategori_id=?';args.push(Number(kategori_id));}
  if(prodi){sql+=' AND u.program_studi=?';args.push(prodi);}
  if(from){sql+=' AND c.created_at>=?';args.push(from);}
  if(to){sql+=' AND c.created_at<=?';args.push(to+' 23:59:59');}
  sql+=' ORDER BY c.created_at DESC';
  const [rows]=await pool.query(sql,args);
  res.json(rows);
});

app.patch('/api/admin/complaints/:id', requireAuth, requireRole('admin','super_admin'), async (req,res)=>{
  const schema=z.object({status:z.enum(['Baru','Diproses','Ditanggapi','Selesai','Ditolak'])});
  const parsed=schema.safeParse(req.body);
  if(!parsed.success) return res.status(400).json({message:'Status tidak valid'});
  const [r]=await pool.query('UPDATE complaints SET status=? WHERE id=?',[parsed.data.status,Number(req.params.id)]);
  if(!r.affectedRows) return res.status(404).json({message:'Aspirasi tidak ditemukan'});
  res.json({message:'Status diperbarui'});
});

app.post('/api/admin/complaints/:id/responses', requireAuth, requireRole('admin','super_admin'), async (req,res)=>{
  const isi=String(req.body.isi_tanggapan||'').trim();
  if(isi.length<3 || isi.length>10000) return res.status(400).json({message:'Tanggapan tidak valid'});
  const id=Number(req.params.id);
  const [r]=await pool.query('INSERT INTO responses (complaint_id,admin_id,isi_tanggapan) VALUES (?,?,?)',[id,req.user.id,isi]);
  await pool.query(`UPDATE complaints SET status=IF(status='Baru','Ditanggapi',status) WHERE id=?`,[id]);
  res.status(201).json({id:r.insertId,message:'Tanggapan dikirim'});
});

app.get('/api/admin/stats', requireAuth, requireRole('admin','super_admin'), async (_,res)=>{
  const [[totals]]=await pool.query(`SELECT
    COUNT(*) total,
    SUM(status='Baru') baru,
    SUM(status='Diproses') diproses,
    SUM(status='Ditanggapi') ditanggapi,
    SUM(status='Selesai') selesai,
    SUM(status='Ditolak') ditolak
    FROM complaints`);
  const [categories]=await pool.query(`SELECT cat.nama_kategori kategori,COUNT(c.id) jumlah
    FROM categories cat LEFT JOIN complaints c ON c.kategori_id=cat.id
    GROUP BY cat.id ORDER BY jumlah DESC`);
  const [trend]=await pool.query(`SELECT DATE(created_at) tanggal,COUNT(*) jumlah
    FROM complaints WHERE created_at>=DATE_SUB(CURDATE(),INTERVAL 30 DAY)
    GROUP BY DATE(created_at) ORDER BY tanggal`);
  res.json({totals,categories,trend});
});

app.get('/api/admin/users', requireAuth, requireRole('super_admin'), async (_,res)=>{
  const [rows]=await pool.query(`SELECT id,nama,nim,email,program_studi,role,created_at FROM users ORDER BY created_at DESC`);
  res.json(rows);
});

app.use((err,req,res,next)=>{
  if(err instanceof multer.MulterError) return res.status(400).json({message:'Lampiran terlalu besar atau tidak valid'});
  console.error(err);
  res.status(500).json({message:'Terjadi kesalahan server'});
});

app.listen(Number(process.env.PORT||5000),()=>console.log(`API berjalan di http://localhost:${process.env.PORT||5000}`));
