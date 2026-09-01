import bcrypt from 'bcrypt';
import { pool } from './db.js';

const email = 'admin@fakultas.ac.id';
const password = 'Admin123!';
const hash = await bcrypt.hash(password, 12);

await pool.query(
  `INSERT INTO users (nama,email,password_hash,role)
   VALUES (?,?,?,'super_admin')
   ON DUPLICATE KEY UPDATE password_hash=VALUES(password_hash), role='super_admin'`,
  ['Administrator Fakultas', email, hash]
);
console.log(`Admin siap: ${email} / ${password}`);
await pool.end();
