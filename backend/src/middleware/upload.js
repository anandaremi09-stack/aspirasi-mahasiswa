import multer from 'multer';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';

const dir = path.resolve('uploads');
fs.mkdirSync(dir, {recursive:true});

const allowed = new Set([
  'image/jpeg','image/png','image/webp',
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
]);

const storage = multer.diskStorage({
  destination: dir,
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext}`);
  }
});

export const upload = multer({
  storage,
  limits: {fileSize: Number(process.env.MAX_FILE_MB || 5) * 1024 * 1024},
  fileFilter: (_, file, cb) => cb(null, allowed.has(file.mimetype))
});
