import crypto from 'crypto';

export function csrfMiddleware(req, res, next) {
  if (!req.cookies.csrf_token) {
    res.cookie('csrf_token', crypto.randomBytes(24).toString('hex'), {
      httpOnly: false,
      sameSite: 'lax',
      secure: process.env.COOKIE_SECURE === 'true'
    });
  }
  if (['GET','HEAD','OPTIONS'].includes(req.method)) return next();

  const cookie = req.cookies.csrf_token;
  const header = req.get('x-csrf-token');
  if (!cookie || !header || cookie !== header) {
    return res.status(403).json({message:'CSRF token tidak valid'});
  }
  next();
}
