require('dotenv').config();

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const helmet = require('helmet');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const argon2 = require('argon2');
const multer = require('multer');
const { rateLimit } = require('express-rate-limit');
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT) || 5000;
const databaseUrl = process.env.DATABASE_URL;
const sessionSecret = process.env.SESSION_SECRET;
const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:5000,http://127.0.0.1:5000,https://perfumesbykache.co.ke')
  .split(',').map((origin) => origin.trim()).filter(Boolean);

if (!databaseUrl) throw new Error('DATABASE_URL is required.');
if (!sessionSecret || sessionSecret.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters.');

const pool = new Pool({ connectionString: databaseUrl, ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined });
const s3 = process.env.R2_ACCOUNT_ID && process.env.R2_ACCESS_KEY_ID && process.env.R2_SECRET_ACCESS_KEY
  ? new S3Client({
    region: 'auto',
    endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY }
  })
  : null;

if (isProduction) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  strictTransportSecurity: isProduction ? undefined : false
}));
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin is not allowed by CORS.'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token']
}));
app.use(express.json({ limit: '1mb' }));
app.use(session({
  name: 'kache.sid',
  store: new PgSession({ pool, tableName: 'sessions', createTableIfMissing: false }),
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: isProduction, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000, path: '/' }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false });
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 5 },
  fileFilter(req, file, callback) {
    if (!['image/jpeg', 'image/png', 'image/webp', 'image/avif'].includes(file.mimetype)) {
      return callback(new Error('Only JPEG, PNG, WebP, and AVIF images are accepted.'));
    }
    callback(null, true);
  }
});

function ensureAdmin(req, res, next) {
  if (!req.session.admin) return res.status(401).json({ error: 'Authentication required.' });
  next();
}

function csrfToken(req) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  return req.session.csrfToken;
}

function ensureCsrf(req, res, next) {
  const supplied = req.get('X-CSRF-Token') || '';
  const expected = req.session.csrfToken || '';
  const valid = supplied.length === expected.length && expected.length > 0
    && crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
  if (!valid) return res.status(403).json({ error: 'Invalid or missing CSRF token.' });
  next();
}

function normalizeProduct(body) {
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const brand = typeof body.brand === 'string' ? body.brand.trim() : '';
  const description = typeof body.description === 'string' ? body.description.trim() : '';
  const category = typeof body.category === 'string' ? body.category.trim() : '';
  const price = Number(body.priceKsh);
  const size = Number(body.sizeMl);
  const stock = Number(body.stock);
  const notes = Array.isArray(body.fragranceNotes)
    ? body.fragranceNotes.map((note) => String(note).trim()).filter(Boolean)
    : String(body.fragranceNotes || '').split(/[\n,]/).map((note) => note.trim()).filter(Boolean);
  const imageUrls = Array.isArray(body.imageUrls) ? body.imageUrls.map((url) => String(url).trim()).filter(Boolean) : [];

  if (!name || !brand || !description || !category || !Number.isFinite(price) || price < 0
    || !Number.isInteger(size) || size <= 0 || !Number.isInteger(stock) || stock < 0
    || notes.length > 30 || imageUrls.length > 10
    || imageUrls.some((url) => !/^https:\/\//i.test(url))) {
    throw new Error('Enter valid product details and HTTPS image URLs.');
  }
  return { name, brand, description, price, size, notes, category, stock, imageUrls };
}

const productColumns = `id, name, brand, description, price_ksh AS "priceKsh", size_ml AS "sizeMl",
  fragrance_notes AS "fragranceNotes", category, stock, image_urls AS "imageUrls",
  is_published AS "isPublished", created_at AS "createdAt", updated_at AS "updatedAt"`;

function productValues(product) {
  return [product.name, product.brand, product.description, product.price, product.size,
    product.notes, product.category, product.stock, product.imageUrls];
}

async function deleteR2Images(imageUrls) {
  if (!s3 || !process.env.R2_BUCKET_NAME || !process.env.R2_PUBLIC_URL || !imageUrls.length) return;
  const publicUrl = new URL(process.env.R2_PUBLIC_URL);
  const basePath = publicUrl.pathname.replace(/\/$/, '') + '/';
  const removals = imageUrls.flatMap((url) => {
    try {
      const imageUrl = new URL(url);
      if (imageUrl.origin !== publicUrl.origin || !imageUrl.pathname.startsWith(basePath)) return [];
      const key = decodeURIComponent(imageUrl.pathname.slice(basePath.length));
      return key ? [s3.send(new DeleteObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: key }))] : [];
    } catch {
      return [];
    }
  });
  const results = await Promise.allSettled(removals);
  if (results.some((result) => result.status === 'rejected')) console.warn('Some removed product images could not be deleted from R2.');
}

app.get('/api/admin/csrf', (req, res) => res.json({ csrfToken: csrfToken(req) }));

app.get('/api/admin/me', (req, res) => {
  res.json({ authenticated: Boolean(req.session.admin), email: req.session.admin?.email || null });
});

app.post('/api/admin/login', loginLimiter, ensureCsrf, async (req, res) => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!email || !password || password.length > 1024) return res.status(400).json({ error: 'Email and password are required.' });
  try {
    const result = await pool.query('SELECT id, email, password_hash FROM admins WHERE email = $1', [email]);
    const admin = result.rows[0];
    if (!admin || !(await argon2.verify(admin.password_hash, password, { type: argon2.argon2id }))) {
      return res.status(401).json({ error: 'Email or password is incorrect.' });
    }
    req.session.regenerate((error) => {
      if (error) return res.status(500).json({ error: 'Unable to start a secure session.' });
      req.session.admin = { id: admin.id, email: admin.email };
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
      req.session.save((saveError) => {
        if (saveError) return res.status(500).json({ error: 'Unable to start a secure session.' });
        res.json({ authenticated: true, csrfToken: req.session.csrfToken });
      });
    });
  } catch (error) {
    console.error('Admin login failed:', error.message);
    res.status(500).json({ error: 'Unable to sign in right now.' });
  }
});

app.post('/api/admin/logout', ensureAdmin, ensureCsrf, (req, res) => {
  req.session.destroy((error) => {
    if (error) return res.status(500).json({ error: 'Unable to sign out.' });
    res.clearCookie('kache.sid', { httpOnly: true, secure: isProduction, sameSite: 'lax', path: '/' });
    res.status(204).end();
  });
});

app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query(`SELECT ${productColumns} FROM products WHERE is_published = TRUE ORDER BY created_at DESC`);
    res.set('Cache-Control', 'no-store').json(result.rows);
  } catch (error) {
    console.error('Public products query failed:', error.message);
    res.status(500).json({ error: 'Unable to load products.' });
  }
});

app.get('/api/admin/products', ensureAdmin, async (req, res) => {
  try {
    const result = await pool.query(`SELECT ${productColumns} FROM products ORDER BY updated_at DESC`);
    res.json(result.rows);
  } catch (error) {
    console.error('Admin products query failed:', error.message);
    res.status(500).json({ error: 'Unable to load products.' });
  }
});

app.post('/api/admin/products', ensureAdmin, ensureCsrf, async (req, res) => {
  try {
    const product = normalizeProduct(req.body);
    const existing = await pool.query('SELECT image_urls AS "imageUrls" FROM products WHERE id=$1', [req.params.id]);
    if (!existing.rowCount) return res.status(404).json({ error: 'Product not found.' });
    const result = await pool.query(
      `INSERT INTO products (name, brand, description, price_ksh, size_ml, fragrance_notes, category, stock, image_urls)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING ${productColumns}`,
      productValues(product)
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(error.message.startsWith('Enter valid') ? 400 : 500).json({ error: error.message.startsWith('Enter valid') ? error.message : 'Unable to save product.' });
  }
});

app.put('/api/admin/products/:id', ensureAdmin, ensureCsrf, async (req, res) => {
  try {
    const product = normalizeProduct(req.body);
    const result = await pool.query(
      `UPDATE products SET name=$1, brand=$2, description=$3, price_ksh=$4, size_ml=$5,
       fragrance_notes=$6, category=$7, stock=$8, image_urls=$9, updated_at=NOW()
       WHERE id=$10 RETURNING ${productColumns}`,
      [...productValues(product), req.params.id]
    );
    const retainedUrls = new Set(product.imageUrls);
    await deleteR2Images(existing.rows[0].imageUrls.filter((url) => !retainedUrls.has(url)));
    res.json(result.rows[0]);
  } catch (error) {
    res.status(error.message.startsWith('Enter valid') ? 400 : 500).json({ error: error.message.startsWith('Enter valid') ? error.message : 'Unable to save product.' });
  }
});

app.patch('/api/admin/products/:id/publication', ensureAdmin, ensureCsrf, async (req, res) => {
  if (typeof req.body.isPublished !== 'boolean') return res.status(400).json({ error: 'isPublished must be a boolean.' });
  try {
    const result = await pool.query(
      `UPDATE products SET is_published=$1, updated_at=NOW() WHERE id=$2 RETURNING ${productColumns}`,
      [req.body.isPublished, req.params.id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Product not found.' });
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Product publication update failed:', error.message);
    res.status(500).json({ error: 'Unable to update publication status.' });
  }
});

app.post('/api/admin/uploads', ensureAdmin, ensureCsrf, (req, res, next) => {
  if (!s3 || !process.env.R2_BUCKET_NAME || !process.env.R2_PUBLIC_URL) {
    return res.status(503).json({ error: 'Image storage is not configured.' });
  }
  next();
}, upload.array('images', 5), async (req, res) => {
  const uploadedKeys = [];
  try {
    const bucket = process.env.R2_BUCKET_NAME;
    const publicBase = process.env.R2_PUBLIC_URL.replace(/\/$/, '');
    const extensions = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/avif': 'avif' };
    const { fileTypeFromBuffer } = await import('file-type');
    const images = [];
    const files = req.files || [];
    const detectedTypes = await Promise.all(files.map((file) => fileTypeFromBuffer(file.buffer)));
    if (detectedTypes.some((detected, index) => !detected || detected.mime !== files[index].mimetype || !extensions[detected.mime])) {
        return res.status(400).json({ error: 'One or more uploaded files are not valid supported images.' });
    }
    for (const file of files) {
      const key = `products/${crypto.randomUUID()}.${extensions[file.mimetype]}`;
      await s3.send(new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: file.buffer,
        ContentType: file.mimetype,
        CacheControl: 'public, max-age=31536000, immutable'
      }));
      uploadedKeys.push(key);
      images.push({ key, url: `${publicBase}/${key}` });
    }
    res.status(201).json({ images });
  } catch (error) {
    await Promise.all(uploadedKeys.map((Key) => s3.send(new DeleteObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key })).catch(() => {})));
    console.error('R2 upload failed:', error.message);
    res.status(502).json({ error: 'Image upload failed.' });
  }
});

app.delete('/api/admin/products/:id', ensureAdmin, ensureCsrf, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM products WHERE id=$1 RETURNING image_urls AS "imageUrls"', [req.params.id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Product not found.' });
    await deleteR2Images(result.rows[0].imageUrls);
    res.status(204).end();
  } catch (error) {
    console.error('Product delete failed:', error.message);
    res.status(500).json({ error: 'Unable to delete product.' });
  }
});

app.get('/admin', (req, res) => {
  if (req.session.admin) return res.redirect(302, '/admin/dashboard');
  res.sendFile(path.join(__dirname, 'admin', 'login.html'));
});
app.get('/admin/assets/:asset', (req, res, next) => {
  if (!['admin.css', 'login.js', 'dashboard.js'].includes(req.params.asset)) return res.sendStatus(404);
  if (req.params.asset === 'dashboard.js' && !req.session.admin) return res.sendStatus(401);
  res.sendFile(path.join(__dirname, 'admin', req.params.asset), (error) => error && next(error));
});
app.get('/admin/dashboard', (req, res) => {
  if (!req.session.admin) return res.redirect(302, '/admin');
  res.sendFile(path.join(__dirname, 'admin', 'dashboard.html'));
});
app.get('/admin/*path', (req, res) => res.redirect('/admin'));

const mpesaLimiter = rateLimit({ windowMs: 60 * 1000, limit: 5, standardHeaders: 'draft-8', legacyHeaders: false });
async function getMpesaToken() {
  const auth = Buffer.from(`${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`).toString('base64');
  const response = await axios.get(
    `${process.env.MPESA_API_BASE_URL}/oauth/v1/generate?grant_type=client_credentials`,
    { headers: { Authorization: `Basic ${auth}` } }
  );
  return response.data.access_token;
}

app.post('/api/stkpush', mpesaLimiter, async (req, res) => {
  try {
    const { phone, amount } = req.body;
    if (!process.env.MPESA_API_BASE_URL || !process.env.MPESA_CONSUMER_KEY || !process.env.MPESA_CONSUMER_SECRET || !process.env.MPESA_SHORTCODE
      || !process.env.MPESA_PASSKEY || !process.env.MPESA_CALLBACK_URL) {
      return res.status(503).json({ success: false, message: 'M-Pesa is not configured.' });
    }
    if (typeof phone !== 'string' || !Number.isFinite(Number(amount)) || Number(amount) <= 0) {
      return res.status(400).json({ success: false, message: 'Enter a valid phone number and amount.' });
    }
    let formattedPhone = phone.trim().replace(/[\s+()-]/g, '');
    if (formattedPhone.startsWith('0')) formattedPhone = `254${formattedPhone.substring(1)}`;
    if (formattedPhone.startsWith('7') || formattedPhone.startsWith('1')) formattedPhone = `254${formattedPhone}`;
    if (!/^254[17]\d{8}$/.test(formattedPhone)) return res.status(400).json({ success: false, message: 'Enter a valid Kenyan phone number.' });

    const token = await getMpesaToken();
    const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, 14);
    const shortcode = process.env.MPESA_SHORTCODE;
    const password = Buffer.from(`${shortcode}${process.env.MPESA_PASSKEY}${timestamp}`).toString('base64');
    const stkData = {
      BusinessShortCode: shortcode,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: Math.round(Number(amount)),
      PartyA: formattedPhone,
      PartyB: shortcode,
      PhoneNumber: formattedPhone,
      CallBackURL: process.env.MPESA_CALLBACK_URL,
      AccountReference: 'PerfumesByKache',
      TransactionDesc: 'Perfume Purchase'
    };
    const response = await axios.post(
      `${process.env.MPESA_API_BASE_URL}/mpesa/stkpush/v1/processrequest`, stkData,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    res.status(200).json({ success: true, message: 'STK Push sent!', data: response.data });
  } catch (error) {
    console.error('M-Pesa STK push failed:', error.response?.data || error.message);
    res.status(502).json({ success: false, message: 'Failed to trigger STK Push.' });
  }
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error instanceof multer.MulterError) return res.status(400).json({ error: 'Upload limit exceeded or invalid upload.' });
  if (error.message.startsWith('Only JPEG')) return res.status(400).json({ error: error.message });
  if (error.message.startsWith('Origin is not allowed')) return res.status(403).json({ error: 'Origin is not allowed.' });
  console.error('Unhandled request error:', error.message);
  res.status(500).json({ error: 'An unexpected server error occurred.' });
});

if (require.main === module) {
  app.listen(port, () => console.log(`Perfumes by Kache API listening on port ${port}`));
}

module.exports = { app, pool };const express = require('express');
const app = express();

// 1. STANDARD MIDDLEWARE (Body parsers, CORS, etc.)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// -------------------------------------------------------------
// 2. GLOBAL REQUEST LOGGER (PASTE HERE - ABOVE ALL ROUTES)
// -------------------------------------------------------------
app.use((req, res, next) => {
  console.log(`[REQUEST] ${req.method} ${req.url}`);
  next(); // Passes the request to the next route or middleware
});

// -------------------------------------------------------------
// 3. YOUR ROUTERS & ROUTES
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'), (err) => {
    if (err) {
      console.error('File send error:', err);
      res.status(500).send('Error loading page: ' + err.message);
    }
  });
});

// -------------------------------------------------------------
// 4. GLOBAL ERROR HANDLER (PASTE AT THE VERY BOTTOM)
// -------------------------------------------------------------
app.use((err, req, res, next) => {
  console.error('SERVER ERROR:', err.stack || err);
  res.status(500).json({ error: err.message || 'An unexpected server error occurred.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
