const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss');
const csrf = require('csurf');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');
const path = require('path');
const fs = require('fs');
const stripe = process.env.STRIPE_SECRET_KEY 
  ? require('stripe')(process.env.STRIPE_SECRET_KEY)
  : null;

// Stripe configuration
const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID || 'price_1TDupAFRLGwNpssTKxUCvsZf';
const STRIPE_PUBLISHABLE_KEY = process.env.STRIPE_PUBLISHABLE_KEY || '';

const DATA_DIR = path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const SESSION_SECRET = process.env.SESSION_SECRET || 'central-alberta-night-life-secret-key';

const SMTP_CONFIG = {
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587', 10),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
};

console.log('[Email] Transporter config:', {
  host: SMTP_CONFIG.host,
  port: SMTP_CONFIG.port,
  secure: SMTP_CONFIG.secure,
  user: SMTP_CONFIG.auth.user || '(not set)',
  passSet: !!SMTP_CONFIG.auth.pass,
});

const emailTransporter = nodemailer.createTransport(SMTP_CONFIG);

const FROM_EMAIL = process.env.FROM_EMAIL || 'noreply@centralalbertaafterdark.com';
const APP_URL = process.env.APP_URL || 'https://www.centralalbertaafterdark.com';

async function sendEmail(to, subject, html) {
  console.log(`[Email] sendEmail() called — to: ${to}, subject: "${subject}"`);
  console.log('[Email] SMTP config at send time:', {
    host: SMTP_CONFIG.host,
    port: SMTP_CONFIG.port,
    secure: SMTP_CONFIG.secure,
    user: SMTP_CONFIG.auth.user || '(not set)',
    passSet: !!SMTP_CONFIG.auth.pass,
    from: FROM_EMAIL,
  });

  if (!SMTP_CONFIG.auth.user || !SMTP_CONFIG.auth.pass) {
    console.error('[Email] SMTP_USER or SMTP_PASS is not set — aborting send.');
    return;
  }

  try {
    const info = await emailTransporter.sendMail({ from: FROM_EMAIL, to, subject, html });
    console.log(`[Email] Message sent successfully — messageId: ${info.messageId}, response: ${info.response}`);
  } catch (err) {
    console.error('[Email] sendMail() threw an error:');
    console.error(`[Email]   message : ${err.message}`);
    console.error(`[Email]   code    : ${err.code || '(none)'}`);
    console.error(`[Email]   command : ${err.command || '(none)'}`);
    console.error(`[Email]   response: ${err.response || '(none)'}`);
    console.error('[Email] Full error object:', err);
  }
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https:"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:", "*"],
    },
  },
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { error: 'Too many registration attempts. Try again in an hour.' },
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP.' },
});


// Webhook BEFORE rate limiting and body parsing
app.use('/api/webhook/stripe', express.raw({ type: 'application/json' }));

app.use('/api/login', loginLimiter);
app.use('/api/register', registerLimiter);
app.use('/api/', apiLimiter);
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
const cookieParser = require('cookie-parser');
app.use(cookieParser());

// Session middleware
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sessionId',
  cookie: {
    secure: IS_PRODUCTION,
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

// Serve uploads folder
const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));

// Multer config for photo uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.random().toString(36).slice(2) + path.extname(file.originalname))
});
const upload = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|webp/i;
    const ext = path.extname(file.originalname).slice(1);
    cb(null, allowed.test(ext) && allowed.test(file.mimetype));
  }
});

const requireAuth = (req, res, next) => {
  if (req.session?.userId) {
    next();
  } else {
    return res.status(401).json({ error: 'Unauthorized - please log in.' });
  }
};

// Delete a photo by index
app.delete('/api/photos/:index', requireAuth, (req, res) => {
  const index = parseInt(req.params.index);
  db.get('SELECT photos FROM profiles WHERE user_id = ?', [req.session.userId], (err, row) => {
    if (err || !row || !row.photos) return res.json({ photos: [] });
    let photos = [];
    try { photos = JSON.parse(row.photos); } catch (_) {}
    if (index >= 0 \&\& index < photos.length) {
      photos.splice(index, 1);
      db.run('UPDATE profiles SET photos = ? WHERE user_id = ?', [JSON.stringify(photos), req.session.userId], (e) => {
        res.json({ photos });
      });
    } else {
      res.json({ photos });
    }
  });
});

// Photo upload endpoint
app.post('/api/upload-photo', requireAuth, upload.single('photo'), (req, res) => {
  console.log('Upload for user:', req.session?.userId, 'file:', req.file?.filename);
  if (!req.file) return res.status(400).json({ error: 'Invalid file type. Use jpg, png, or webp.' });
  
  const photoUrl = '/uploads/' + req.file.filename;
  const positionX = req.body.positionX || 0;
  const positionY = req.body.positionY || 0;
  
  // Get current photos
  db.get('SELECT photos FROM profiles WHERE user_id = ?', [req.session.userId], (err, row) => {
    if (err) {
      console.log('DB error:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }
    let photos = [];
    if (row && row.photos) {
      try { photos = JSON.parse(row.photos); } catch (_) {}
    }
    // Add new photo (max 4 photos)
    if (photos.length >= 4) photos.shift();
    photos.push({ url: photoUrl, x: positionX, y: positionY });
    
    db.run('UPDATE profiles SET photos = ? WHERE user_id = ?', [JSON.stringify(photos), req.session.userId], (err) => {
      if (err) {
        console.log('Update error:', err.message);
        return res.status(500).json({ error: 'Save failed' });
      }
      console.log('Photo saved for user:', req.session.userId);
      res.json({ url: photoUrl, photos });
    });
  });
});

// Admin: Delete test users
app.delete('/api/admin/users', (req, res) => {
  const { usernames } = req.body;
  if (!usernames || !Array.isArray(usernames)) {
    return res.status(400).json({ error: 'usernames array required' });
  }
  const placeholders = usernames.map(() => '?').join(',');
  db.run('DELETE FROM users WHERE username IN (' + placeholders + ')', usernames, function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
  db.run('DELETE FROM profiles WHERE user_id IN (SELECT id FROM users WHERE username IN (' + placeholders + '))', usernames);
});

app.use(express.static('public'));

const csrfProtection = csrf({ cookie: { httpOnly: true }, secret: SESSION_SECRET });

const csrfGenerateOnly = (req, res, next) => {
  csrfProtection(req, res, (err) => {
    if (err && err.code === 'EBADCSRFTOKEN') {
      return next();
    }
    next(err);
  });
};

app.get('/api/csrf-token', csrfGenerateOnly, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.get('/test-email', async (req, res) => {
  const to = req.query.to || FROM_EMAIL;
  console.log(`[Email] /test-email triggered — sending test email to: ${to}`);
  try {
    await sendEmail(
      to,
      'Central Alberta After Dark — SMTP test',
      '<p>This is a test email sent from the <strong>/test-email</strong> endpoint to verify that the nodemailer transporter is working correctly.</p>'
    );
    res.json({
      success: true,
      message: `Test email dispatched to ${to}. Check server logs for delivery confirmation or error details.`,
      smtpConfig: {
        host: SMTP_CONFIG.host,
        port: SMTP_CONFIG.port,
        secure: SMTP_CONFIG.secure,
        user: SMTP_CONFIG.auth.user || '(not set)',
        passSet: !!SMTP_CONFIG.auth.pass,
        from: FROM_EMAIL,
      },
    });
  } catch (err) {
    console.error('[Email] /test-email caught unexpected error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

const db = new sqlite3.Database(path.join(DATA_DIR, 'database.sqlite'), (err) => {
  if (err) {
    console.error('Failed to open database:', err.message);
    process.exit(1);
  }
  console.log('Connected to SQLite database.');
});

db.serialize(() => {
  db.run('PRAGMA foreign_keys = ON');
  
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    age INTEGER CHECK(age >= 18 AND age <= 120),
    location TEXT,
    bio TEXT,
    shift_schedule TEXT,
    is_verified INTEGER DEFAULT 0,
    is_premium INTEGER DEFAULT 0,
    verification_token TEXT,
    reset_token TEXT,
    reset_token_expires INTEGER,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until INTEGER,
    last_active DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  const newColumns = [
    `ALTER TABLE users ADD COLUMN verification_token TEXT`,
    `ALTER TABLE users ADD COLUMN reset_token TEXT`,
    `ALTER TABLE users ADD COLUMN reset_token_expires INTEGER`,
    `ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN locked_until INTEGER`,
    `ALTER TABLE users ADD COLUMN last_active DATETIME`,
  ];

  newColumns.forEach(sql => {
    db.run(sql, (err) => {
      if (err && !err.message.includes('duplicate column')) {
        console.error('Migration error:', err.message);
      }
    });
  });

  db.run(`CREATE TABLE IF NOT EXISTS profiles (
    user_id INTEGER PRIMARY KEY,
    interests TEXT,
    looking_for TEXT,
    photos TEXT DEFAULT '[]',
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    liker_id INTEGER,
    liked_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(liker_id, liked_id),
    FOREIGN KEY(liker_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(liked_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1_id INTEGER,
    user2_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user1_id, user2_id),
    FOREIGN KEY(user1_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(user2_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS public_ticker (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS webhook_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stripe_event_id TEXT UNIQUE NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT,
    processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  console.log('Database tables initialized.');
});

const xssOptions = { whiteList: {}, stripIgnoreTag: true, stripIgnoreTagBody: ['script', 'style'] };
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return xss(input, xssOptions);
}

app.use((req, res, next) => {
  if (req.body && typeof req.body === 'object') {
    try {
      for (const key of Object.keys(req.body)) {
        if (typeof req.body[key] === 'string') {
          req.body[key] = sanitizeInput(req.body[key]);
        }
      }
    } catch (e) {
      console.error('Sanitization error:', e);
    }
  }
  next();
});

app.post('/api/register', csrfProtection, [
  body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
  body('username').isLength({ min: 3, max: 20 }).matches(/^[a-zA-Z0-9_]+$/).withMessage('Username: 3-20 chars, letters/numbers/underscore only'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  body('age').optional().isInt({ min: 18, max: 120 }).withMessage('Age must be 18-120')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
  }
  
  const { email, username, password, age, location } = req.body;
  const safeLocation = location ? sanitizeInput(location) : null;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    const verificationToken = crypto.randomBytes(32).toString('hex');
    
    // Use serialize to ensure synchronous execution
    db.serialize(() => {
      db.run(
        `INSERT INTO users (email, username, password_hash, age, location, verification_token, is_verified) VALUES (?, ?, ?, ?, ?, ?, 1)`,
        [email.toLowerCase(), username, hashedPassword, age || null, safeLocation, verificationToken],
        function(err) {
          if (err) {
            if (err.message?.includes('UNIQUE constraint failed')) {
              return res.status(400).json({ error: 'Email or username already taken.' });
            }
            console.error('DB Error:', err);
            return res.status(500).json({ error: 'Database error' });
          }
          
          const userId = this.lastID;
          console.log('User created with ID:', userId);
          
          // Create user profile
          db.run(
            `INSERT INTO profiles (user_id) VALUES (?)`,
            [userId],
            (err) => {
              if (err) console.error('Profile creation error:', err);
            }
          );
          
          // Only send verification email for real domains (skip test@example.com etc)
          const isTestEmail = /\b(example\.com|test\.com|foo\.com|fake\.com|null)\$/i.test(email);
          if (!isTestEmail) {
            const verifyUrl = `${APP_URL}/api/verify-email?token=${verificationToken}`;
            sendEmail(
              email,
              'Verify your Central Alberta After Dark account',
              `<p>Welcome to Central Alberta After Dark!</p><p>Please verify your email address: <a href="${verifyUrl}">${verifyUrl}</a></p><p>Must verify before logging in.</p>`
            ).catch(err => console.log('Email error:', err.message));
          }
          
          res.status(201).json({ success: true, message: 'Account created!' });
        }
      );
    });
  } catch (error) {
    console.error('Server Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/verify-email', (req, res) => {
  const { token } = req.query;

  const renderPage = (statusCode, title, heading, bodyHtml) => {
    res.status(statusCode).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title} — Central Alberta After Dark</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background: #0d0d0d;
      color: #e8e8e8;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem;
    }
    .card {
      background: #1a1a1a;
      border: 1px solid #2e2e2e;
      border-radius: 12px;
      padding: 2.5rem 2rem;
      max-width: 480px;
      width: 100%;
      text-align: center;
    }
    .icon { font-size: 3rem; margin-bottom: 1rem; }
    h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.75rem; }
    p { color: #aaa; line-height: 1.6; margin-bottom: 1.5rem; }
    a.btn {
      display: inline-block;
      background: #c0392b;
      color: #fff;
      text-decoration: none;
      padding: 0.65rem 1.5rem;
      border-radius: 8px;
      font-weight: 600;
      font-size: 0.95rem;
      transition: background 0.2s;
    }
    a.btn:hover { background: #a93226; }
    a.link { color: #c0392b; text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    ${bodyHtml}
  </div>
</body>
</html>`);
  };

  if (!token || typeof token !== 'string') {
    return renderPage(400, 'Invalid Link', 'Invalid Link', `
      <div class="icon">⚠️</div>
      <h1>Invalid verification link</h1>
      <p>This verification link is missing or malformed. Please request a new one.</p>
      <a class="btn" href="${APP_URL}">Go to homepage</a>
    `);
  }

  db.run(
    `UPDATE users SET is_verified = 1, verification_token = NULL WHERE verification_token = ? AND is_verified = 0`,
    [token],
    function(err) {
      if (err) {
        console.error('DB Error:', err);
        return renderPage(500, 'Server Error', 'Server Error', `
          <div class="icon">❌</div>
          <h1>Something went wrong</h1>
          <p>A database error occurred while verifying your account. Please try again later or contact support.</p>
          <a class="btn" href="${APP_URL}">Go to homepage</a>
        `);
      }
      if (this.changes === 0) {
        return renderPage(400, 'Link Expired', 'Link Expired', `
          <div class="icon">🔗</div>
          <h1>Link already used or expired</h1>
          <p>This verification link has already been used or has expired. If your account is not yet verified, you can request a new link.</p>
          <a class="btn" href="${APP_URL}">Go to homepage</a>
        `);
      }
      renderPage(200, 'Email Verified', 'Email Verified', `
        <div class="icon">✅</div>
        <h1>Email verified!</h1>
        <p>Your account has been successfully verified. You can now log in and enjoy Central Alberta After Dark.</p>
        <a class="btn" href="${APP_URL}">Go to homepage</a>
      `);
    }
  );
});

app.post('/api/resend-verification', csrfProtection, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });
  
  db.get(
    `SELECT id, email, is_verified, verification_token FROM users WHERE email = ?`,
    [email.toLowerCase()],
    async (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!user || user.is_verified) {
        return res.json({ success: true, message: 'If that address is registered and unverified, a new email has been sent.' });
      }
      
      const newToken = crypto.randomBytes(32).toString('hex');
      db.run(`UPDATE users SET verification_token = ? WHERE id = ?`, [newToken, user.id]);
      
      const verifyUrl = `${APP_URL}/api/verify-email?token=${newToken}`;
      await sendEmail(user.email, 'Verify your Central Alberta After Dark account', `<p>Here is your new verification link: <a href="${verifyUrl}">${verifyUrl}</a></p>`);
      
      res.json({ success: true, message: 'If that address is registered and unverified, a new email has been sent.' });
    }
  );
});

app.post('/api/login', csrfProtection, [
  body('username').isLength({ min: 3 }).withMessage('Invalid username'),
  body('password').exists().withMessage('Password required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
  }
  
  const { username, password } = req.body;
  
  db.get(
    `SELECT id, username, password_hash, is_verified, failed_login_attempts, locked_until, last_active FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!user) {
        await bcrypt.hash('dummy', 12);
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      const now = Date.now();
      if (user.locked_until && now < user.locked_until) {
        return res.status(423).json({ error: `Account locked. Try again in ${(user.locked_until - now)/60000|0} minutes.` });
      }
      if (!user.is_verified) {
        return res.status(403).json({ error: 'Please verify your email address before logging in.' });
      }
      
      try {
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
          const newAttempts = (user.failed_login_attempts || 0) + 1;
          const shouldLock = newAttempts >= 5;
          db.run(
            `UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?`,
            [newAttempts, shouldLock ? now + 15*60*1000 : null, user.id]
          );
          if (shouldLock) {
            return res.status(423).json({ error: 'Too many failed attempts. Account locked for 15 minutes.' });
          }
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        db.run(`UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`, [user.id]);
        
        req.session.regenerate((err) => {
          if (err) {
            console.error('Session regeneration error:', err);
            return res.status(500).json({ error: 'Server error' });
          }
          req.session.userId = user.id;
          req.session.username = user.username;
          
          // Check for new likes since last login
          const lastActive = user.last_active || '1970-01-01';
          db.all(`SELECT l.id, l.created_at, u.username, u.age, u.location, u.bio
            FROM likes l 
            JOIN users u ON l.liker_id = u.id
            WHERE l.liked_id = ? AND l.created_at > ?
            ORDER BY l.created_at DESC`, [user.id, lastActive], (err, newLikes) => {
            // Update last_active
            db.run(`UPDATE users SET last_active = datetime('now') WHERE id = ?`, [user.id]);
            
            const likers = newLikes ? newLikes.map(u => u.username) : [];
            if (likers.length > 0) {
              res.json({ 
                success: true, 
                username: user.username,
                newLikes: likers,
                newLikesMessage: `❤️ You've been liked by ${likers.join(', ')} while you were away!`
              });
            } else {
              res.json({ success: true, username: user.username });
            }
          });
        });
      } catch (error) {
        console.error('Bcrypt Error:', error);
        res.status(500).json({ error: 'Server error' });
      }
    }
  );
});

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: 'Logout failed.' });
    res.clearCookie('sessionId');
    res.json({ success: true, message: 'Logged out.' });
  });
});

app.post('/api/forgot-password', csrfProtection, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });
  
  const genericResponse = { success: true, message: 'If that email is registered, a reset link has been sent.' };
  
  db.get(
    `SELECT id, email FROM users WHERE email = ?`,
    [email.toLowerCase()],
    async (err, user) => {
      if (err) console.error('DB Error:', err);
      if (!user) return res.json(genericResponse);
      
      const resetToken = crypto.randomBytes(32).toString('hex');
      const expires = Date.now() + 60 * 60 * 1000;
      
      db.run(
        `UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?`,
        [resetToken, expires, user.id],
        async (err) => {
          if (err) {
            console.error('DB Error:', err);
            return res.json(genericResponse);
          }
          const resetUrl = `${APP_URL}/reset-password.html?token=${resetToken}`;
          await sendEmail(user.email, 'Reset your Central Alberta After Dark password', `<p><a href="${resetUrl}">${resetUrl}</a></p>`);
          res.json(genericResponse);
        }
      );
    }
  );
});

app.post('/api/reset-password', csrfProtection, async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token and new password are required.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  
  db.get(
    `SELECT id, reset_token_expires FROM users WHERE reset_token = ?`,
    [token],
    async (err, user) => {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!user) return res.status(400).json({ error: 'Invalid or expired reset token.' });
      if (Date.now() > user.reset_token_expires) return res.status(400).json({ error: 'Reset token has expired.' });
      
      try {
        const hashedPassword = await bcrypt.hash(password, 12);
        db.run(
          `UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL, failed_login_attempts = 0, locked_until = NULL WHERE id = ?`,
          [hashedPassword, user.id],
          (err) => {
            if (err) {
              console.error('DB Error:', err);
              return res.status(500).json({ error: 'Database error' });
            }
            res.json({ success: true, message: 'Password updated. You can now log in.' });
          }
        );
      } catch (error) {
        console.error('Bcrypt Error:', error);
        res.status(500).json({ error: 'Server error' });
      }
    }
  );
});

// Get Stripe publishable key for frontend
app.get('/api/stripe-config', (req, res) => {
  res.json({ 
    publishableKey: STRIPE_PUBLISHABLE_KEY,
    hasStripe: !!stripe
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  db.get(
    `SELECT u.id, u.username, u.email, u.age, u.location, u.bio, u.shift_schedule, u.is_premium, u.created_at,
            p.interests, p.looking_for, p.photos
     FROM users u
     LEFT JOIN profiles p ON u.id = p.user_id
     WHERE u.id = ?`,
    [req.session.userId],
    (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!user) return res.status(404).json({ error: 'User not found' });
      user.photos = user.photos ? JSON.parse(user.photos) : [];
      res.json(user);
    }
  );
});

// Get all verified profiles
app.get('/api/profiles', requireAuth, (req, res) => {
  // Update last_active for current user
  db.run('UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE id = ?', [req.session.userId]);
  
  db.all(
    `SELECT u.id, u.username, u.age, u.location, u.bio, u.shift_schedule, u.is_premium, u.last_active, u.created_at,
            p.interests, p.looking_for, p.photos
     FROM users u
     LEFT JOIN profiles p ON u.id = p.user_id
     WHERE u.is_verified = 1 AND u.id != ?
     ORDER BY u.created_at DESC`,
    [req.session.userId],
    (err, users) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      const now = Date.now();
      users = users.map(u => {
        const lastActive = u.last_active ? new Date(u.last_active).getTime() : 0;
        const isOnline = now - lastActive < 5 * 60 * 1000; // 5 minutes
        return {
          ...u,
          photos: u.photos ? JSON.parse(u.photos) : [],
          online: isOnline
        };
      });
      res.json(users);
    }
  );
});

// Update user profile (including age)
app.put('/api/me', requireAuth, csrfProtection, (req, res) => {
  const { age, bio, location, shift_schedule, interests, looking_for } = req.body;
  
  // Handle empty strings as null
  const ageVal = age && age !== '' ? parseInt(age) : null;
  const bioVal = bio && bio.trim() ? sanitizeInput(bio) : null;
  const locVal = location && location.trim() ? sanitizeInput(location) : null;
  const shiftVal = shift_schedule && shift_schedule.trim() ? sanitizeInput(shift_schedule) : null;
  
  db.run(
    `UPDATE users SET 
       age = COALESCE(?, age),
       bio = COALESCE(?, bio), 
       location = COALESCE(?, location), 
       shift_schedule = COALESCE(?, shift_schedule) 
     WHERE id = ?`,
    [ageVal, bioVal, locVal, shiftVal, req.session.userId],
    function(err) {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      // Ensure profile row exists, then update interests/looking_for
      db.run(
        `INSERT OR IGNORE INTO profiles (user_id) VALUES (?)`,
        [req.session.userId],
        () => {
          db.run(
            `UPDATE profiles SET interests = COALESCE(?, interests), looking_for = COALESCE(?, looking_for) WHERE user_id = ?`,
            [interests || null, looking_for || null, req.session.userId],
            (err) => {
              if (err) console.error('Profile update error:', err);
            }
          );
        }
      );
      
      res.json({ success: true });
    }
  );
});

app.get('/api/profiles', (req, res) => {
  const currentUserId = req.session?.userId;
  
  db.all(
    `SELECT id, username, age, location, bio, shift_schedule, interests, looking_for, is_premium FROM users WHERE is_verified = 1 AND (id != ? OR ? IS NULL)`,
    [currentUserId || null, currentUserId || null],
    (err, rows) => {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      // Get current user for compatibility scoring
      if (currentUserId) {
        db.get(`SELECT * FROM users WHERE id = ?`, [currentUserId], (err, currentUser) => {
          if (currentUser) {
            // Calculate compatibility for each profile
            rows = rows.map(profile => ({
              ...profile,
              match_score: calculateCompatibility(currentUser, profile)
            }));
          }
          res.json(rows);
        });
      } else {
        res.json(rows);
      }
    }
  );
});

// Calculate compatibility score between two users
function calculateCompatibility(user1, user2) {
  let score = 0;
  let factors = 0;
  
  // Age compatibility
  if (user1.age && user2.age) {
    const ageDiff = Math.abs(user1.age - user2.age);
    if (ageDiff <= 3) score += 30;
    else if (ageDiff <= 10) score += 15;
    factors++;
  }
  
  // Location matching
  if (user1.location && user2.location && user1.location === user2.location) {
    score += 25;
    factors++;
  }
  
  // Shift schedule compatibility
  if (user1.shift_schedule && user2.shift_schedule && user1.shift_schedule === user2.shift_schedule) {
    score += 25;
    factors++;
  }
  
  // Interests overlap
  if (user1.interests && user2.interests) {
    const interests1 = (user1.interests || '').toLowerCase().split(/[,\s]+/).filter(Boolean);
    const interests2 = (user2.interests || '').toLowerCase().split(/[,\s]+/).filter(Boolean);
    const overlap = interests1.filter(i => interests2.includes(i)).length;
    if (interests1.length + interests2.length > 0) {
      score += (overlap / (interests1.length + interests2.length)) * 20;
    }
    factors++;
  }
  
  return factors > 0 ? Math.min(100, Math.round(score)) : null;
}

// AI Match endpoint (premium only)
app.post('/api/ai-match', requireAuth, csrfProtection, async (req, res) => {
  const targetId = req.body.target_id;
  if (!targetId) return res.status(400).json({ error: 'Target required' });
  
  // Check premium
  if (!req.session.isPremium) {
    return res.status(403).json({ error: 'Premium required', premium_required: true });
  }
  
  try {
    const target = await new Promise((resolve, reject) => {
      db.get(`SELECT * FROM users WHERE id = ?`, [targetId], (err, row) => {
        if (err) reject(err); else resolve(row);
      });
    });
    
    const currentUser = await new Promise((resolve, reject) => {
      db.get(`SELECT * FROM users WHERE id = ?`, [req.session.userId], (err, row) => {
        if (err) reject(err); else resolve(row);
      });
    });
    
    if (!target || !currentUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Generate AI match explanation
    const explanation = generateAiMatchExplanation(currentUser, target);
    
    res.json({ explanation, success: true });
  } catch (err) {
    console.error('AI Match error:', err);
    res.status(500).json({ error: 'AI matching failed' });
  }
});

function generateAiMatchExplanation(user1, user2) {
  const reasons = [];
  
  if (user1.age && user2.age && Math.abs(user1.age - user2.age) <= 5) {
    reasons.push('Similar age range');
  }
  if (user1.location === user2.location) {
    reasons.push(`Both in ${user1.location}`);
  }
  if (user1.shift_schedule === user2.shift_schedule) {
    reasons.push('Same shift schedule');
  }
  if (user1.interests && user2.interests) {
    const i1 = (user1.interests || '').toLowerCase().split(/[,\s]+/).filter(Boolean);
    const i2 = (user2.interests || '').toLowerCase().split(/[,\s]+/).filter(Boolean);
    const shared = i1.filter(i => i2.includes(i));
    if (shared.length > 0) {
      reasons.push(`Shared interests: ${shared.join(', ')}`);
    }
  }
  if (user1.looking_for === user2.looking_for) {
    reasons.push(`Looking for the same: ${user1.looking_for}`);
  }
  
  if (reasons.length === 0) {
    reasons.push('Great potential match!');
  }
  
  return reasons.join('. ');
}

app.post('/api/like/:id', requireAuth, csrfProtection, (req, res) => {
  const likedId = parseInt(req.params.id, 10);
  const likerId = req.session.userId;
  if (likedId === likerId) return res.status(400).json({ error: 'Cannot like yourself' });
  

  // Get liker name for notifications
  let likerName = "Someone";
  db.get(`SELECT username FROM users WHERE id = ?`, [likerId], (err, row) => {
    if (row) likerName = row.username;
  });
  db.run(
    `INSERT OR IGNORE INTO likes (liker_id, liked_id) VALUES (?, ?)`,
    [likerId, likedId],
    function(err) {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      db.get(
        `SELECT * FROM likes WHERE liker_id = ? AND liked_id = ?`,
        [likedId, likerId],
        (err, reciprocal) => {
          if (err) {
            console.error('DB Error:', err);
            return res.status(500).json({ error: 'Database error' });
          }
          if (reciprocal) {
            const user1 = Math.min(likerId, likedId);
            const user2 = Math.max(likerId, likedId);
            db.run(`INSERT OR IGNORE INTO matches (user1_id, user2_id) VALUES (?, ?)`, [user1, user2]);
            
            // Send match email notification (async, don't wait)
            db.get(`SELECT email, username FROM users WHERE id = ?`, [likedId], (err, likedUser) => {
              if (likedUser && likerName && !/\b(example\.com|test\.com|fake\.com)\$/i.test(likedUser.email)) {
                sendEmail(
                  likedUser.email,
                  '💛 It\'s a Match with ' + likerName + '!',
                  `<p>🎉 Congratulations! You and <strong>${likerName}</strong> liked each other!</p><p>It's a match! Send them a message.</p>`
                ).catch(e => console.log('Match email error:', e.message));
              }
            });
            
            return res.json({ success: true, match: true, message: "It's a match!" });
          }
          
          // Send like email notification (async, don't wait)
          db.get(`SELECT email, username FROM users WHERE id = ?`, [likedId], (err, likedUser) => {
            if (likedUser && likerName && !/\b(example\.com|test\.com|fake\.com)\$/i.test(likedUser.email)) {
              sendEmail(
                likedUser.email,
                '❤️ ' + likerName + ' liked your profile!',
                `<p>🌙 <strong>${likerName}</strong> liked your profile!</p><p>Log in to see who and like them back!</p>`
              ).catch(e => console.log('Like email error:', e.message));
            }
          });
          
          res.json({ success: true, match: false, message: 'Liked!' });
        }
      );
    }
  );
});

app.post('/create-checkout-session', requireAuth, csrfProtection, async (req, res) => {
  if (!stripe) {
    return res.status(503).json({ error: 'Premium checkout is not configured. Please contact support.' });
  }
  try {
    console.log('[Stripe] Creating checkout session for user:', req.session.userId);
    console.log('[Stripe] Price ID:', STRIPE_PRICE_ID);
    
    const checkoutSession = await stripe.checkout.sessions.create({
      billing_address_collection: 'auto',
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      mode: 'subscription',
      client_reference_id: String(req.session.userId),
      success_url: `${APP_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${APP_URL}/cancel.html`,
    });
    
    console.log('[Stripe] Checkout session created:', checkoutSession.id);
    res.json({ url: checkoutSession.url });
  } catch (err) {
    console.error('[Stripe] Checkout error:', err.message);
    console.error('[Stripe] Code:', err.code);
    res.status(500).json({ error: err.message || 'Failed to create checkout session.' });
  }
});

app.get('/api/webhook/stripe', (req, res) => res.send('Stripe webhook endpoint active')); app.post('/api/webhook/stripe', (req, res) => {
  console.log('[Webhook] Received stripe webhook');
  if (!stripe) {
    console.error('Stripe not configured — webhook disabled.');
    return res.status(503).send('Stripe not configured.');
  }
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  
  if (!webhookSecret) {
    console.error('STRIPE_WEBHOOK_SECRET not set — webhook disabled.');
    return res.status(200).send("Add STRIPE_WEBHOOK_SECRET");
  }
  
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  
  db.get(
    `SELECT id FROM webhook_events WHERE stripe_event_id = ?`,
    [event.id],
    (err, existing) => {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).send('Database error');
      }
      if (existing) return res.json({ received: true });
      
      db.run(
        `INSERT INTO webhook_events (stripe_event_id, event_type, payload) VALUES (?, ?, ?)`,
        [event.id, event.type, JSON.stringify(event.data.object)],
        (err) => {
          if (err) console.error('Webhook log error:', err);
        }
      );
      
      if (event.type === 'checkout.session.completed') {
        const userId = event.data.object.client_reference_id;
        if (userId) {
          db.run(`UPDATE users SET is_premium = 1 WHERE id = ?`, [userId], (err) => {
            if (err) console.error('Failed to upgrade user:', err);
          });
        }
      }
      
      res.json({ received: true });
    }
  );
});

// Get new likes/notifications for polling
app.get('/api/notifications', requireAuth, (req, res) => {
  const userId = req.session.userId;
  const since = req.query.since || '1970-01-01';
  
  db.all(
    `SELECT l.id, l.created_at as time, u.id as liker_id, u.username, u.age, u.photos
      FROM likes l 
      JOIN users u ON l.liker_id = u.id
      WHERE l.liked_id = ? AND l.created_at > ?
      ORDER BY l.created_at DESC
      LIMIT 10`,
    [userId, since],
    (err, notifications) => {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({ notifications: notifications || [] });
    }
  );
});

// Get user's matches
app.get('/api/matches', requireAuth, (req, res) => {
  const userId = req.session.userId;
  
  db.all(`
    SELECT m.id, m.created_at,
      CASE WHEN m.user1_id = ? THEN m.user2_id ELSE m.user1_id END as user_id,
      u.username, u.location, u.last_active
    FROM matches m
    JOIN users u ON u.id = CASE WHEN m.user1_id = ? THEN m.user2_id ELSE m.user1_id END
    WHERE m.user1_id = ? OR m.user2_id = ?
    ORDER BY m.created_at DESC
  `, [userId, userId, userId, userId], (err, rows) => {
    if (err) {
      console.error('Matches error:', err);
      return res.status(500).json({ error: 'Failed to get matches' });
    }
    res.json({ matches: rows || [] });
  });
});

// Public ticker: Get recent messages (no auth required)
app.get('/api/ticker', (req, res) => {
  db.all(`SELECT * FROM public_ticker ORDER BY created_at DESC LIMIT 20`, [], (err, rows) => {
    if (err) {
      console.error('Ticker error:', err);
      return res.status(500).json({ error: 'Failed to get ticker' });
    }
    res.json({ ticker: rows || [] });
  });
});

// Public ticker: Post a message (requires auth)
app.post('/api/ticker', requireAuth, csrfProtection, (req, res) => {
  const { message } = req.body;
  const userId = req.session.userId;
  const username = req.session.username;
  
  if (!message || message.trim().length < 2) {
    return res.status(400).json({ error: 'Message too short' });
  }
  if (message.length > 200) {
    return res.status(400).json({ error: 'Message too long (max 200 chars)' });
  }
  
  db.run(`INSERT INTO public_ticker (user_id, username, message) VALUES (?, ?, ?)`,
    [userId, username, message.trim()], function(err) {
      if (err) {
        console.error('Ticker post error:', err);
        return res.status(500).json({ error: 'Failed to post' });
      }
      res.json({ success: true, id: this.lastID });
    });
});

// Chat: Send a message
app.post('/api/messages', requireAuth, csrfProtection, (req, res) => {
  const { receiver_id, message } = req.body;
  const sender_id = req.session.userId;
  
  if (!receiver_id || !message) {
    return res.status(400).json({ error: 'receiver_id and message required' });
  }
  if (message.length > 1000) {
    return res.status(400).json({ error: 'Message too long (max 1000 chars)' });
  }
  
  db.run(`INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)`,
    [sender_id, receiver_id, message], function(err) {
      if (err) {
        console.error('Message send error:', err);
        return res.status(500).json({ error: 'Failed to send message' });
      }
      res.json({ success: true, message: 'Message sent!', message_id: this.lastID });
    });
});

// Chat: Get conversations (list of users you've messaged with)
app.get('/api/conversations', requireAuth, (req, res) => {
  const userId = req.session.userId;
  
  db.all(`
    SELECT DISTINCT 
      CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END as partner_id,
      u.username, u.location, u.last_active,
      (SELECT message FROM messages WHERE id IN (
        SELECT id FROM messages WHERE 
        (sender_id = ? AND receiver_id = partner_id) OR 
        (sender_id = partner_id AND receiver_id = ?)
      ) ORDER BY created_at DESC LIMIT 1) as last_message,
      (SELECT created_at FROM messages WHERE id IN (
        SELECT id FROM messages WHERE 
        (sender_id = ? AND receiver_id = partner_id) OR 
        (sender_id = partner_id AND receiver_id = ?)
      ) ORDER BY created_at DESC LIMIT 1) as last_time,
      (SELECT COUNT(*) FROM messages WHERE sender_id = partner_id AND receiver_id = ? AND is_read = 0) as unread
    FROM messages m
    JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
    WHERE m.sender_id = ? OR m.receiver_id = ?
    ORDER BY last_time DESC
  `, [userId, userId, userId, userId, userId, userId, userId, userId, userId], (err, rows) => {
    if (err) {
      console.error('Conversations error:', err);
      return res.status(500).json({ error: 'Failed to get conversations' });
    }
    res.json({ conversations: rows || [] });
  });
});

// Chat: Get messages with a specific user
app.get('/api/messages/:partnerId', requireAuth, (req, res) => {
  const userId = req.session.userId;
  const partnerId = parseInt(req.params.partnerId);
  
  if (!partnerId || isNaN(partnerId)) {
    return res.status(400).json({ error: 'Invalid partner ID' });
  }
  
  db.all(`
    SELECT m.*, u.username as sender_username 
    FROM messages m
    JOIN users u ON u.id = m.sender_id
    WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
    ORDER BY m.created_at ASC
  `, [userId, partnerId, partnerId, userId], (err, rows) => {
    if (err) {
      console.error('Messages error:', err);
      return res.status(500).json({ error: 'Failed to get messages' });
    }
    // Mark messages as read
    db.run(`UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ? AND is_read = 0`,
      [partnerId, userId], () => {});
    res.json({ messages: rows || [] });
  });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/settings', (req, res) => res.sendFile(path.join(__dirname, 'public', 'settings.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/forgot-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/reset-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset-password.html')));
app.get('/success', (req, res) => res.sendFile(path.join(__dirname, 'public', 'success.html')));
app.get('/cancel', (req, res) => res.sendFile(path.join(__dirname, 'public', 'cancel.html')));

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid or missing CSRF token. Please refresh the page and try again.' });
  }
  console.error('Unhandled Error:', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT_NUM = parseInt(PORT, 10);
app.listen(PORT_NUM, () => {
  console.log(`Server listening on port ${PORT_NUM}`);
});
