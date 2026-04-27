const express = require('express');
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
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

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
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
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

app.use('/api/login', loginLimiter);
app.use('/api/register', registerLimiter);
app.use('/api/', apiLimiter);

app.use('/webhook/stripe', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
const cookieParser = require('cookie-parser');
app.use(cookieParser());
app.use(express.static('public'));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: '/app/data' }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sessionId',
  cookie: {
    secure: IS_PRODUCTION,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax',
    domain: IS_PRODUCTION ? 'centralalbertaafterdark.com' : undefined,
  },
}));

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

const db = new sqlite3.Database('/app/data/database.sqlite', (err) => {
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  const newColumns = [
    `ALTER TABLE users ADD COLUMN verification_token TEXT`,
    `ALTER TABLE users ADD COLUMN reset_token TEXT`,
    `ALTER TABLE users ADD COLUMN reset_token_expires INTEGER`,
    `ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN locked_until INTEGER`,
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

const requireAuth = (req, res, next) => {
  if (req.session?.userId) {
    next();
  } else {
    return res.status(401).json({ error: 'Unauthorized - please log in.' });
  }
};

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
    
    db.run(
      `INSERT INTO users (email, username, password_hash, age, location, verification_token) VALUES (?, ?, ?, ?, ?, ?)`,
      [email.toLowerCase(), username, hashedPassword, age || null, safeLocation, verificationToken],
      async function(err) {
        if (err) {
          if (err.message?.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Email or username already taken.' });
          }
          console.error('DB Error:', err);
          return res.status(500).json({ error: 'Database error' });
        }
        
        const verifyUrl = `${APP_URL}/api/verify-email?token=${verificationToken}`;
        await sendEmail(
          email,
          'Verify your Central Alberta After Dark account',
          `<p>Welcome to Central Alberta After Dark!</p><p>Please verify your email address: <a href="${verifyUrl}">${verifyUrl}</a></p><p>Must verify before logging in.</p>`
        );
        
        res.status(201).json({ success: true, message: 'Account created! Please check your email to verify.' });
      }
    );
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
    `SELECT id, username, password_hash, is_verified, failed_login_attempts, locked_until FROM users WHERE username = ?`,
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
          res.json({ success: true, username: user.username });
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

app.get('/api/me', requireAuth, (req, res) => {
  db.get(
    `SELECT id, username, email, age, location, bio, is_premium, created_at FROM users WHERE id = ?`,
    [req.session.userId],
    (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json(user);
    }
  );
});

app.put('/api/me', requireAuth, csrfProtection, (req, res) => {
  const { bio, location, shift_schedule } = req.body;
  db.run(
    `UPDATE users SET bio = COALESCE(?, bio), location = COALESCE(?, location), shift_schedule = COALESCE(?, shift_schedule) WHERE id = ?`,
    [bio ? sanitizeInput(bio) : null, location ? sanitizeInput(location) : null, shift_schedule ? sanitizeInput(shift_schedule) : null, req.session.userId],
    function(err) {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json({ success: true });
    }
  );
});

app.get('/api/profiles', (req, res) => {
  db.all(
    `SELECT id, username, age, location, bio FROM users WHERE is_verified = 1 AND (id != ? OR ? IS NULL)`,
    [req.session?.userId || null, req.session?.userId || null],
    (err, rows) => {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(rows);
    }
  );
});

app.post('/api/like/:id', requireAuth, csrfProtection, (req, res) => {
  const likedId = parseInt(req.params.id, 10);
  const likerId = req.session.userId;
  if (likedId === likerId) return res.status(400).json({ error: 'Cannot like yourself' });
  
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
            return res.json({ success: true, match: true, message: "It's a match!" });
          }
          res.json({ success: true, match: false, message: 'Liked!' });
        }
      );
    }
  );
});

app.post('/create-checkout-session', requireAuth, csrfProtection, async (req, res) => {
  try {
    const checkoutSession = await stripe.checkout.sessions.create({
      billing_address_collection: 'auto',
      line_items: [{ price: 'price_1TDupAFRLGwNpssTKxUCvsZf', quantity: 1 }],
      mode: 'subscription',
      client_reference_id: String(req.session.userId),
      success_url: `${APP_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${APP_URL}/cancel.html`,
    });
    
    res.json({ url: checkoutSession.url });
  } catch (err) {
    console.error('Stripe error:', err);
    res.status(500).json({ error: 'Failed to create checkout session.' });
  }
});

app.post('/webhook/stripe', (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  
  if (!webhookSecret) {
    console.error('STRIPE_WEBHOOK_SECRET not set — webhook disabled.');
    return res.status(500).send('Webhook secret not configured.');
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

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid or missing CSRF token. Please refresh the page and try again.' });
  }
  console.error('Unhandled Error:', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Central Alberta Night Life server running on http://localhost:${PORT}`);
});
