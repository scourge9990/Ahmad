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
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const SESSION_SECRET = process.env.SESSION_SECRET || 'central-alberta-night-life-secret-key';

// ---------------------------------------------------------------------------
// Email transporter (configure via environment variables)
// ---------------------------------------------------------------------------
const emailTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587', 10),
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const FROM_EMAIL = process.env.FROM_EMAIL || 'noreply@centralalbertaafterdark.com';
const APP_URL = process.env.APP_URL || 'https://www.centralalbertaafterdark.com';

async function sendEmail(to, subject, html) {
  try {
    await emailTransporter.sendMail({ from: FROM_EMAIL, to, subject, html });
  } catch (err) {
    console.error('Email send error:', err);
  }
}

// ---------------------------------------------------------------------------
// Security middleware
// ---------------------------------------------------------------------------
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// ---------------------------------------------------------------------------
// Rate limiters
// ---------------------------------------------------------------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
});

// Stricter limiter for registration to prevent bot account spam
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
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

// ---------------------------------------------------------------------------
// Body parsing — Stripe webhook needs raw body BEFORE json middleware
// ---------------------------------------------------------------------------
app.use('/webhook/stripe', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
const cookieParser = require('cookie-parser');
app.use(cookieParser());
app.use(express.static('public'));

// ---------------------------------------------------------------------------
// Session — persistent SQLite store, secure cookies in production
// ---------------------------------------------------------------------------
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: './' }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sessionId',
  cookie: {
    secure: IS_PRODUCTION,   // HTTPS-only in production
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'strict',
  },
}));

// ---------------------------------------------------------------------------
// CSRF protection — applied to all state-changing routes
// ---------------------------------------------------------------------------
const csrfProtection = csrf({ cookie: true }); // uses cookie store

// Expose CSRF token to the frontend via a dedicated endpoint.
// We run csrfProtection but swallow EBADCSRFTOKEN validation errors — the
// middleware still attaches req.csrfToken() to the request before it checks
// the incoming token, so the handler can generate a fresh token even when
// no prior token exists (e.g. first page load, login/signup forms).
const csrfGenerateOnly = (req, res, next) => {
  csrfProtection(req, res, (err) => {
    if (err && err.code === 'EBADCSRFTOKEN') {
      // Validation failed but req.csrfToken is now available — continue.
      return next();
    }
    next(err);
  });
};

app.get('/api/csrf-token', csrfGenerateOnly, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------
const db = new sqlite3.Database('./database.sqlite', (err) => {
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

  // Add new columns to existing databases that were created before this migration
  const newColumns = [
    `ALTER TABLE users ADD COLUMN verification_token TEXT`,
    `ALTER TABLE users ADD COLUMN reset_token TEXT`,
    `ALTER TABLE users ADD COLUMN reset_token_expires INTEGER`,
    `ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN locked_until INTEGER`,
  ];
  newColumns.forEach(sql => {
    db.run(sql, (err) => {
      // Ignore "duplicate column" errors — column already exists
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

// ---------------------------------------------------------------------------
// Input sanitization — strip all HTML from user-supplied strings
// ---------------------------------------------------------------------------
const xssOptions = {
  whiteList: {},
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style'],
};

function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return xss(input, xssOptions);
}

// Sanitize every string value in req.body
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

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------
const requireAuth = (req, res, next) => {
  if (req.session?.userId) {
    next();
  } else {
    return res.status(401).json({ error: 'Unauthorized - please log in.' });
  }
};

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------
app.post('/api/register',
  csrfProtection,
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('username')
      .isLength({ min: 3, max: 20 })
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username: 3-20 chars, letters/numbers/underscore only'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('age').optional().isInt({ min: 18, max: 120 }).withMessage('Age must be 18-120'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
    }

    const { email, username, password, age, location } = req.body;

    // Sanitize free-text fields explicitly
    const safeLocation = location ? sanitizeInput(location) : null;

    try {
      const hashedPassword = await bcrypt.hash(password, 12);
      const verificationToken = crypto.randomBytes(32).toString('hex');

      db.run(
        `INSERT INTO users (email, username, password_hash, age, location, verification_token)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [email.toLowerCase(), username, hashedPassword, age || null, safeLocation, verificationToken],
        async function(err) {
          if (err) {
            if (err.message?.includes('UNIQUE constraint failed')) {
              return res.status(400).json({ error: 'Email or username already taken.' });
            }
            console.error('DB Error:', err);
            return res.status(500).json({ error: 'Database error' });
          }

          // Send verification email
          const verifyUrl = `${APP_URL}/api/verify-email?token=${verificationToken}`;
          await sendEmail(
            email,
            'Verify your Central Alberta After Dark account',
            `<p>Welcome to Central Alberta After Dark!</p>
             <p>Please verify your email address by clicking the link below:</p>
             <p><a href="${verifyUrl}">${verifyUrl}</a></p>
             <p>This link does not expire — but you must verify before you can log in.</p>`
          );

          res.status(201).json({
            success: true,
            message: 'Account created! Please check your email to verify your address before logging in.',
          });
        }
      );
    } catch (error) {
      console.error('Server Error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// ---------------------------------------------------------------------------
// Email verification
// ---------------------------------------------------------------------------
app.get('/api/verify-email', (req, res) => {
  const { token } = req.query;
  if (!token || typeof token !== 'string') {
    return res.status(400).json({ error: 'Invalid verification token.' });
  }

  db.run(
    `UPDATE users SET is_verified = 1, verification_token = NULL
     WHERE verification_token = ? AND is_verified = 0`,
    [token],
    function(err) {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (this.changes === 0) {
        return res.status(400).json({ error: 'Invalid or already-used verification token.' });
      }
      // Redirect to the homepage with a success flag the frontend can read
      res.redirect('/?verified=1');
    }
  );
});

// Resend verification email
app.post('/api/resend-verification', csrfProtection, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });

  db.get(
    `SELECT id, email, is_verified, verification_token FROM users WHERE email = ?`,
    [email.toLowerCase()],
    async (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      // Always return success to avoid user enumeration
      if (!user || user.is_verified) {
        return res.json({ success: true, message: 'If that address is registered and unverified, a new email has been sent.' });
      }

      const newToken = crypto.randomBytes(32).toString('hex');
      db.run(`UPDATE users SET verification_token = ? WHERE id = ?`, [newToken, user.id]);

      const verifyUrl = `${APP_URL}/api/verify-email?token=${newToken}`;
      await sendEmail(
        user.email,
        'Verify your Central Alberta After Dark account',
        `<p>Here is your new verification link:</p>
         <p><a href="${verifyUrl}">${verifyUrl}</a></p>`
      );

      res.json({ success: true, message: 'If that address is registered and unverified, a new email has been sent.' });
    }
  );
});

// ---------------------------------------------------------------------------
// Login — with session fixation fix, account lockout, and verified check
// ---------------------------------------------------------------------------
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes

app.post('/api/login',
  csrfProtection,
  body('username').isLength({ min: 3 }).withMessage('Invalid username'),
  body('password').exists().withMessage('Password required'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
    }

    const { username, password } = req.body;

    db.get(
      `SELECT id, username, password_hash, is_verified, failed_login_attempts, locked_until
       FROM users WHERE username = ?`,
      [username],
      async (err, user) => {
        if (err) {
          console.error('DB Error:', err);
          return res.status(500).json({ error: 'Database error' });
        }

        // Use a constant-time response to prevent user enumeration
        if (!user) {
          await bcrypt.hash('dummy-prevent-timing-attack', 12);
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Account lockout check
        const now = Date.now();
        if (user.locked_until && now < user.locked_until) {
          const minutesLeft = Math.ceil((user.locked_until - now) / 60000);
          return res.status(423).json({
            error: `Account locked due to too many failed attempts. Try again in ${minutesLeft} minute(s).`,
          });
        }

        // Email verification check
        if (!user.is_verified) {
          return res.status(403).json({
            error: 'Please verify your email address before logging in. Check your inbox or request a new verification email.',
          });
        }

        try {
          const match = await bcrypt.compare(password, user.password_hash);

          if (!match) {
            const newAttempts = (user.failed_login_attempts || 0) + 1;
            const shouldLock = newAttempts >= MAX_FAILED_ATTEMPTS;
            db.run(
              `UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?`,
              [newAttempts, shouldLock ? now + LOCKOUT_DURATION_MS : null, user.id]
            );
            if (shouldLock) {
              return res.status(423).json({ error: 'Too many failed attempts. Account locked for 15 minutes.' });
            }
            return res.status(401).json({ error: 'Invalid credentials' });
          }

          // Successful login — reset lockout counters
          db.run(
            `UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`,
            [user.id]
          );

          // Fix session fixation: regenerate session ID after authentication
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
  }
);

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed.' });
    }
    res.clearCookie('sessionId');
    res.json({ success: true, message: 'Logged out.' });
  });
});

// ---------------------------------------------------------------------------
// Password reset — request
// ---------------------------------------------------------------------------
app.post('/api/forgot-password', csrfProtection, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });

  // Always return success to prevent user enumeration
  const genericResponse = { success: true, message: 'If that email is registered, a reset link has been sent.' };

  db.get(`SELECT id, email FROM users WHERE email = ?`, [email.toLowerCase()], async (err, user) => {
    if (err) { console.error('DB Error:', err); }
    if (!user) return res.json(genericResponse);

    const resetToken = crypto.randomBytes(32).toString('hex');
    const expires = Date.now() + 60 * 60 * 1000; // 1 hour

    db.run(
      `UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?`,
      [resetToken, expires, user.id],
      async (err) => {
        if (err) { console.error('DB Error:', err); return res.json(genericResponse); }

        const resetUrl = `${APP_URL}/reset-password.html?token=${resetToken}`;
        await sendEmail(
          user.email,
          'Reset your Central Alberta After Dark password',
          `<p>You requested a password reset.</p>
           <p>Click the link below to set a new password. This link expires in 1 hour.</p>
           <p><a href="${resetUrl}">${resetUrl}</a></p>
           <p>If you did not request this, you can safely ignore this email.</p>`
        );

        res.json(genericResponse);
      }
    );
  });
});

// ---------------------------------------------------------------------------
// Password reset — confirm
// ---------------------------------------------------------------------------
app.post('/api/reset-password', csrfProtection, async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) {
    return res.status(400).json({ error: 'Token and new password are required.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  db.get(
    `SELECT id, reset_token_expires FROM users WHERE reset_token = ?`,
    [token],
    async (err, user) => {
      if (err) { console.error('DB Error:', err); return res.status(500).json({ error: 'Database error' }); }
      if (!user) return res.status(400).json({ error: 'Invalid or expired reset token.' });
      if (Date.now() > user.reset_token_expires) {
        return res.status(400).json({ error: 'Reset token has expired. Please request a new one.' });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 12);
        db.run(
          `UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL,
           failed_login_attempts = 0, locked_until = NULL WHERE id = ?`,
          [hashedPassword, user.id],
          (err) => {
            if (err) { console.error('DB Error:', err); return res.status(500).json({ error: 'Database error' }); }
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

// ---------------------------------------------------------------------------
// Profile & social endpoints
// ---------------------------------------------------------------------------
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
  const safeBio = bio ? sanitizeInput(bio) : null;
  const safeLocation = location ? sanitizeInput(location) : null;
  const safeShift = shift_schedule ? sanitizeInput(shift_schedule) : null;

  db.run(
    `UPDATE users SET bio = COALESCE(?, bio), location = COALESCE(?, location),
     shift_schedule = COALESCE(?, shift_schedule) WHERE id = ?`,
    [safeBio, safeLocation, safeShift, req.session.userId],
    function(err) {
      if (err) { console.error('DB Error:', err); return res.status(500).json({ error: 'Database error' }); }
      res.json({ success: true });
    }
  );
});

app.get('/api/profiles', (req, res) => {
  db.all(
    `SELECT id, username, age, location, bio FROM users
     WHERE is_verified = 1 AND (id != ? OR ? IS NULL)`,
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

  if (likedId === likerId) {
    return res.status(400).json({ error: 'Cannot like yourself' });
  }

  db.run(
    `INSERT OR IGNORE INTO likes (liker_id, liked_id) VALUES (?, ?)`, [likerId, likedId],
    function(err) {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      db.get(
        `SELECT * FROM likes WHERE liker_id = ? AND liked_id = ?`, [likedId, likerId],
        (err, reciprocal) => {
          if (err) {
            console.error('DB Error:', err);
            return res.status(500).json({ error: 'Database error' });
          }

          if (reciprocal) {
            const user1 = Math.min(likerId, likedId);
            const user2 = Math.max(likerId, likedId);
            db.run(
              `INSERT OR IGNORE INTO matches (user1_id, user2_id) VALUES (?, ?)`,
              [user1, user2],
              (err) => { if (err) console.error('Match creation error:', err); }
            );
            return res.json({ success: true, match: true, message: "It's a match!" });
          }

          res.json({ success: true, match: false, message: 'Liked!' });
        }
      );
    }
  );
});

// ---------------------------------------------------------------------------
// Stripe checkout
// ---------------------------------------------------------------------------
app.post('/create-checkout-session', requireAuth, csrfProtection, async (req, res) => {
  try {
    const prices = await stripe.prices.list({
      lookup_keys: [req.body.lookup_key],
      expand: ['data.product'],
    });
    if (!prices.data.length) {
      return res.status(400).json({ error: 'Invalid price lookup key.' });
    }
    const checkoutSession = await stripe.checkout.sessions.create({
      billing_address_collection: 'auto',
      line_items: [{ price: prices.data[0].id, quantity: 1 }],
      mode: 'subscription',
      client_reference_id: String(req.session.userId),
      success_url: `${APP_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${APP_URL}/cancel.html`,
    });
    res.redirect(303, checkoutSession.url);
  } catch (err) {
    console.error('Stripe error:', err);
    res.status(500).json({ error: 'Failed to create checkout session.' });
  }
});

// ---------------------------------------------------------------------------
// Stripe webhook — verifies signature, upgrades user on successful payment
// ---------------------------------------------------------------------------
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

  // Idempotency: skip already-processed events
  db.get(`SELECT id FROM webhook_events WHERE stripe_event_id = ?`, [event.id], (err, existing) => {
    if (err) { console.error('DB Error:', err); return res.status(500).send('Database error'); }
    if (existing) return res.json({ received: true }); // already handled

    db.run(
      `INSERT INTO webhook_events (stripe_event_id, event_type, payload) VALUES (?, ?, ?)`,
      [event.id, event.type, JSON.stringify(event.data.object)],
      (err) => { if (err) console.error('Webhook log error:', err); }
    );

    if (event.type === 'checkout.session.completed') {
      const checkoutSession = event.data.object;
      const userId = checkoutSession.client_reference_id;

      if (userId) {
        db.run(`UPDATE users SET is_premium = 1 WHERE id = ?`, [userId], (err) => {
          if (err) console.error('Failed to upgrade user:', err);
          else console.log(`User ${userId} upgraded to premium via Stripe webhook.`);
        });
      }
    }

    res.json({ received: true });
  });
});

// ---------------------------------------------------------------------------
// Static routes
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------------------------------------------------------------------------
// Global error handler — also handles CSRF token errors gracefully
// ---------------------------------------------------------------------------
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
