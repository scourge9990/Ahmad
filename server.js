const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss');
const { body, validationResult } = require('express-validator');
const path = require('path');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)

const app = express();
const PORT = process.env.PORT || 3000;

const SESSION_SECRET = process.env.SESSION_SECRET || 'central-alberta-night-life-secret-key';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP.' },
});

app.use('/api/login', loginLimiter);
app.use('/api/', apiLimiter);

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static('public'));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sessionId',
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'strict',
  },
}));

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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

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

  console.log('Database tables initialized.');
});

function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return xss(input, {
    whiteList: {},
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script', 'style'] });
}

app.use((req, res, next) => {
  if (req.body) {
    try {
      Object.keys(req.body).forEach(key => {
        if (typeof req.body === 'string') {
          req.body = sanitizeInput(req.body );
        }
      });
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

app.post('/api/register',
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('username').isLength({ min: 3, max: 20 }).matches(/^ +$/).withMessage('Username: 3-20 chars, letters/numbers/underscore only'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
    body('age').optional().isInt({ min: 18, max: 120 }).withMessage('Age must be 18-120'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
    }

    const { email, username, password, age, location } = req.body;

    try {
      const hashedPassword = await bcrypt.hash(password, 10);

      db.run(
        `INSERT INTO users (email, username, password_hash, age, location) VALUES (?, ?, ?, ?, ?)`,
        [email?.toLowerCase(), username, hashedPassword, age, location || null],
        function(err) {
          if (err) {
            if (err.message?.includes('UNIQUE constraint failed')) {
              return res.status(400).json({ error: 'Email or username already taken.' });
            }
            console.error('DB Error:', err);
            return res.status(500).json({ error: 'Database error' });
          }

          res.status(201).json({
            success: true,
            userId: this.lastID,
            message: 'Account created! Please log in.',
          });
        }
      );
    } catch (error) {
      console.error('Server Error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

app.post('/api/login',
  body('username').isLength({ min: 3 }).withMessage('Invalid username'),
  body('password').exists().withMessage('Password required'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
    }

    const { username, password } = req.body;

    db.get(`SELECT id, username, password_hash FROM users WHERE username = ?`, [username], async (err, user) => {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      try {
        const match = await bcrypt.compare(password, user.password_hash);
        if (match) {
          req.session.userId = user.id;
          req.session.username = user.username;
          res.json({ success: true, username: user.username });
        } else {
          res.status(401).json({ error: 'Invalid credentials' });
        }
      } catch (error) {
        console.error('Bcrypt Error:', error);
        res.status(500).json({ error: 'Server error' });
      }
    });
  }
);

app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed.' });
    }
    res.json({ success: true, message: 'Logged out.' });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  db.get(
    `SELECT id, username, email, age, location, is_premium, created_at FROM users WHERE id = ?`, [req.session.userId],
    (err, user) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json(user);
    }
  );
});

app.get('/api/profiles', (req, res) => {
  db.all(
    `SELECT id, username, age, location, bio FROM users WHERE id != ? OR ? IS NULL`,
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

app.post('/api/like/:id', requireAuth, (req, res) => {
  const likedId = req.params.id;
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
        `SELECT * FROM likes WHERE liker_id = ? AND liked_id = ?`, [likerId, likedId],
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
              (err) => {
                if (err) console.error('Match creation error:', err);
              }
            );
            
            return res.json({ success: true, match: true, message: "It's a match!" });
          }

          res.json({ success: true, match: false, message: "Liked!" });
        }
      );
    }
  );
});

// NEW: Stripe subscription checkout endpoint
app.post('/create-checkout-session', async (req, res) => {
  const prices = await stripe.prices.list({
    lookup_keys: [req.body.lookup_key],
    expand: ['data.product'],
  });
  const session = await stripe.checkout.sessions.create({
    billing_address_collection: 'auto',
    line_items: [
      {
        price: prices.data[0].id,
        // For usage-based billing, don't pass quantity
        quantity: 1,

      },
    ],
    mode: 'subscription',
    success_url: `https://www.centralalbertaafterdark.com/success.html?session_id={CHECKOUT_SESSION_ID}`,
  });

  res.redirect(303, session.url);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Central Alberta Night Life server running on http://localhost:${PORT}`);
});
