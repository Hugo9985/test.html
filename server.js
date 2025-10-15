// server.js
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const bodyParser = require("body-parser");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const nodemailer = require("nodemailer");
const path = require("path");
const helmet = require("helmet");
const csrf = require("csurf");

const app = express();
const db = new sqlite3.Database("./database.sqlite");

const PORT = process.env.PORT || 3000;
const SESSION_SECRET =
  process.env.SESSION_SECRET || "change_this_secret_in_prod";

// --- Init DB ---
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password_hash TEXT,
    totp_secret TEXT,
    is_2fa_enabled INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// --- Middleware ---
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false }, // secure:true only with HTTPS
  })
);
const csrfProtection = csrf();
app.use("/public", express.static(path.join(__dirname, "public")));
app.use("/", express.static(path.join(__dirname, "public")));

// Simple auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ error: "Not authenticated" });
}

// --- Email transport (configure via env) ---
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.example.com",
  port: process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER || "user@example.com",
    pass: process.env.SMTP_PASS || "smtp-password",
  },
});

// --- Routes API (JSON) ---

// Register
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });
  try {
    const saltRounds = 12;
    const hash = await bcrypt.hash(password, saltRounds);
    db.run(
      "INSERT INTO users (email, password_hash) VALUES (?, ?)",
      [email, hash],
      function (err) {
        if (err) {
          if (err.code === "SQLITE_CONSTRAINT")
            return res.status(409).json({ error: "Email already used" });
          console.error(err);
          return res.status(500).json({ error: "Database error" });
        }
        // Optionally send welcome email (non blocking)
        // transporter.sendMail({ from: 'no-reply@example.com', to: email, subject: 'Bienvenue', text: 'Thanks' }).catch(console.error);
        return res.json({ success: true, userId: this.lastID });
      }
    );
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

// Login step 1: verify credentials
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });
  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "DB error" });
    }
    if (!user) return res.status(401).json({ error: "Invalid credentials" });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    // If 2FA enabled -> require TOTP code
    if (user.is_2fa_enabled) {
      // set a temporary session flag to indicate credential validated but 2FA pending
      req.session.tempUserId = user.id;
      return res.json({ twoFactorRequired: true });
    }

    // full login
    req.session.userId = user.id;
    return res.json({ success: true });
  });
});

// Verify TOTP and complete login
app.post("/api/login/2fa", (req, res) => {
  const { token } = req.body;
  const tempId = req.session.tempUserId;
  if (!tempId) return res.status(400).json({ error: "No pending 2FA" });
  db.get("SELECT * FROM users WHERE id = ?", [tempId], (err, user) => {
    if (err || !user) return res.status(400).json({ error: "Invalid session" });
    const verified = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: "base32",
      token,
      window: 1,
    });
    if (!verified) return res.status(401).json({ error: "Invalid 2FA token" });
    // complete login
    req.session.userId = user.id;
    delete req.session.tempUserId;
    return res.json({ success: true });
  });
});

// Get current user profile
app.get("/api/me", (req, res) => {
  const id = req.session.userId;
  if (!id) return res.status(401).json({ error: "Not authenticated" });
  db.get(
    "SELECT id, email, is_2fa_enabled, created_at FROM users WHERE id = ?",
    [id],
    (err, row) => {
      if (err || !row) return res.status(500).json({ error: "DB error" });
      res.json({ user: row });
    }
  );
});

// Logout
app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error(err);
    res.json({ success: true });
  });
});

// Setup 2FA - generate secret and QR (must be authenticated)
app.post("/api/2fa/setup", requireAuth, (req, res) => {
  const userId = req.session.userId;
  // generate secret
  const secret = speakeasy.generateSecret({ length: 20 });
  const otpauth = speakeasy.otpauthURL({
    secret: secret.base32,
    label: `MyApp:${userId}`,
    algorithm: "sha1",
  });
  qrcode.toDataURL(otpauth, (err, dataUrl) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "QR generation failed" });
    }
    // Store temp secret in session until user verifies code
    req.session.totpTempSecret = secret.base32;
    res.json({ qr: dataUrl, secret: secret.base32 });
  });
});

// Verify 2FA setup and enable
app.post("/api/2fa/verify-setup", requireAuth, (req, res) => {
  const { token } = req.body;
  const userId = req.session.userId;
  const secret = req.session.totpTempSecret;
  if (!secret)
    return res.status(400).json({ error: "No TOTP setup initiated" });
  const verified = speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token,
    window: 1,
  });
  if (!verified) return res.status(401).json({ error: "Invalid token" });
  // persist secret and enable 2FA
  db.run(
    "UPDATE users SET totp_secret = ?, is_2fa_enabled = 1 WHERE id = ?",
    [secret, userId],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "DB error" });
      }
      delete req.session.totpTempSecret;
      res.json({ success: true });
    }
  );
});

// Disable 2FA
app.post("/api/2fa/disable", requireAuth, (req, res) => {
  const { password, token } = req.body;
  const userId = req.session.userId;
  db.get("SELECT * FROM users WHERE id = ?", [userId], async (err, user) => {
    if (err || !user) return res.status(500).json({ error: "DB error" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid password" });
    const validToken = speakeasy.totp.verify({
      secret: user.totp_secret,
      encoding: "base32",
      token,
      window: 1,
    });
    if (!validToken)
      return res.status(401).json({ error: "Invalid 2FA token" });
    db.run(
      "UPDATE users SET totp_secret = NULL, is_2fa_enabled = 0 WHERE id = ?",
      [userId],
      function (err2) {
        if (err2) return res.status(500).json({ error: "DB error" });
        res.json({ success: true });
      }
    );
  });
});

// Fallback
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
