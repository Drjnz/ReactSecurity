require('dotenv').config();
const fs = require('fs');
const jwt = require('jsonwebtoken');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const rateLimit = require("express-rate-limit");
const helmet = require('helmet');
const sanitizeHtml = require('sanitize-html');
const { body, validationResult } = require('express-validator');

const db = require('./database');
const authMiddleware = require('./middleware/auth');
const isAdmin = require('./middleware/isAdmin');


// MODULE 4 — Logging : utilitaire de traçabilité

function logSecurityEvent(message) {
  const line = `${new Date().toISOString()} — ${message}\n`;
  fs.appendFile('security.log', line, err => {
    if (err) console.error('Erreur écriture log :', err);
  });
}


// MODULE 2 — Message d'erreur générique (aucune fuite technique)

const INTERNAL_ERROR = { error: "Une erreur interne du serveur est survenue." };

const saltRounds = 10;
const app = express();

// Sécurité globale

app.use(helmet());

// CORS strict : seul le front React est autorisé
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  methods: ['GET', 'POST', 'PUT', 'DELETE']
}));

app.use(express.json());

// Rate limiting sur les routes d'authentification

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

// ROUTE : Inscription

app.post(
  '/api/auth/register',
  loginLimiter,
  [
    body('email')
      .isEmail()
      .withMessage("Format d'email invalide"),
    body('password')
      .isLength({ min: 8 })
      .withMessage('Le mot de passe doit faire au moins 8 caractères')
  ],
  async (req, res) => {

    // MODULE 1 — Validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    console.log("Tentative d'inscription pour :", email);

    try {
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const query = `INSERT INTO users (email, password, role) VALUES (?, ?, 'user')`;
      db.run(query, [email, hashedPassword], function (err) {
        if (err) {
          console.error("Erreur BDD /register :", err.message);
          return res.status(500).json(INTERNAL_ERROR);
        }
        res.status(201).json({ message: "Utilisateur créé avec succès" });
      });
    } catch (error) {
      console.error("Erreur hachage /register :", error);
      res.status(500).json(INTERNAL_ERROR);
    }
  }
);

// ROUTE : Connexion

app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { email, password } = req.body;
  const query = `SELECT * FROM users WHERE email = ?`;

  db.get(query, [email], async (err, user) => {
    if (err) {
      console.error("Erreur BDD /login :", err.message);
      return res.status(500).json(INTERNAL_ERROR);
    }

    if (!user) {
      return res.status(401).json({ error: "Identifiants incorrects" });
    }

    // MODULE 3 : Vérification du verrou temporel

    if (user.lock_until && Date.now() < user.lock_until) {
      const remaining = Math.ceil((user.lock_until - Date.now()) / 1000 / 60);
      logSecurityEvent(`SOFT_LOCK_REJECTED email=${user.email} remaining=${remaining}min`);
      return res.status(423).json({
        error: `Compte temporairement verrouillé. Réessayez dans ${remaining} minute(s).`
      });
    }

    try {
      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        const attempts = (user.login_attempts || 0) + 1;

        if (attempts >= 5) {
          const lockUntil = Date.now() + 15 * 60 * 1000;
          db.run(
            `UPDATE users SET login_attempts = 0, lock_until = ? WHERE id = ?`,
            [lockUntil, user.id],
            (updateErr) => {
              if (updateErr) {
                console.error("Erreur BDD lock :", updateErr.message);
                return res.status(500).json(INTERNAL_ERROR);
              }
              logSecurityEvent(`ACCOUNT_LOCKED email=${user.email} until=${new Date(lockUntil).toISOString()}`);
              return res.status(423).json({ error: "Compte verrouillé pendant 15 minutes." });
            }
          );
          return;
        }

        db.run(
          `UPDATE users SET login_attempts = ? WHERE id = ?`,
          [attempts, user.id],
          (updateErr) => {
            if (updateErr) {
              console.error("Erreur BDD attempts :", updateErr.message);
              return res.status(500).json(INTERNAL_ERROR);
            }
            return res.status(401).json({ error: `Identifiants incorrects (${attempts}/5 tentatives).` });
          }
        );
        return;
      }

      // Succès — remise à zéro des compteurs

      db.run(
        `UPDATE users SET login_attempts = 0, lock_until = NULL WHERE id = ?`,
        [user.id],
        (updateErr) => {
          if (updateErr) {
            console.error("Erreur BDD reset :", updateErr.message);
            return res.status(500).json(INTERNAL_ERROR);
          }

          // MODULE 4 — Log connexion réussie
          logSecurityEvent(`LOGIN_SUCCESS email=${user.email}`);

          // JWT avec rôle inclus

          const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
          );

          delete user.password;
          delete user.login_attempts;
          delete user.lock_until;

          res.json({
            message: "Connexion réussie",
            user: user,
            token: token
          });
        }
      );

    } catch (error) {
      console.error("Erreur bcrypt /login :", error);
      res.status(500).json(INTERNAL_ERROR);
    }
  });
});

// ROUTE : Récupérer les notes

app.get("/api/notes", authMiddleware, (req, res) => {
  const isAdminUser = req.user.role === 'admin';
  const query = isAdminUser
    ? "SELECT * FROM notes"
    : "SELECT * FROM notes WHERE user_id = ?";
  const params = isAdminUser ? [] : [req.user.id];

  db.all(query, params, (err, notes) => {
    if (err) {
      console.error("Erreur BDD GET /notes :", err.message);
      return res.status(500).json(INTERNAL_ERROR);
    }
    res.json(notes);
  });
});

// Créer une note

app.post("/api/notes", authMiddleware, (req, res) => {
  const { content } = req.body;
  const userId = req.user.id;

  if (!content) {
    return res.status(400).json({ error: "Le contenu de la note est obligatoire" });
  }

  // Sanitisation XSS

  const cleanContent = sanitizeHtml(content, {
    allowedTags: [],
    allowedAttributes: {}
  });

  const query = "INSERT INTO notes (content, user_id) VALUES (?, ?)";

  db.run(query, [cleanContent, userId], function (err) {
    if (err) {
      console.error("Erreur BDD POST /notes :", err.message);
      return res.status(500).json(INTERNAL_ERROR);
    }
    res.status(201).json({
      message: "Note ajoutée avec succès",
      note: { id: this.lastID, content: cleanContent, user_id: userId }
    });
  });
});

// Supprimer une note

app.delete("/api/notes/:id", authMiddleware, (req, res) => {
  const noteId = req.params.id;
  const userId = req.user.id;

  // IDOR : double condition id + user_id

  const query = "DELETE FROM notes WHERE id = ? AND user_id = ?";

  db.run(query, [noteId, userId], function (err) {
    if (err) {
      console.error("Erreur BDD DELETE /notes :", err.message);
      return res.status(500).json(INTERNAL_ERROR);
    }
    if (this.changes === 0) {
      return res.status(403).json({ error: "Suppression refusée : note introuvable ou non autorisée" });
    }
    res.status(200).json({ message: "Note supprimée avec succès" });
  });
});

// Module 3 : le droit à l'oubli — suppression de son compte par l'utilisateur

app.delete("/api/users/me", authMiddleware, (req, res) => {
  const userId = req.user.id;

  const query = "DELETE FROM users WHERE id = ?";

  db.run(query, [userId], function (err) {
    if (err) {
      console.error("Erreur lors de la suppression de l'utilisateur :", err);
      return res.status(500).json({ error: "Erreur serveur" });
    }

    res.status(200).json({ message: "Utilisateur supprimé avec succès" });
  });
});

// Mission 1 : L'Édition de Profil
// PUT /api/users/:id — mise à jour email et/ou bio

app.put('/api/users/:id',authMiddleware,[body('email').optional().isEmail().withMessage("L'email fourni n'est pas valide."),],(req, res) => {
    // Validation express-validator
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const targetId = parseInt(req.params.id, 10);

    // Un utilisateur ne peut modifier que son propre profil
    if (req.user.id !== targetId) {
      return res.status(403).json({
        error: "Accès refusé : vous ne pouvez modifier que votre propre profil."
      });
    }

    const { email, bio } = req.body;

    // Nettoyage de la bio avec sanitize-html (texte riche accepté mais sécurisé)
    const cleanBio = bio !== undefined
      ? sanitizeHtml(bio, {
          allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'li'],
          allowedAttributes: { a: ['href'] },
        })
      : undefined;

    // Construction dynamique de la requête UPDATE
    const fields = [];
    const values = [];

    if (email !== undefined) {
      fields.push('email = ?');
      values.push(email);
    }
    if (cleanBio !== undefined) {
      fields.push('bio = ?');
      values.push(cleanBio);
    }

    if (fields.length === 0) {
      return res.status(400).json({ error: "Aucun champ à mettre à jour." });
    }

    values.push(targetId);

    db.run(
      `UPDATE users SET ${fields.join(', ')} WHERE id = ?`,
      values,
      function (err) {
        if (err) {
          console.error("Erreur BDD PUT /users/:id :", err.message);
          return res.status(500).json(INTERNAL_ERROR);
        }
        if (this.changes === 0) {
          return res.status(404).json({ error: "Utilisateur introuvable." });
        }
        res.json({ message: "Profil mis à jour avec succès." });
      }
    );
  }
);
// ─────────────────────────────────────────────
// Mission 2 : Le Verrouillage du Back-Office
// GET /api/admin/users — liste tous les utilisateurs
// Protégée : token JWT valide + rôle admin requis
// CORS strict : accessible uniquement depuis le front React
// ─────────────────────────────────────────────
app.get('/api/admin/users', authMiddleware, isAdmin, (req, res) => {
  const query = "SELECT id, email, role, bio FROM users ORDER BY id ASC";

  db.all(query, [], (err, users) => {
    if (err) {
      console.error("Erreur BDD GET /api/admin/users :", err.message);
      return res.status(500).json(INTERNAL_ERROR);
    }
    res.json({ users });
  });
});

// Mission 2 : Le Verrouillage du Back-Office
// GET /api/admin/users — liste tous les utilisateurs
// Protégée : token JWT valide + rôle admin requis
// CORS strict : accessible uniquement depuis le front React

app.get('/api/admin/users', authMiddleware, isAdmin, (req, res) => {
  const query = "SELECT id, email, role, bio FROM users ORDER BY id ASC";

  db.all(query, [], (err, users) => {
    if (err) {
      console.error("Erreur BDD GET /api/admin/users :", err.message);
      return res.status(500).json(INTERNAL_ERROR);
    }
    res.json({ users });
  });
});

// Liste des utilisateurs (admin)
app.get('/api/users', authMiddleware, isAdmin, (req, res) => {
  const query = "SELECT id, email, role FROM users";
  db.all(query, [], (err, users) => {
    if (err) {
      console.error("Erreur BDD GET /users :", err.message);
      return res.status(500).json(INTERNAL_ERROR);
    }
    res.json(users);
  });
});

/*app.put('/api/users/:id/role', authMiddleware, isAdmin, (req, res) => {
  const userId = req.params.id;
  const { role } = req.body;

  const query = "UPDATE users SET role = ? WHERE id = ?";

  db.run(query, [role, userId], function (err) {
    if (err) {
      console.error("Erreur BDD PUT /users/:id/role :", err.message);
      return res.status(500).json(INTERNAL_ERROR);
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: "Utilisateur non trouvé" });
    }
    res.json({ message: "Rôle mis à jour avec succès" });
  });
});
*/
// Démarrage du serveur

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Serveur Back-end démarré sur http://localhost:${PORT}`);
});