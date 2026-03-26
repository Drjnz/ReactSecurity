const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const db = new sqlite3.Database('./securenotes.db');

async function initDb() {
  db.serialize(async () => {

    // ── Création des tables ──────────────────────────────────
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      email           TEXT UNIQUE,
      password        TEXT,
      role            TEXT DEFAULT 'user',
      login_attempts  INTEGER DEFAULT 0,
      lock_until      INTEGER DEFAULT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS notes (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      title    TEXT,
      content  TEXT,
      user_id  INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // ── Vérification : on n'insère les données qu'une seule fois ──
    db.get(`SELECT COUNT(*) as count FROM users`, async (err, row) => {
      if (err || row.count > 0) return; // Déjà initialisé → on ne touche à rien

      const hashAdmin = await bcrypt.hash('adminpass', 10);
      const hashUser  = await bcrypt.hash('userpass', 10);
      const hashLucas = await bcrypt.hash('lucaspass', 10);

      // ── Utilisateurs ────────────────────────────────────────
      db.run(
        `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
        ['admin@example.com', hashAdmin, 'admin']
      );
      db.run(
        `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
        ['user@example.com', hashUser, 'user']   // ← rôle corrigé
      );
      db.run(
        `INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
        ['lucas@example.com', hashLucas, 'user']
      );

      // ── Notes de démo ────────────────────────────────────────
      db.run(
        `INSERT INTO notes (title, content, user_id) VALUES (?, ?, ?)`,
        ['Ma première note', 'Voici le texte de ma note.', 1]
      );

      console.log("✅ Base de données initialisée avec les comptes de démo.");
      console.log("   admin@example.com  / adminpass  (admin)");
      console.log("   user@example.com   / userpass   (user)");
      console.log("   lucas@example.com  / lucaspass  (user)");
    });
  });
}

initDb();

module.exports = db;