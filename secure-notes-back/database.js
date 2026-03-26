const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const db = new sqlite3.Database('./securenotes.db');

async function initDb() {
  db.serialize(async () => {

    // Création des tables
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      email           TEXT UNIQUE,
      password        TEXT,
      role            TEXT DEFAULT 'user',
      bio             TEXT,
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

    // Vérifier si l'admin existe déjà
    db.get(`SELECT * FROM users WHERE email = 'admin@example.com'`, async (err, row) => {
      if (err) {
        console.error("Erreur SELECT admin :", err);
        return;
      }

      if (!row) {
        console.log("Aucun admin trouvé, création d'un admin par défaut…");
        
        // hash du mot de passe admin 
        const hashAdmin = await bcrypt.hash('adminpass', 10);

        db.run(
          `INSERT INTO users (email, password, role) VALUES (?, ?, 'admin')`,
          ['admin@example.com', hashAdmin],
          (err) => {
            if (err) console.error("Erreur création admin :", err);
            else console.log("Admin créé");
          }
        );
      } else {
        console.log("Admin déjà présent ");
      }
    });

    // Vérifier si la base contient au moins 1 utilisateur
    db.get(`SELECT COUNT(*) as count FROM users`, async (err, row) => {
      if (err) return;

      if (row.count <= 1) {
        console.log("Base vide, insertion des utilisateurs de démo…");
        // hash des mots de passe des utilisateurs
        const hashUser = await bcrypt.hash('userpass', 10);
        const hashJeremy = await bcrypt.hash('jeremypass', 10);

        db.run(
          `INSERT INTO users (email, password, role) VALUES (?, ?, 'user')`,
          ['user@example.com', hashUser]
        );
        db.run(
          `INSERT INTO users (email, password, role) VALUES (?, ?, 'user')`,
          ['jeremy@example.com', hashJeremy]
        );

        db.run(
          `INSERT INTO notes (title, content, user_id) VALUES (?, ?, ?)`,
          ['Ma première note', 'Voici le texte de ma note.', 1]
        );

        console.log(" Comptes de démo ajoutés.");
      }
    });
  });
}

initDb();

module.exports = db;
