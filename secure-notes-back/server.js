const express = require('express');
const cors = require('cors');
const app = express();
const db = require('./database');
const bcrypt = require('bcrypt'); 
app.use(cors());
app.use(express.json());
const saltRounds = 10; 

app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    console.log("Tentative d'inscription pour :", email);
    
    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const query = `INSERT INTO users (email, password) VALUES (?, ?)`;
        db.run(query, [email, hashedPassword], function(err) {
            if (err) {
                console.error("Erreur base de données :", err.message);
                return res.status(500).json({ error: "Erreur lors de l'inscription" }); 
            }
            res.status(201).json({ message: "Utilisateur créé avec succès" });
        });
    } catch (error) {
        console.error("Erreur lors du hachage :", error);
        res.status(500).json({ error: "Erreur serveur lors de la création du compte" });
    }
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    const query = `SELECT * FROM users WHERE email = ?`;
    
    db.get(query, [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: "Erreur serveur" });
        }

        if (!user) {
            return res.status(401).json({ error: "Identifiants incorrects" });
        }
        
        try {
            const match = await bcrypt.compare(password, user.password);
            
            if (match) {
                const { password: userPassword, ...safeUser } = user;
                res.json({ user: safeUser, token: 'super-faux-token' });
            } else {
                res.status(401).json({ error: "Identifiants incorrects" });
            }
        } catch (error) {
            console.error("Erreur lors de la comparaison :", error);
            res.status(500).json({ error: "Erreur serveur" });
        }
    });
});

app.get('/api/notes', (req, res) => {
    console.log("React demande la liste des notes !");
    res.json([
        {
            id: 1,
            content: 'Ceci est une fausse note envoyée par le serveur !',
            authorId: 2
        }
    ]);
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`🚀 Serveur Back-end démarré sur http://localhost:${PORT}`);
});