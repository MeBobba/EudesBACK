const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
const port = 3000;
const secretKey = 'yourSecretKey';

app.use(bodyParser.json());
app.use(cors());

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, x-access-token');
    next();
});

// Fonction pour obtenir l'IP du client
function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    return forwarded ? forwarded.split(',').shift() : req.connection.remoteAddress;
}

// Fonction pour générer des questions anti-robot
function generateAntiRobotQuestion() {
    const num1 = Math.floor(Math.random() * 10);
    const num2 = Math.floor(Math.random() * 10);
    return {
        question: `What is ${num1} + ${num2}?`,
        answer: num1 + num2
    };
}

// Inscription
app.post('/register', (req, res) => {
    const { username, password, mail } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    const account_created = Math.floor(Date.now() / 1000);
    const last_login = account_created;
    const motto = 'Nouveau sur MeBobba';
    const ip = getClientIp(req); // Utiliser la fonction pour obtenir l'IP

    db.query(
        'INSERT INTO users (username, password, mail, account_created, last_login, motto, ip_register, ip_current) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [username, hashedPassword, mail, account_created, last_login, motto, ip, ip],
        (err, result) => {
            if (err) return res.status(500).send('Server error');
            const token = jwt.sign({ id: result.insertId }, secretKey, { expiresIn: 86400 });
            res.status(200).send({ auth: true, token });
        }
    );
});

// Connexion
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Server error');
        }
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        const user = results[0];

        try {
            const passwordIsValid = await bcrypt.compare(password, user.password);
            if (!passwordIsValid) {
                return res.status(401).send('Invalid password');
            }

            if (user.is_logged_in) {
                return res.status(403).send('User already logged in');
            }

            const token = jwt.sign({ id: user.id, rank: user.rank }, secretKey, {
                expiresIn: 86400
            });

            db.query('UPDATE users SET is_logged_in = 1 WHERE id = ?', [user.id], (err, results) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).send('Server error');
                }
                res.status(200).send({ auth: true, token });
            });
        } catch (error) {
            console.error('Bcrypt error:', error);
            return res.status(500).send('Server error');
        }
    });
});

// Déconnexion
app.post('/logout', verifyToken, (req, res) => {
    db.query('UPDATE users SET is_logged_in = 0 WHERE id = ?', [req.userId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Server error');
        }
        res.status(200).send('User logged out successfully');
    });
});

// Tableau de bord utilisateur
app.get('/dashboard', verifyToken, (req, res) => {
    db.query('SELECT * FROM users WHERE id = ?', [req.userId], (err, results) => {
        if (err) return res.status(500).send('Server error');
        if (results.length === 0) return res.status(404).send('User not found');
        res.status(200).send(results[0]);
    });
});

// Vérification du nom d'utilisateur
app.post('/check-username', (req, res) => {
    const { username } = req.body;
    db.query('SELECT username FROM users WHERE username = ?', [username], (err, results) => {
        if (err) return res.status(500).send('Server error');
        res.status(200).send({ exists: results.length > 0 });
    });
});

// Vérification de l'email
app.post('/check-email', (req, res) => {
    const { email } = req.body;
    db.query('SELECT mail FROM users WHERE mail = ?', [email], (err, results) => {
        if (err) return res.status(500).send('Server error');
        res.status(200).send({ exists: results.length > 0 });
    });
});

// Endpoint pour obtenir une question anti-robot
app.get('/anti-robot-question', (req, res) => {
    const question = generateAntiRobotQuestion();
    res.status(200).send(question);
});

// Middleware de vérification du token
function verifyToken(req, res, next) {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(403).send('No token provided');

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) return res.status(500).send('Failed to authenticate token');
        req.userId = decoded.id;
        req.userRank = decoded.rank;
        next();
    });
}

// Gestion des erreurs 404
app.use((req, res, next) => {
    res.status(404).send('Not Found');
});

// Gestion des erreurs 500
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Server Error');
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
