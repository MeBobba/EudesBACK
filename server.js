const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const db = require('./db');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const secretKey = process.env.SECRET_KEY || 'yourSecretKey';

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

// Fonction pour vérifier si un utilisateur est banni
async function checkBan(userId, ip, machineId) {
    try {
        const [results] = await db.promise().query(
            'SELECT * FROM bans WHERE (user_id = ? OR ip = ? OR machine_id = ?) AND (ban_expire = 0 OR ban_expire > UNIX_TIMESTAMP())',
            [userId, ip, machineId]
        );
        return results.length > 0;
    } catch (err) {
        console.error('Error checking ban status:', err);
        throw new Error('Server error');
    }
}

// Inscription
app.post('/register', async (req, res) => {
    const { username, password, mail, machine_id } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    const account_created = Math.floor(Date.now() / 1000);
    const last_login = account_created;
    const motto = 'Nouveau sur MeBobba';
    const ip = getClientIp(req);

    try {
        const [result] = await db.promise().query(
            'INSERT INTO users (username, password, mail, account_created, last_login, motto, ip_register, ip_current, machine_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [username, hashedPassword, mail, account_created, last_login, motto, ip, ip, machine_id]
        );
        const token = jwt.sign({ id: result.insertId }, secretKey, { expiresIn: '24h' });
        res.status(200).send({ auth: true, token });
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(500).send('Server error');
    }
});

// Connexion
app.post('/login', async (req, res) => {
    const { username, password, token2fa, machine_id } = req.body;
    const ip = getClientIp(req);

    try {
        const [results] = await db.promise().query('SELECT * FROM users WHERE username = ?', [username]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        const user = results[0];

        // Vérifier les bannissements
        const isBanned = await checkBan(user.id, ip, machine_id);
        if (isBanned) {
            return res.status(403).send('User is banned');
        }

        const passwordIsValid = await bcrypt.compare(password, user.password);
        if (!passwordIsValid) {
            return res.status(401).send('Invalid password');
        }

        if (user.is_logged_in) {
            return res.status(403).send('User already logged in');
        }

        // Vérifier le token 2FA si activé
        if (user.is_2fa_enabled) {
            const verified = speakeasy.totp.verify({
                secret: user.google_auth_secret,
                encoding: 'base32',
                token: token2fa,
                window: 1 // Permet une légère dérive temporelle
            });
            if (!verified) {
                return res.status(401).send('Invalid 2FA token');
            }
        }

        const token = jwt.sign({ id: user.id, rank: user.rank }, secretKey, { expiresIn: '24h' });

        await db.promise().query('UPDATE users SET is_logged_in = 1, machine_id = ? WHERE id = ?', [machine_id, user.id]);
        res.status(200).send({ auth: true, token });
    } catch (err) {
        console.error('Error logging in user:', err);
        res.status(500).send('Server error');
    }
});

// Déconnexion
app.post('/logout', verifyToken, async (req, res) => {
    try {
        await db.promise().query('UPDATE users SET is_logged_in = 0 WHERE id = ?', [req.userId]);
        res.status(200).send('User logged out successfully');
    } catch (err) {
        console.error('Error logging out user:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour activer Google Authenticator
app.post('/enable-2fa', verifyToken, async (req, res) => {
    const secret = speakeasy.generateSecret({ length: 20 });
    const url = speakeasy.otpauthURL({
        secret: secret.base32,
        label: 'MyApp',
        issuer: 'MyApp'
    });

    // Stocker le secret dans la base de données de l'utilisateur
    try {
        await db.promise().query('UPDATE users SET google_auth_secret = ? WHERE id = ?', [secret.base32, req.userId]);
        qrcode.toDataURL(url, (err, data_url) => {
            res.status(200).send({ secret: secret.base32, dataURL: data_url });
        });
    } catch (err) {
        console.error('Error enabling 2FA:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour vérifier le code Google Authenticator
app.post('/verify-2fa', verifyToken, async (req, res) => {
    const { token } = req.body;
    try {
        const [results] = await db.promise().query('SELECT google_auth_secret FROM users WHERE id = ?', [req.userId]);
        const user = results[0];
        const verified = speakeasy.totp.verify({
            secret: user.google_auth_secret,
            encoding: 'base32',
            token,
            window: 1 // Allow some time drift
        });
        if (verified) {
            await db.promise().query('UPDATE users SET is_2fa_enabled = 1 WHERE id = ?', [req.userId]);
            res.status(200).send('2FA enabled successfully');
        } else {
            res.status(400).send('Invalid token');
        }
    } catch (err) {
        console.error('Error verifying 2FA:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour désactiver Google Authenticator
app.post('/disable-2fa', verifyToken, async (req, res) => {
    try {
        await db.promise().query('UPDATE users SET is_2fa_enabled = 0, google_auth_secret = NULL WHERE id = ?', [req.userId]);
        res.status(200).send('2FA disabled successfully');
    } catch (err) {
        console.error('Error disabling 2FA:', err);
        res.status(500).send('Server error');
    }
});

// Tableau de bord utilisateur
app.get('/dashboard', verifyToken, async (req, res) => {
    try {
        const [results] = await db.promise().query('SELECT * FROM users WHERE id = ?', [req.userId]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }
        res.status(200).send(results[0]);
    } catch (err) {
        console.error('Error fetching dashboard data:', err);
        res.status(500).send('Server error');
    }
});

// Vérification du nom d'utilisateur
app.post('/check-username', async (req, res) => {
    const { username } = req.body;
    try {
        const [results] = await db.promise().query('SELECT username FROM users WHERE username = ?', [username]);
        res.status(200).send({ exists: results.length > 0 });
    } catch (err) {
        console.error('Error checking username:', err);
        res.status(500).send('Server error');
    }
});

// Vérification de l'email
app.post('/check-email', async (req, res) => {
    const { email } = req.body;
    try {
        const [results] = await db.promise().query('SELECT mail FROM users WHERE mail = ?', [email]);
        res.status(200).send({ exists: results.length > 0 });
    } catch (err) {
        console.error('Error checking email:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour obtenir une question anti-robot
app.get('/anti-robot-question', (req, res) => {
    const question = generateAntiRobotQuestion();
    res.status(200).send(question);
});

// Endpoint pour télécharger les données de l'utilisateur
app.get('/download-data', verifyToken, async (req, res) => {
    try {
        const [results] = await db.promise().query('SELECT * FROM users WHERE id = ?', [req.userId]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }
        res.status(200).json(results[0]);
    } catch (err) {
        console.error('Error downloading user data:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour supprimer le compte de l'utilisateur
app.delete('/delete-account', verifyToken, async (req, res) => {
    try {
        await db.promise().query('DELETE FROM users WHERE id = ?', [req.userId]);
        res.status(200).send('User account deleted successfully');
    } catch (err) {
        console.error('Error deleting user account:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour mettre à jour les données de l'utilisateur
app.put('/update-account', verifyToken, async (req, res) => {
    const { username, real_name, mail, motto, look, gender } = req.body;
    try {
        await db.promise().query('UPDATE users SET username = ?, real_name = ?, mail = ?, motto = ?, look = ?, gender = ? WHERE id = ?',
            [username, real_name, mail, motto, look, gender, req.userId]);
        res.status(200).send('User account updated successfully');
    } catch (err) {
        console.error('Error updating user account:', err);
        res.status(500).send('Server error');
    }
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
