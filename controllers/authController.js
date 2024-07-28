const db = require("../db");
const bcrypt = require("bcryptjs");
const twofactor = require("node-2fa");
const jwt = require("jsonwebtoken");
const {getClientIp, checkBan} = require("../utils");

const secretKey = process.env.SECRET_KEY || 'yourSecretKey';

exports.login = async (req, res) => {
    const {username, password, token2fa, machine_id} = req.body;
    const ip = getClientIp(req);

    try {
        // TODO: implémenter validation schema avec yup pour que ce soit plus simple
        // Si pas de nom d'utilisateur, retourner une erreur
        if (!username) {
            return res.status(400).send('Username is required');
        }

        // Si pas de mot de passe, retourner une erreur
        if (!password) {
            return res.status(400).send('Password is required');
        }

        const [results] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        const user = results[0];

        // Vérifier les bannissements
        const isBanned = await checkBan(user.id, ip, machine_id);
        if (isBanned) {
            return res.status(403).send('User is banned');
        }

        // Vérifier le mot de passe
        const passwordIsValid = await bcrypt.compare(password, user.password);
        if (!passwordIsValid) {
            return res.status(401).send('Invalid password');
        }

        // Vérifier le token 2FA si activé
        if (user.is_2fa_enabled) {
            const verified = twofactor.verifyToken(user.google_auth_secret, token2fa);
            if (!verified) {
                return res.status(401).send('Invalid 2FA token');
            }
        }

        const token = jwt.sign({id: user.id, rank: user.rank}, secretKey, {expiresIn: '24h'});

        await db.query('UPDATE users SET machine_id = ? WHERE id = ?', [machine_id, user.id]);
        res.status(200).send({auth: true, token});
    } catch (err) {
        console.error('Error logging in user:', err);
        res.status(500).send('Server error');
    }
};

exports.logout = async (req, res) => {
    try {
        await db.query('UPDATE users SET is_logged_in = 0 WHERE id = ?', [req.userId]);
        res.status(200).send('User logged out successfully');
    } catch (err) {
        console.error('Error logging out user:', err);
        res.status(500).send('Server error');
    }
};

exports.register = async (req, res) => {
    const {username, password, mail, machine_id} = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    const account_created = Math.floor(Date.now() / 1000);
    const last_login = account_created;
    const motto = 'Nouveau sur MeBobba';
    const ip = getClientIp(req);

    try {
        const [result] = await db.query(
            'INSERT INTO users (username, password, mail, account_created, last_login, motto, ip_register, ip_current, machine_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [username, hashedPassword, mail, account_created, last_login, motto, ip, ip, machine_id]
        );
        const token = jwt.sign({id: result.insertId}, secretKey, {expiresIn: '24h'});
        res.status(200).send({auth: true, token});
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(500).send('Server error');
    }
};

exports.checkSession = (req, res) => {
    res.status(200).send({valid: true});
};

function generateAntiRobotQuestion() {
    const num1 = Math.floor(Math.random() * 10);
    const num2 = Math.floor(Math.random() * 10);
    return {
        question: `What is ${num1} + ${num2}?`,
        answer: num1 + num2
    };
}

exports.generateAntiRobotQuestion = (req, res) => {
    const question = generateAntiRobotQuestion();
    res.status(200).send(question);
};