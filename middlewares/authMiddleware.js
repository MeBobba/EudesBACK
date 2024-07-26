const jwt = require('jsonwebtoken');
const db = require('../db');
require('dotenv').config();

const secretKey = process.env.SECRET_KEY || 'yourSecretKey';

exports.verifyToken = (req, res, next) => {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(403).send('No token provided');

    jwt.verify(token, secretKey, async (err, decoded) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                // Mettre à jour is_logged_in à 0 lorsque le token est expiré
                try {
                    await db.query('UPDATE users SET is_logged_in = 0 WHERE id = ?', [decoded.id]);
                } catch (updateErr) {
                    console.error('Error updating is_logged_in on token expiration:', updateErr);
                }
                return res.status(401).send('Token expired');
            } else {
                return res.status(500).send('Failed to authenticate token');
            }
        }
        req.userId = decoded.id;
        req.userRank = decoded.rank;
        next();
    });
};
