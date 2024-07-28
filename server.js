const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const db = require('./db');
const http = require('http');
const socketIo = require('socket.io');
const authRoutes = require('./routes/authRoutes');
const articleRoutes = require('./routes/articleRoutes');
const postRoutes = require('./routes/postRoutes');
const gameRoutes = require('./routes/gameRoutes');
const shopRoutes = require('./routes/shopRoutes');
const paymentRoutes = require('./routes/paymentRoutes');
const userRoutes = require('./routes/userRoutes');
const musicRoutes = require('./routes/musicRoutes');
const {getClientIp} = require("./utils");

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: process.env.FRONTEND_URL,
        methods: ["GET", "POST"]
    }
});

const port = process.env.PORT || 3000;
const secretKey = process.env.SECRET_KEY || 'yourSecretKey';

app.use(bodyParser.json());
// CORS frontend
app.use(cors({
    origin: process.env.FRONTEND_URL,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Origin", "X-Requested-With", "Content-Type", "Accept", "x-access-token"]
}));

app.use((req, res, next) => {
    req.setTimeout(0); // Désactive le timeout pour chaque requête
    next();
});

// Endpoint pour mettre à jour les informations d'un utilisateur
// todo: reactiver ça sinon la page staff marche plus
// app.put('/users/:userId', verifyToken, async (req, res) => {
//     const { userId } = req.params;
//     const { rank, mail, motto } = req.body;
//
//     try {
//         const [result] = await db.query(
//             'UPDATE users SET rank = ?, mail = ?, motto = ? WHERE id = ?',
//             [rank, mail, motto, userId]
//         );
//
//         if (result.affectedRows === 0) {
//             return res.status(404).send('User not found');
//         }
//
//         const [updatedUser] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
//         res.status(200).send(updatedUser[0]);
//     } catch (err) {
//         console.error('Error updating user:', err);
//         res.status(500).send('Server error');
//     }
// });

app.get('/maintenance-status', async (req, res) => {
    try {
        const [results] = await db.query("SELECT `value` FROM `emulator_settings` WHERE `key` = 'website.maintenance'");
        const isMaintenance = results.length > 0 && results[0].value === '1';

        // Notify clients if maintenance mode is enabled
        if (isMaintenance) {
            io.emit('maintenance', true);
        }

        res.status(200).send({ maintenance: isMaintenance });
    } catch (error) {
        console.error('Error fetching maintenance status:', error);
        res.status(500).send('Server error');
    }
});

// Endpoint pour récupérer les informations du staff avec noms de rangs
app.get('/staff', verifyToken, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;
    try {
        const [ranks] = await db.query(
            'SELECT * FROM permissions WHERE level >= 5 ORDER BY level DESC'
        );

        const [users] = await db.query(
            'SELECT * FROM users WHERE rank >= 5 ORDER BY rank DESC LIMIT ? OFFSET ?',
            [limit, offset]
        );

        const staffSections = ranks.map(rank => {
            return { rank_name: rank.rank_name, rank_level: rank.level, users: users.filter(user => user.rank === rank.level) };
        }).filter(section => section.users.length > 0);

        res.status(200).send({ staffSections, ranks });
    } catch (err) {
        console.error('Error fetching staff data:', err);
        res.status(500).send('Server error');
    }
});

// Ajout de la route /check-ban
app.get('/check-ban', verifyToken, async (req, res) => {
    const ip = getClientIp(req);
    const machineId = req.headers['machine-id'];
    try {
        const isBanned = await checkBan(req.userId, ip, machineId);
        if (isBanned) {
            return res.status(403).send('User is banned');
        }
        res.status(200).send('User is not banned');
    } catch (err) {
        console.error('Error checking ban status:', err);
        res.status(500).send('Server error');
    }
});

// Fonction pour générer des questions anti-robot
function generateAntiRobotQuestion() {
    const num1 = Math.floor(Math.random() * 10);
    const num2 = Math.floor(Math.random() * 10);
    return {
        question: `What is ${num1} + ${num2}?`,
        answer: num1 + num2
    };
}

// Endpoint pour obtenir une question anti-robot
app.get('/anti-robot-question', (req, res) => {
    const question = generateAntiRobotQuestion();
    res.status(200).send(question);
});

// Endpoint pour récupérer les posts de l'utilisateur
// todo: à quoi ça sert ?? c'est pas sur le front
// app.get('/posts', verifyToken, async (req, res) => {
//     try {
//         const [posts] = await db.query(
//             `SELECT posts.*,
//                     users.username,
//                     users.look,
//                     COALESCE(likesCount.likesCount, 0)       as likesCount,
//                     COALESCE(commentsCount.commentsCount, 0) as commentsCount,
//                     userLikes.is_like                        as userLike
//              FROM posts
//                       JOIN users ON posts.user_id = users.id
//                       LEFT JOIN (SELECT post_id, COUNT(*) as likesCount
//                                  FROM likes
//                                  WHERE is_like = true
//                                  GROUP BY post_id) likesCount ON posts.id = likesCount.post_id
//                       LEFT JOIN (SELECT post_id, COUNT(*) as commentsCount
//                                  FROM comments
//                                  GROUP BY post_id) commentsCount ON posts.id = commentsCount.post_id
//                       LEFT JOIN (SELECT post_id, is_like
//                                  FROM likes
//                                  WHERE user_id = ?) userLikes ON posts.id = userLikes.post_id
//              WHERE posts.user_id = ?
//                 OR posts.visibility = "public"
//                 OR (posts.visibility = "friends" AND posts.user_id IN (SELECT CASE
//                                                                                   WHEN user_one_id = ? THEN user_two_id
//                                                                                   WHEN user_two_id = ? THEN user_one_id
//                                                                                   END AS friend_id
//                                                                        FROM messenger_friendships
//                                                                        WHERE user_one_id = ?
//                                                                           OR user_two_id = ?))
//              ORDER BY posts.created_at DESC`,
//             [req.userId, req.userId, req.userId, req.userId, req.userId, req.userId]
//         );
//
//         for (let post of posts) {
//             const [comments] = await db.query(
//                 `SELECT comments.*, users.username, users.look
//                  FROM comments
//                           JOIN users ON comments.user_id = users.id
//                  WHERE comments.post_id = ?
//                  ORDER BY comments.created_at DESC`,
//                 [post.id]
//             );
//             post.comments = comments;
//         }
//
//         res.status(200).send(posts);
//     } catch (err) {
//         console.error('Error fetching posts:', err);
//         res.status(500).send('Server error');
//     }
// });

// Middleware de vérification du token
function verifyToken(req, res, next) {
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
}

// gestion des routes par modules
// routes pour authentification
app.use('/auth', authRoutes);
// routes pour les articles
app.use('/articles', articleRoutes);
// route pour les posts
app.use('/posts', postRoutes);
// routes pour les jeux
app.use('/games', gameRoutes);
// routes pour la boutique
app.use('/shop', shopRoutes);
// routes pour le paiement
app.use('/payment', paymentRoutes);
// routes pour les utilisateurs
app.use('/users', userRoutes);
// routes pour musique
app.use('/music', musicRoutes);

// Gestion des erreurs 404
app.use((req, res, next) => {
    res.status(404).send('Not Found');
});

// Gestion des erreurs 500
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Server Error');
});

server.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
