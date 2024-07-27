const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const twofactor = require("node-2fa");
const qrcode = require('qrcode');
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

const fs = require('fs');
const path = require('path');

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
app.put('/users/:userId', verifyToken, async (req, res) => {
    const { userId } = req.params;
    const { rank, mail, motto } = req.body;

    try {
        const [result] = await db.query(
            'UPDATE users SET rank = ?, mail = ?, motto = ? WHERE id = ?',
            [rank, mail, motto, userId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).send('User not found');
        }

        const [updatedUser] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
        res.status(200).send(updatedUser[0]);
    } catch (err) {
        console.error('Error updating user:', err);
        res.status(500).send('Server error');
    }
});

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

// Endpoint pour obtenir les informations du portefeuille de l'utilisateur
app.get('/user/wallet', verifyToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT points, credits, pixels FROM users WHERE id = ?', [req.userId]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }
        res.status(200).send(results[0]);
    } catch (error) {
        console.error('Error fetching user wallet data:', error);
        res.status(500).send('Server error');
    }
});

// app.use((req, res, next) => {
//     res.header('Access-Control-Allow-Origin', '*');
//     res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, x-access-token');
//     next();
// });

// Endpoint pour vérifier l'existence d'une piste
app.get('/tracks/:spotifyId', async (req, res) => {
    const spotifyId = req.params.spotifyId;
    try {
        const [results] = await db.query('SELECT * FROM tracks WHERE spotify_id = ?', [spotifyId]);
        res.send({ exists: results.length > 0 });
    } catch (error) {
        console.error('Error checking track existence:', error);
        res.status(500).send('Server error');
    }
});

// Endpoint pour stocker une nouvelle piste
app.post('/tracks', async (req, res) => {
    const track = req.body;
    const query = 'INSERT INTO tracks (name, album_id, duration, spotify_popularity, spotify_id, description, image, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())';
    const values = [
        track.name,
        track.album_id,
        track.duration,
        track.spotify_popularity,
        track.spotify_id,
        track.description,
        track.image
    ];
    try {
        await db.query(query, values);
        res.status(201).send('Track stored successfully');
    } catch (error) {
        console.error('Error storing track:', error);
        res.status(500).send('Server error');
    }
});

// Endpoint pour les filtres de mots
app.get('/wordfilter', verifyToken, async (req, res) => {
    try {
        const [filters] = await db.query('SELECT * FROM wordfilter');
        res.status(200).send(filters);
    } catch (err) {
        console.error('Error fetching word filters:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour les histoires utilisateur (user stories)
app.get('/stories/:userId', verifyToken, async (req, res) => {
    const { userId } = req.params;
    try {
        const [stories] = await db.query('SELECT * FROM stories WHERE user_id = ?', [userId]);
        res.status(200).send(stories);
    } catch (err) {
        console.error('Error fetching stories:', err);
        res.status(500).send('Server error');
    }
});

app.get('/user/points', verifyToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT points FROM users WHERE id = ?', [req.userId]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }
        res.status(200).send({ points: results[0].points });
    } catch (error) {
        console.error('Error fetching user points:', error);
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

// Ajout de la route /check-2fa
app.get('/check-2fa', async (req, res) => {
    const { username } = req.query;
    try {
        const [results] = await db.query('SELECT is_2fa_enabled FROM users WHERE username = ?', [username]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        const user = results[0];
        res.status(200).send({ is2FAEnabled: user.is_2fa_enabled });
    } catch (err) {
        console.error('Error checking 2FA status:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour activer Google Authenticator
app.post('/enable-2fa', verifyToken, async (req, res) => {
    const [results] = await db.query('SELECT username FROM users WHERE id = ?', [req.userId]);
    const username = results[0].username;

    const { secret, uri} = twofactor.generateSecret({ name: 'MeBobba', account: username });

    try {
        await db.query('UPDATE users SET google_auth_secret = ? WHERE id = ?', [secret, req.userId]);
        qrcode.toDataURL(uri, (err, data_url) => {
            res.status(200).send({ secret: secret, dataURL: data_url });
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
        const [results] = await db.query('SELECT google_auth_secret FROM users WHERE id = ?', [req.userId]);
        const user = results[0];
        const verified = twofactor.verifyToken(user.google_auth_secret, token);
        if (verified) {
            await db.query('UPDATE users SET is_2fa_enabled = 1 WHERE id = ?', [req.userId]);
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
        await db.query('UPDATE users SET is_2fa_enabled = 0, google_auth_secret = NULL WHERE id = ?', [req.userId]);
        res.status(200).send('2FA disabled successfully');
    } catch (err) {
        console.error('Error disabling 2FA:', err);
        res.status(500).send('Server error');
    }
});

// Tableau de bord utilisateur
app.get('/dashboard', verifyToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM users WHERE id = ?', [req.userId]);
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
        const [results] = await db.query('SELECT username FROM users WHERE username = ?', [username]);
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
        const [results] = await db.query('SELECT mail FROM users WHERE mail = ?', [email]);
        res.status(200).send({ exists: results.length > 0 });
    } catch (err) {
        console.error('Error checking email:', err);
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

// Endpoint pour télécharger les données de l'utilisateur
app.get('/download-data', verifyToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM users WHERE id = ?', [req.userId]);
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
    const userId = req.userId;

    try {
        // Start a transaction
        await db.query('START TRANSACTION');

        // Delete likes made by the user
        await db.query(`DELETE
                        FROM likes
                        WHERE user_id = ?`, [userId]);

        // Delete related likes and comments of posts
        await db.query(`DELETE
                        FROM likes
                        WHERE post_id IN (SELECT id FROM posts WHERE user_id = ?)`, [userId]);
        await db.query(`DELETE
                        FROM comments
                        WHERE post_id IN (SELECT id FROM posts WHERE user_id = ?)`, [userId]);

        // Delete the posts
        await db.query(`DELETE
                        FROM posts
                        WHERE user_id = ?`, [userId]);

        // Delete related likes and comments of articles
        await db.query(`DELETE
                        FROM article_likes
                        WHERE article_id IN (SELECT id FROM articles WHERE user_id = ?)`, [userId]);
        await db.query(`DELETE
                        FROM article_comments
                        WHERE article_id IN (SELECT id FROM articles WHERE user_id = ?)`, [userId]);

        // Delete the articles
        await db.query(`DELETE
                        FROM articles
                        WHERE user_id = ?`, [userId]);

        // Delete from other related tables
        const tablesToDeleteFrom = [
            { table: 'bans', column: 'user_id' },
            { table: 'bots', column: 'user_id' },
            { table: 'calendar_rewards_claimed', column: 'user_id' },
            { table: 'camera_web', column: 'user_id' },
            { table: 'catalog_items_limited', column: 'user_id' },
            { table: 'chatlogs_private', columns: ['user_to_id', 'user_from_id'] },
            { table: 'chatlogs_room', columns: ['user_to_id', 'user_from_id'] },
            { table: 'commandlogs', column: 'user_id' },
            { table: 'guilds', column: 'user_id' },
            { table: 'guilds_forums_comments', column: 'user_id' },
            { table: 'guilds_forums_threads', column: 'opener_id' },
            { table: 'guilds_members', column: 'user_id' },
            { table: 'guild_forum_views', column: 'user_id' },
            { table: 'items', column: 'user_id' },
            { table: 'items_highscore_data', column: 'user_ids' },
            { table: 'logs_hc_payday', column: 'user_id' },
            { table: 'logs_shop_purchases', column: 'user_id' },
            { table: 'lottery_plays', column: 'user_id' },
            { table: 'marketplace_items', column: 'user_id' },
            { table: 'messenger_categories', column: 'user_id' },
            { table: 'messenger_friendrequests', columns: ['user_to_id', 'user_from_id'] },
            { table: 'messenger_friendships', columns: ['user_one_id', 'user_two_id'] },
            { table: 'messenger_offline', columns: ['user_id', 'user_from_id'] },
            { table: 'namechange_log', column: 'user_id' },
            { table: 'polls_answers', column: 'user_id' },
            { table: 'rooms', column: 'owner_id' },
            { table: 'room_bans', column: 'user_id' },
            { table: 'room_enter_log', column: 'user_id' },
            { table: 'room_game_scores', column: 'user_id' },
            { table: 'room_mutes', column: 'user_id' },
            { table: 'room_rights', column: 'user_id' },
            { table: 'room_trade_log', columns: ['user_two_id', 'user_one_id'] },
            { table: 'room_trade_log_items', column: 'user_id' },
            { table: 'room_votes', column: 'user_id' },
            { table: 'sanctions', column: 'habbo_id' },
            { table: 'stories', column: 'user_id' } // Added stories table
        ];

        for (const entry of tablesToDeleteFrom) {
            if (Array.isArray(entry.columns)) {
                for (const column of entry.columns) {
                    await db.query(`DELETE
                                    FROM ${entry.table}
                                    WHERE ${column} = ?`, [userId]);
                }
            } else {
                await db.query(`DELETE
                                FROM ${entry.table}
                                WHERE ${entry.column} = ?`, [userId]);
            }
        }

        // Delete the user account
        await db.query('DELETE FROM users WHERE id = ?', [userId]);

        // Commit the transaction
        await db.query('COMMIT');

        res.status(200).send('User account and related data deleted successfully');
    } catch (err) {
        await db.query('ROLLBACK');
        console.error('Error deleting user account:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour mettre à jour les données de l'utilisateur
app.put('/update-account', verifyToken, async (req, res) => {
    const { username, real_name, mail, motto, look, gender } = req.body;
    try {
        await db.query('UPDATE users SET username = ?, real_name = ?, mail = ?, motto = ?, look = ?, gender = ? WHERE id = ?',
            [username, real_name, mail, motto, look, gender, req.userId]);
        res.status(200).send('User account updated successfully');
    } catch (err) {
        console.error('Error updating user account:', err);
        res.status(500).send('Server error');
    }
});

app.get('/lyrics', async (req, res) => {
    const { q_track, q_artist } = req.query;
    try {
        const response = await axios.get(`https://api.musixmatch.com/ws/1.1/matcher.lyrics.get`, {
            params: {
                q_track,
                q_artist,
                apikey: process.env.MUSIXMATCH_API_KEY
            }
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).send('Error fetching lyrics');
    }
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

// Endpoint pour récupérer les photos de l'utilisateur
app.get('/user-photos', verifyToken, async (req, res) => {
    try {
        const [photos] = await db.query(
            'SELECT id, user_id, room_id, timestamp, url FROM camera_web WHERE user_id = ?',
            [req.userId]
        );
        res.status(200).send(photos);
    } catch (err) {
        console.error('Error fetching user photos:', err);
        res.status(500).send('Server error');
    }
});

// Route pour récupérer le profil de l'utilisateur courant
app.get('/profile/me', verifyToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM users WHERE id = ?', [req.userId]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }
        res.status(200).send(results[0]);
    } catch (err) {
        console.error('Error fetching user profile:', err);
        res.status(500).send('Server error');
    }
});

// Route pour récupérer le profil d'un utilisateur par ID
app.get('/profile/:userId', verifyToken, async (req, res) => {
    const { userId } = req.params;
    try {
        const [users] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
        if (users.length === 0) {
            return res.status(404).send('User not found');
        }
        res.status(200).send(users[0]);
    } catch (err) {
        console.error('Error fetching user profile:', err);
        res.status(500).send('Server error');
    }
});

// Ajout de la route pour la recherche d'utilisateurs
app.get('/search-users', verifyToken, async (req, res) => {
    const { query } = req.query;
    try {
        const [results] = await db.query('SELECT id, username FROM users WHERE username LIKE ?', [`%${query}%`]);
        res.status(200).send(results);
    } catch (err) {
        console.error('Error searching users:', err);
        res.status(500).send('Server error');
    }
});

// Tableau de bord utilisateur
app.get('/dashboard/:userId', verifyToken, async (req, res) => {
    const userId = req.params.userId === 'me' ? req.userId : req.params.userId;
    try {
        const [results] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }
        res.status(200).send(results[0]);
    } catch (err) {
        console.error('Error fetching dashboard data:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour récupérer les photos de l'utilisateur
app.get('/user-photos/:userId', verifyToken, async (req, res) => {
    const userId = req.params.userId === 'me' ? req.userId : req.params.userId;
    try {
        const [photos] = await db.query(
            'SELECT id, user_id, room_id, timestamp, url FROM camera_web WHERE user_id = ?',
            [userId]
        );
        res.status(200).send(photos);
    } catch (err) {
        console.error('Error fetching user photos:', err);
        res.status(500).send('Server error');
    }
});

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
