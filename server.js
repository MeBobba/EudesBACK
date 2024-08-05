const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();
const http = require('http');
const authRoutes = require('./routes/authRoutes');
const articleRoutes = require('./routes/articleRoutes');
const postRoutes = require('./routes/postRoutes');
const gameRoutes = require('./routes/gameRoutes');
const shopRoutes = require('./routes/shopRoutes');
const paymentRoutes = require('./routes/paymentRoutes');
const userRoutes = require('./routes/userRoutes');
const musicRoutes = require('./routes/musicRoutes');
const staffRoutes = require('./routes/staffRoutes');
const maintenanceRoutes = require('./routes/maintenanceRoutes');
const headerRoutes = require('./routes/headerRoutes');
const {initializeSocket} = require("./socket");

const app = express();
const server = http.createServer(app);

// initialize socket.io
initializeSocket(server);

const port = process.env.PORT || 3000;

// Augmente la taille maximale des requêtes JSON à 50 Mo
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
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
// routes pour le staff
app.use('/staff', staffRoutes);
// routes pour la maintenance
app.use('/maintenance', maintenanceRoutes);
// routes pour le header
app.use('/headerimages', headerRoutes);

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