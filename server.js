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
        const [results] = await db.promise().query('SELECT is_2fa_enabled FROM users WHERE username = ?', [username]);
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
        label: 'MeBobba',
        issuer: 'Eudes'
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

// Endpoint pour créer un nouveau post
app.post('/posts', verifyToken, async (req, res) => {
    const { content, image, video, visibility } = req.body;
    try {
        const [result] = await db.promise().query(
            'INSERT INTO posts (user_id, content, image, video, visibility) VALUES (?, ?, ?, ?, ?)',
            [req.userId, content, image, video, visibility]
        );

        const [newPost] = await db.promise().query(
            `SELECT posts.*, users.username, users.look
            FROM posts
            JOIN users ON posts.user_id = users.id
            WHERE posts.id = ?`,
            [result.insertId]
        );

        res.status(201).send(newPost[0]);
    } catch (err) {
        console.error('Error creating post:', err);
        res.status(500).send('Server error');
    }
});


// Endpoint pour récupérer les posts de l'utilisateur
app.get('/posts', verifyToken, async (req, res) => {
    try {
        const [posts] = await db.promise().query(
            `SELECT posts.*, users.username, users.look,
            COALESCE(likesCount.likesCount, 0) as likesCount,
            COALESCE(commentsCount.commentsCount, 0) as commentsCount,
            userLikes.is_like as userLike
            FROM posts
            JOIN users ON posts.user_id = users.id
            LEFT JOIN (
                SELECT post_id, COUNT(*) as likesCount 
                FROM likes 
                WHERE is_like = true 
                GROUP BY post_id
            ) likesCount ON posts.id = likesCount.post_id
            LEFT JOIN (
                SELECT post_id, COUNT(*) as commentsCount 
                FROM comments 
                GROUP BY post_id
            ) commentsCount ON posts.id = commentsCount.post_id
            LEFT JOIN (
                SELECT post_id, is_like 
                FROM likes 
                WHERE user_id = ?
            ) userLikes ON posts.id = userLikes.post_id
            WHERE posts.user_id = ? OR posts.visibility = "public"
            OR (posts.visibility = "friends" AND posts.user_id IN (
                SELECT CASE
                    WHEN user_one_id = ? THEN user_two_id
                    WHEN user_two_id = ? THEN user_one_id
                END AS friend_id
                FROM messenger_friendships
                WHERE user_one_id = ? OR user_two_id = ?
            ))
            ORDER BY posts.created_at DESC`,
            [req.userId, req.userId, req.userId, req.userId, req.userId, req.userId]
        );

        for (let post of posts) {
            const [comments] = await db.promise().query(
                `SELECT comments.*, users.username, users.look
                FROM comments
                JOIN users ON comments.user_id = users.id
                WHERE comments.post_id = ?
                ORDER BY comments.created_at DESC`,
                [post.id]
            );
            post.comments = comments;
        }

        res.status(200).send(posts);
    } catch (err) {
        console.error('Error fetching posts:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint for retrieving public posts with pagination
app.get('/public-posts', verifyToken, async (req, res) => {
    const { page = 1, limit = 10 } = req.query;
    const offset = (page - 1) * limit;
    try {
        const [posts] = await db.promise().query(
            `SELECT DISTINCT posts.*, users.username, users.look,
            COALESCE(likesCount.likesCount, 0) as likesCount,
            COALESCE(commentsCount.commentsCount, 0) as commentsCount,
            userLikes.is_like as userLike
            FROM posts
            JOIN users ON posts.user_id = users.id
            LEFT JOIN (
                SELECT post_id, COUNT(*) as likesCount 
                FROM likes 
                WHERE is_like = true 
                GROUP BY post_id
            ) likesCount ON posts.id = likesCount.post_id
            LEFT JOIN (
                SELECT post_id, COUNT(*) as commentsCount 
                FROM comments 
                GROUP BY post_id
            ) commentsCount ON posts.id = commentsCount.post_id
            LEFT JOIN (
                SELECT post_id, is_like 
                FROM likes 
                WHERE user_id = ?
            ) userLikes ON posts.id = userLikes.post_id
            WHERE posts.visibility = 'public'
            ORDER BY posts.created_at DESC
            LIMIT ? OFFSET ?`,
            [req.userId, parseInt(limit), parseInt(offset)]
        );

        for (let post of posts) {
            const [comments] = await db.promise().query(
                `SELECT comments.*, users.username, users.look
                FROM comments
                JOIN users ON comments.user_id = users.id
                WHERE comments.post_id = ?
                ORDER BY comments.created_at DESC`,
                [post.id]
            );
            post.comments = comments;
        }

        res.status(200).send(posts);
    } catch (err) {
        console.error('Error fetching public posts:', err);
        res.status(500).send('Server error');
    }
});

async function deletePostWithComments(postId, userId) {
    try {
        await db.promise().query('DELETE FROM comments WHERE post_id = ?', [postId]);
        await db.promise().query('DELETE FROM likes WHERE post_id = ?', [postId]);
        await db.promise().query('DELETE FROM posts WHERE id = ? AND user_id = ?', [postId, userId]);
    } catch (err) {
        throw err;
    }
}

// Endpoint pour supprimer un post
app.delete('/posts/:postId', verifyToken, async (req, res) => {
    const { postId } = req.params;
    try {
        await deletePostWithComments(postId, req.userId);
        res.status(200).send('Post deleted successfully');
    } catch (err) {
        console.error('Error deleting post:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour supprimer un commentaire
app.delete('/comments/:commentId', verifyToken, async (req, res) => {
    try {
        const [result] = await db.promise().query('DELETE FROM comments WHERE id = ? AND user_id = ?', [req.params.commentId, req.userId]);
        if (result.affectedRows === 0) {
            return res.status(404).send('Comment not found or not authorized');
        }
        res.status(200).send('Comment deleted successfully');
    } catch (err) {
        console.error('Error deleting comment:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour commenter un post
app.post('/comments', verifyToken, async (req, res) => {
    const { postId, content } = req.body;
    try {
        const [result] = await db.promise().query(
            'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
            [postId, req.userId, content]
        );
        const [comment] = await db.promise().query(
            'SELECT comments.*, users.username, users.look FROM comments JOIN users ON comments.user_id = users.id WHERE comments.id = ?',
            [result.insertId]
        );
        res.status(201).send(comment[0]);
    } catch (err) {
        console.error('Error adding comment:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour liker/disliker un post
app.post('/likes', verifyToken, async (req, res) => {
    const { postId, isLike } = req.body;
    try {
        const [existingLike] = await db.promise().query(
            'SELECT * FROM likes WHERE post_id = ? AND user_id = ?',
            [postId, req.userId]
        );

        if (existingLike.length > 0) {
            await db.promise().query(
                'UPDATE likes SET is_like = ? WHERE id = ?',
                [isLike, existingLike[0].id]
            );
        } else {
            await db.promise().query(
                'INSERT INTO likes (post_id, user_id, is_like) VALUES (?, ?, ?)',
                [postId, req.userId, isLike]
            );
        }

        res.status(201).send('Like/dislike added');
    } catch (err) {
        console.error('Error adding like/dislike:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour récupérer les photos de l'utilisateur
app.get('/user-photos', verifyToken, async (req, res) => {
    try {
        const [photos] = await db.promise().query(
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
        const [results] = await db.promise().query('SELECT * FROM users WHERE id = ?', [req.userId]);
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
        const [users] = await db.promise().query('SELECT * FROM users WHERE id = ?', [userId]);
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
        const [results] = await db.promise().query('SELECT id, username FROM users WHERE username LIKE ?', [`%${query}%`]);
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
        const [results] = await db.promise().query('SELECT * FROM users WHERE id = ?', [userId]);
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
        const [photos] = await db.promise().query(
            'SELECT id, user_id, room_id, timestamp, url FROM camera_web WHERE user_id = ?',
            [userId]
        );
        res.status(200).send(photos);
    } catch (err) {
        console.error('Error fetching user photos:', err);
        res.status(500).send('Server error');
    }
});


// Endpoint pour récupérer les posts de l'utilisateur
app.get('/posts/:userId', verifyToken, async (req, res) => {
    const userId = req.params.userId === 'me' ? req.userId : req.params.userId;
    try {
        const [posts] = await db.promise().query(
            `SELECT posts.*, users.username, users.look,
            COALESCE(likesCount.likesCount, 0) as likesCount,
            COALESCE(commentsCount.commentsCount, 0) as commentsCount,
            userLikes.is_like as userLike
            FROM posts
            JOIN users ON posts.user_id = users.id
            LEFT JOIN (
                SELECT post_id, COUNT(*) as likesCount 
                FROM likes 
                WHERE is_like = true 
                GROUP BY post_id
            ) likesCount ON posts.id = likesCount.post_id
            LEFT JOIN (
                SELECT post_id, COUNT(*) as commentsCount 
                FROM comments 
                GROUP BY post_id
            ) commentsCount ON posts.id = commentsCount.post_id
            LEFT JOIN (
                SELECT post_id, is_like 
                FROM likes 
                WHERE user_id = ?
            ) userLikes ON posts.id = userLikes.post_id
            WHERE posts.user_id = ? AND (posts.visibility = "public"
            OR (posts.visibility = "friends" AND posts.user_id IN (
                SELECT CASE
                    WHEN user_one_id = ? THEN user_two_id
                    WHEN user_two_id = ? THEN user_one_id
                END AS friend_id
                FROM messenger_friendships
                WHERE user_one_id = ? OR user_two_id = ?
            )))
            ORDER BY posts.created_at DESC`,
            [req.userId, userId, req.userId, req.userId, req.userId, req.userId]
        );

        for (let post of posts) {
            const [comments] = await db.promise().query(
                `SELECT comments.*, users.username, users.look
                FROM comments
                JOIN users ON comments.user_id = users.id
                WHERE comments.post_id = ?
                ORDER BY comments.created_at DESC`,
                [post.id]
            );
            post.comments = comments;
        }

        res.status(200).send(posts);
    } catch (err) {
        console.error('Error fetching posts:', err);
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
