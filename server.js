const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const db = require('./db');
require('dotenv').config();
const http = require('http');
const socketIo = require('socket.io');
const moment = require('moment-timezone');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "https://mebobba.com",
        methods: ["GET", "POST"]
    }
});

const port = process.env.PORT || 3000;
const secretKey = process.env.SECRET_KEY || 'yourSecretKey';

const fs = require('fs');
const path = require('path');

app.use(bodyParser.json());
app.use(cors());
app.use('/webhook', bodyParser.raw({type: 'application/json'}));

app.use((req, res, next) => {
    req.setTimeout(0); // Désactive le timeout pour chaque requête
    next();
});

app.post('/create-checkout-session', verifyToken, async (req, res) => {
    const {packageId} = req.body;

    // Définir les packages de jetons et leurs prix
    const tokenPackages = {
        1: {name: 'Small Package', amount: 100, price: 500},  // prix en centimes
        2: {name: 'Medium Package', amount: 500, price: 2000}, // prix en centimes
        3: {name: 'Large Package', amount: 1000, price: 3500}  // prix en centimes
    };

    const selectedPackage = tokenPackages[packageId];
    if (!selectedPackage) {
        return res.status(400).send('Invalid package ID');
    }

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: 'eur',
                        product_data: {
                            name: selectedPackage.name,
                        },
                        unit_amount: selectedPackage.price,
                    },
                    quantity: 1,
                },
            ],
            mode: 'payment',
            success_url: `${process.env.FRONTEND_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.FRONTEND_URL}/cancel`,
            metadata: {
                userId: req.userId,
                packageId: packageId
            }
        });

        res.status(200).send({url: session.url});
    } catch (error) {
        console.error('Error creating Stripe checkout session:', error);
        res.status(500).send('Server error');
    }
});

app.post('/webhook', bodyParser.raw({type: 'application/json'}), (req, res) => {
    const sig = req.headers['stripe-signature'];

    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        const userId = session.metadata.userId;
        const packageId = session.metadata.packageId;

        // Définir les packages de jetons et leurs montants
        const tokenPackages = {
            1: {name: 'Small Package', amount: 100},
            2: {name: 'Medium Package', amount: 500},
            3: {name: 'Large Package', amount: 1000}
        };

        const selectedPackage = tokenPackages[packageId];

        if (selectedPackage) {
            // Ajouter les jetons à l'utilisateur dans la base de données
            db.query('UPDATE users SET points = points + ? WHERE id = ?', [selectedPackage.amount, userId], (err, result) => {
                if (err) {
                    console.error('Error updating user tokens:', err);
                } else {
                    console.log(`Added ${selectedPackage.amount} tokens to user ID ${userId}`);
                }
            });
        }
    }

    res.status(200).send('Received webhook');
});

app.get('/maintenance-status', async (req, res) => {
    try {
        const [results] = await db.query("SELECT `value` FROM `emulator_settings` WHERE `key` = 'website.maintenance'");
        const isMaintenance = results.length > 0 && results[0].value === '1';

        // Notify clients if maintenance mode is enabled
        if (isMaintenance) {
            io.emit('maintenance', true);
        }

        res.status(200).send({maintenance: isMaintenance});
    } catch (error) {
        console.error('Error fetching maintenance status:', error);
        res.status(500).send('Server error');
    }
});

// Endpoint pour vérifier la validité de la session
app.get('/check-session', verifyToken, (req, res) => {
    res.status(200).send({valid: true});
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

// Endpoint pour générer des crédits pour l'utilisateur
app.post('/generate-credits', verifyToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT credits FROM users WHERE id = ?', [req.userId]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        const userCredits = results[0].credits;
        if (userCredits < 10000) {
            const newCredits = userCredits + 10000;
            await db.query('UPDATE users SET credits = ? WHERE id = ?', [newCredits, req.userId]);
            res.status(200).send({generatedCredits: 10000});
        } else {
            res.status(400).send('You have enough credits.');
        }
    } catch (error) {
        console.error('Error generating credits:', error);
        res.status(500).send('Server error');
    }
});

// Servir les fichiers statiques
app.use('/topstory', express.static(path.join(__dirname, 'topstory')));

// Endpoint pour récupérer les images de la galerie
app.get('/topstory', verifyToken, async (req, res) => {
    try {
        // Assurez-vous que l'utilisateur a le rang nécessaire
        const [user] = await db.query('SELECT rank FROM users WHERE id = ?', [req.userId]);
        if (user.length === 0 || user[0].rank < 5) {
            return res.status(403).send('Access denied');
        }

        const imagesDir = path.join(__dirname, 'topstory');
        fs.readdir(imagesDir, (err, files) => {
            if (err) {
                console.error('Error reading images directory:', err);
                return res.status(500).send('Server error');
            }

            const images = files.map(file => ({
                name: file,
                path: `/topstory/${file}`
            }));

            res.status(200).send(images);
        });
    } catch (error) {
        console.error('Error fetching topstory images:', error);
        res.status(500).send('Server error');
    }
});

// Endpoint pour générer des pixels pour l'utilisateur
app.post('/generate-pixels', verifyToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT pixels FROM users WHERE id = ?', [req.userId]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        const userPixels = results[0].pixels;
        if (userPixels < 10000) {
            const newPixels = userPixels + 10000;
            await db.query('UPDATE users SET pixels = ? WHERE id = ?', [newPixels, req.userId]);
            res.status(200).send({generatedPixels: 10000});
        } else {
            res.status(400).send('You have enough pixels.');
        }
    } catch (error) {
        console.error('Error generating pixels:', error);
        res.status(500).send('Server error');
    }
});

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

// Endpoint pour vérifier l'existence d'une piste
app.get('/tracks/:spotifyId', async (req, res) => {
    const spotifyId = req.params.spotifyId;
    try {
        const [results] = await db.query('SELECT * FROM tracks WHERE spotify_id = ?', [spotifyId]);
        res.send({exists: results.length > 0});
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

// Fonction pour vérifier si un utilisateur est banni
async function checkBan(userId, ip, machineId) {
    try {
        const [results] = await db.query(
            'SELECT * FROM bans WHERE (user_id = ? OR ip = ? OR machine_id = ?) AND (ban_expire = 0 OR ban_expire > UNIX_TIMESTAMP())',
            [userId, ip, machineId]
        );
        return results.length > 0;
    } catch (err) {
        console.error('Error checking ban status:', err);
        throw new Error('Server error');
    }
}

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
    const {userId} = req.params;
    try {
        const [stories] = await db.query('SELECT * FROM stories WHERE user_id = ?', [userId]);
        res.status(200).send(stories);
    } catch (err) {
        console.error('Error fetching stories:', err);
        res.status(500).send('Server error');
    }
});

function drawLotteryNumbers(betAmount, selectedNumbers) {
    const numbers = Array.from({length: 49}, (_, i) => i + 1);
    const drawnNumbers = [];
    const chanceFactor = Math.min((betAmount - 150) / (1000 - 150), 0.7); // Facteur de chance limité à 0.7

    for (let i = 0; i < 6; i++) {
        let index;
        if (Math.random() < chanceFactor) {
            // Sélectionner un nombre parmi ceux choisis par l'utilisateur avec une probabilité accrue
            const commonNumbers = selectedNumbers.filter(num => numbers.includes(num));
            index = numbers.indexOf(commonNumbers[Math.floor(Math.random() * commonNumbers.length)]);
        } else {
            // Sélectionner un nombre aléatoire parmi les nombres restants
            index = Math.floor(Math.random() * numbers.length);
        }
        drawnNumbers.push(numbers.splice(index, 1)[0]);
    }
    return drawnNumbers;
}

function checkWin(selectedNumbers, drawnNumbers, betAmount) {
    const matches = selectedNumbers.filter(number => drawnNumbers.includes(number)).length;
    if (matches === 6) {
        const baseMultipliers = [0, 0, 0.5, 1, 2, 5, 10]; // Multiplicateurs de base pour 0 à 6 correspondances
        const chanceFactor = Math.min((betAmount - 150) / (1000 - 150), 0.7); // Facteur de chance limité à 0.7
        const adjustedMultipliers = baseMultipliers.map(multiplier => multiplier * (1 + chanceFactor));
        return adjustedMultipliers[matches];
    }
    return 0; // Si tous les numéros ne correspondent pas, retourne 0
}

app.post('/lottery', verifyToken, async (req, res) => {
    const {selectedNumbers, betAmount} = req.body;
    if (!Array.isArray(selectedNumbers) || selectedNumbers.length !== 6) {
        return res.status(400).send('Invalid input');
    }
    if (betAmount < 150 || betAmount > 1000) {
        return res.status(400).send('Bet amount must be between 150 and 1000 points.');
    }

    try {
        const [user] = await db.query('SELECT points FROM users WHERE id = ?', [req.userId]);
        if (user[0].points < betAmount) {
            return res.status(400).send({success: false, message: 'You do not have enough points to play.'});
        }

        const drawnNumbers = drawLotteryNumbers(betAmount, selectedNumbers);
        const multiplier = checkWin(selectedNumbers, drawnNumbers, betAmount); // Utilisation de la nouvelle fonction
        const rewardAmount = betAmount * multiplier;

        await db.query('UPDATE users SET points = points - ? WHERE id = ?', [betAmount, req.userId]);

        if (rewardAmount > 0) {
            await db.query('UPDATE users SET points = points + ? WHERE id = ?', [rewardAmount, req.userId]);
        }

        await db.query(
            'INSERT INTO lottery_plays (user_id, bet_amount, reward_amount, reward_type, drawn_numbers) VALUES (?, ?, ?, ?, ?)',
            [req.userId, betAmount, rewardAmount, 'Points', drawnNumbers.join(',')]
        );

        res.status(200).send({success: true, drawnNumbers, reward: {amount: rewardAmount, type: 'Points'}});
    } catch (error) {
        console.error('Error processing lottery:', error);
        res.status(500).send('Server error');
    }
});

app.get('/last-members', async (req, res) => {
    try {
        const [results] = await db.query(
            `SELECT u.username,
                    l.bet_amount                           AS betAmount,
                    l.reward_amount                        AS rewardAmount,
                    l.reward_type                          AS rewardType,
                    (l.reward_amount / l.bet_amount * 100) AS probability
             FROM lottery_plays l
                      JOIN users u ON l.user_id = u.id
             ORDER BY l.created_at DESC LIMIT 10`
        );
        res.status(200).send(results);
    } catch (error) {
        console.error('Error fetching last members:', error);
        res.status(500).send('Server error');
    }
});

app.get('/user/points', verifyToken, async (req, res) => {
    try {
        const [results] = await db.query('SELECT points FROM users WHERE id = ?', [req.userId]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }
        res.status(200).send({points: results[0].points});
    } catch (error) {
        console.error('Error fetching user points:', error);
        res.status(500).send('Server error');
    }
});

// Endpoint pour récupérer les informations du staff
app.get('/staff', verifyToken, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;
    try {
        const [ranks] = await db.query(
            'SELECT * FROM permissions WHERE level >= 5 ORDER BY level DESC LIMIT ? OFFSET ?',
            [limit, offset]
        );

        const staffSections = await Promise.all(
            ranks.map(async (rank) => {
                const [users] = await db.query('SELECT * FROM users WHERE rank = ?', [rank.level]);
                return {rank_name: rank.rank_name, users};
            })
        );

        res.status(200).send(staffSections);
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
    const {username} = req.query;
    try {
        const [results] = await db.query('SELECT is_2fa_enabled FROM users WHERE username = ?', [username]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        const user = results[0];
        res.status(200).send({is2FAEnabled: user.is_2fa_enabled});
    } catch (err) {
        console.error('Error checking 2FA status:', err);
        res.status(500).send('Server error');
    }
});

// Inscription
app.post('/register', async (req, res) => {
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
});

// Connexion
app.post('/login', async (req, res) => {
    const {username, password, token2fa, machine_id} = req.body;
    const ip = getClientIp(req);

    try {
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

        const passwordIsValid = await bcrypt.compare(password, user.password);
        if (!passwordIsValid) {
            return res.status(401).send('Invalid password');
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

        const token = jwt.sign({id: user.id, rank: user.rank}, secretKey, {expiresIn: '24h'});

        await db.query('UPDATE users SET machine_id = ? WHERE id = ?', [machine_id, user.id]);
        res.status(200).send({auth: true, token});
    } catch (err) {
        console.error('Error logging in user:', err);
        res.status(500).send('Server error');
    }
});

// Déconnexion
app.post('/logout', verifyToken, async (req, res) => {
    try {
        await db.query('UPDATE users SET is_logged_in = 0 WHERE id = ?', [req.userId]);
        res.status(200).send('User logged out successfully');
    } catch (err) {
        console.error('Error logging out user:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour mettre à jour un post
app.put('/posts/:postId', verifyToken, async (req, res) => {
    const {postId} = req.params;
    const {content} = req.body;

    try {
        const [result] = await db.query(
            'UPDATE posts SET content = ? WHERE id = ?',
            [content, postId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).send('Post not found');
        }

        const [updatedPost] = await db.query('SELECT * FROM posts WHERE id = ?', [postId]);
        res.status(200).send(updatedPost[0]);
    } catch (err) {
        console.error('Error updating post:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour activer Google Authenticator
app.post('/enable-2fa', verifyToken, async (req, res) => {
    const secret = speakeasy.generateSecret({length: 20});
    const url = speakeasy.otpauthURL({
        secret: secret.base32,
        label: 'MeBobba',
        issuer: 'Eudes'
    });

    try {
        await db.query('UPDATE users SET google_auth_secret = ? WHERE id = ?', [secret.base32, req.userId]);
        qrcode.toDataURL(url, (err, data_url) => {
            res.status(200).send({secret: secret.base32, dataURL: data_url});
        });
    } catch (err) {
        console.error('Error enabling 2FA:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour vérifier le code Google Authenticator
app.post('/verify-2fa', verifyToken, async (req, res) => {
    const {token} = req.body;
    try {
        const [results] = await db.query('SELECT google_auth_secret FROM users WHERE id = ?', [req.userId]);
        const user = results[0];
        const verified = speakeasy.totp.verify({
            secret: user.google_auth_secret,
            encoding: 'base32',
            token,
            window: 1 // Allow some time drift
        });
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
    const {username} = req.body;
    try {
        const [results] = await db.query('SELECT username FROM users WHERE username = ?', [username]);
        res.status(200).send({exists: results.length > 0});
    } catch (err) {
        console.error('Error checking username:', err);
        res.status(500).send('Server error');
    }
});

// Vérification de l'email
app.post('/check-email', async (req, res) => {
    const {email} = req.body;
    try {
        const [results] = await db.query('SELECT mail FROM users WHERE mail = ?', [email]);
        res.status(200).send({exists: results.length > 0});
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
            {table: 'bans', column: 'user_id'},
            {table: 'bots', column: 'user_id'},
            {table: 'calendar_rewards_claimed', column: 'user_id'},
            {table: 'camera_web', column: 'user_id'},
            {table: 'catalog_items_limited', column: 'user_id'},
            {table: 'chatlogs_private', columns: ['user_to_id', 'user_from_id']},
            {table: 'chatlogs_room', columns: ['user_to_id', 'user_from_id']},
            {table: 'commandlogs', column: 'user_id'},
            {table: 'guilds', column: 'user_id'},
            {table: 'guilds_forums_comments', column: 'user_id'},
            {table: 'guilds_forums_threads', column: 'opener_id'},
            {table: 'guilds_members', column: 'user_id'},
            {table: 'guild_forum_views', column: 'user_id'},
            {table: 'items', column: 'user_id'},
            {table: 'items_highscore_data', column: 'user_ids'},
            {table: 'logs_hc_payday', column: 'user_id'},
            {table: 'logs_shop_purchases', column: 'user_id'},
            {table: 'lottery_plays', column: 'user_id'},
            {table: 'marketplace_items', column: 'user_id'},
            {table: 'messenger_categories', column: 'user_id'},
            {table: 'messenger_friendrequests', columns: ['user_to_id', 'user_from_id']},
            {table: 'messenger_friendships', columns: ['user_one_id', 'user_two_id']},
            {table: 'messenger_offline', columns: ['user_id', 'user_from_id']},
            {table: 'namechange_log', column: 'user_id'},
            {table: 'polls_answers', column: 'user_id'},
            {table: 'rooms', column: 'owner_id'},
            {table: 'room_bans', column: 'user_id'},
            {table: 'room_enter_log', column: 'user_id'},
            {table: 'room_game_scores', column: 'user_id'},
            {table: 'room_mutes', column: 'user_id'},
            {table: 'room_rights', column: 'user_id'},
            {table: 'room_trade_log', columns: ['user_two_id', 'user_one_id']},
            {table: 'room_trade_log_items', column: 'user_id'},
            {table: 'room_votes', column: 'user_id'},
            {table: 'sanctions', column: 'habbo_id'},
            {table: 'stories', column: 'user_id'} // Added stories table
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
    const {username, real_name, mail, motto, look, gender} = req.body;
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
    const {q_track, q_artist} = req.query;
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

// Endpoint pour créer un nouveau post
app.post('/posts', verifyToken, async (req, res) => {
    const {content, image, video, visibility} = req.body;

    try {
        const [[user]] = await db.query('SELECT rank, last_post_time FROM users WHERE id = ?', [req.userId]);
        const currentTime = Math.floor(Date.now() / 1000);

        // Check for flood protection
        if (user.rank < 5 && user.last_post_time && (currentTime - user.last_post_time < 15)) {
            return res.status(429).send('You must wait 15 seconds before posting again.');
        }

        // Apply wordfilter
        const [wordFilters] = await db.query('SELECT * FROM wordfilter');
        let filteredContent = content;
        wordFilters.forEach(filter => {
            const regex = new RegExp(`\\b${filter.key}\\b`, 'gi');
            filteredContent = filteredContent.replace(regex, filter.replacement);
        });

        const [result] = await db.query(
            'INSERT INTO posts (user_id, content, image, video, visibility, created_at) VALUES (?, ?, ?, ?, ?, ?)',
            [req.userId, filteredContent, image, video, visibility, new Date()]
        );

        await db.query('UPDATE users SET last_post_time = ? WHERE id = ?', [currentTime, req.userId]);

        const [newPost] = await db.query(
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
        const [posts] = await db.query(
            `SELECT posts.*,
                    users.username,
                    users.look,
                    COALESCE(likesCount.likesCount, 0)       as likesCount,
                    COALESCE(commentsCount.commentsCount, 0) as commentsCount,
                    userLikes.is_like                        as userLike
             FROM posts
                      JOIN users ON posts.user_id = users.id
                      LEFT JOIN (SELECT post_id, COUNT(*) as likesCount
                                 FROM likes
                                 WHERE is_like = true
                                 GROUP BY post_id) likesCount ON posts.id = likesCount.post_id
                      LEFT JOIN (SELECT post_id, COUNT(*) as commentsCount
                                 FROM comments
                                 GROUP BY post_id) commentsCount ON posts.id = commentsCount.post_id
                      LEFT JOIN (SELECT post_id, is_like
                                 FROM likes
                                 WHERE user_id = ?) userLikes ON posts.id = userLikes.post_id
             WHERE posts.user_id = ?
                OR posts.visibility = "public"
                OR (posts.visibility = "friends" AND posts.user_id IN (SELECT CASE
                                                                                  WHEN user_one_id = ? THEN user_two_id
                                                                                  WHEN user_two_id = ? THEN user_one_id
                                                                                  END AS friend_id
                                                                       FROM messenger_friendships
                                                                       WHERE user_one_id = ?
                                                                          OR user_two_id = ?))
             ORDER BY posts.created_at DESC`,
            [req.userId, req.userId, req.userId, req.userId, req.userId, req.userId]
        );

        for (let post of posts) {
            const [comments] = await db.query(
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
    const {page = 1, limit = 10} = req.query;
    const offset = (page - 1) * limit;
    try {
        const [posts] = await db.query(
            `SELECT DISTINCT posts.*,
                             users.username,
                             users.look,
                             COALESCE(likesCount.likesCount, 0)       as likesCount,
                             COALESCE(commentsCount.commentsCount, 0) as commentsCount,
                             userLikes.is_like                        as userLike
             FROM posts
                      JOIN users ON posts.user_id = users.id
                      LEFT JOIN (SELECT post_id, COUNT(*) as likesCount
                                 FROM likes
                                 WHERE is_like = true
                                 GROUP BY post_id) likesCount ON posts.id = likesCount.post_id
                      LEFT JOIN (SELECT post_id, COUNT(*) as commentsCount
                                 FROM comments
                                 GROUP BY post_id) commentsCount ON posts.id = commentsCount.post_id
                      LEFT JOIN (SELECT post_id, is_like
                                 FROM likes
                                 WHERE user_id = ?) userLikes ON posts.id = userLikes.post_id
             WHERE posts.visibility = 'public'
             ORDER BY posts.created_at DESC LIMIT ?
             OFFSET ?`,
            [req.userId, parseInt(limit), parseInt(offset)]
        );

        for (let post of posts) {
            const [comments] = await db.query(
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

async function deletePostWithComments(postId) {
    try {
        await db.query('DELETE FROM comments WHERE post_id = ?', [postId]);
        await db.query('DELETE FROM likes WHERE post_id = ?', [postId]);
        await db.query('DELETE FROM posts WHERE id = ?', [postId]);
    } catch (err) {
        throw err;
    }
}

// Endpoint pour supprimer un post
app.delete('/posts/:postId', verifyToken, async (req, res) => {
    const {postId} = req.params;
    try {
        const [[user]] = await db.query('SELECT rank FROM users WHERE id = ?', [req.userId]);
        const userRank = user.rank;

        const [[post]] = await db.query('SELECT user_id FROM posts WHERE id = ?', [postId]);
        if (!post) {
            return res.status(404).send('Post not found');
        }

        const postOwnerId = post.user_id;

        if (userRank < 5 && postOwnerId !== req.userId) {
            return res.status(403).send('Not authorized to delete this post');
        }

        await deletePostWithComments(postId);

        res.status(200).send('Post deleted successfully');
    } catch (err) {
        console.error('Error deleting post:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour commenter un post
app.post('/comments', verifyToken, async (req, res) => {
    const {postId, content} = req.body;
    try {
        const [result] = await db.query(
            'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
            [postId, req.userId, content]
        );
        const [comment] = await db.query(
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
    const {postId, isLike} = req.body;
    try {
        const [existingLike] = await db.query(
            'SELECT * FROM likes WHERE post_id = ? AND user_id = ?',
            [postId, req.userId]
        );

        if (existingLike.length > 0) {
            if (existingLike[0].is_like === isLike) {
                // If the same like status is being sent, remove the like
                await db.query(
                    'DELETE FROM likes WHERE id = ?',
                    [existingLike[0].id]
                );
            } else {
                // Otherwise, update the like status
                await db.query(
                    'UPDATE likes SET is_like = ? WHERE id = ?',
                    [isLike, existingLike[0].id]
                );
            }
        } else {
            await db.query(
                'INSERT INTO likes (post_id, user_id, is_like) VALUES (?, ?, ?)',
                [postId, req.userId, isLike]
            );
        }

        const [[likeStatus]] = await db.query(
            'SELECT is_like FROM likes WHERE post_id = ? AND user_id = ?',
            [postId, req.userId]
        );

        const [[likesCount]] = await db.query(
            'SELECT COUNT(*) AS likesCount FROM likes WHERE post_id = ? AND is_like = true',
            [postId]
        );

        res.status(201).send({userLike: likeStatus ? likeStatus.is_like : null, likesCount: likesCount.likesCount});
    } catch (err) {
        console.error('Error adding like/dislike:', err);
        res.status(500).send('Server error');
    }
});

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

// Endpoint pour récupérer les jeux
app.get('/games', async (req, res) => {
    try {
        const [games] = await db.query('SELECT * FROM games');
        res.status(200).send(games);
    } catch (error) {
        console.error('Error fetching games:', error);
        res.status(500).send('Server error');
    }
});

// Endpoint pour récupérer les jeux par ID
app.get('/games/:id', async (req, res) => {
    try {
        const [games] = await db.query('SELECT * FROM games WHERE id = ?', [req.params.id]);
        if (games.length === 0) {
            return res.status(404).send('Game not found');
        }
        res.status(200).send(games[0]);
    } catch (error) {
        console.error('Error fetching game by ID:', error);
        res.status(500).send('Server error');
    }
});

// Route pour récupérer le profil d'un utilisateur par ID
app.get('/profile/:userId', verifyToken, async (req, res) => {
    const {userId} = req.params;
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
    const {query} = req.query;
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

// Endpoint pour récupérer les posts de l'utilisateur
app.get('/posts/:userId', verifyToken, async (req, res) => {
    const userId = req.params.userId === 'me' ? req.userId : req.params.userId;
    try {
        const [posts] = await db.query(
            `SELECT posts.*,
                    users.username,
                    users.look,
                    COALESCE(likesCount.likesCount, 0)       as likesCount,
                    COALESCE(commentsCount.commentsCount, 0) as commentsCount,
                    userLikes.is_like                        as userLike
             FROM posts
                      JOIN users ON posts.user_id = users.id
                      LEFT JOIN (SELECT post_id, COUNT(*) as likesCount
                                 FROM likes
                                 WHERE is_like = true
                                 GROUP BY post_id) likesCount ON posts.id = likesCount.post_id
                      LEFT JOIN (SELECT post_id, COUNT(*) as commentsCount
                                 FROM comments
                                 GROUP BY post_id) commentsCount ON posts.id = commentsCount.post_id
                      LEFT JOIN (SELECT post_id, is_like
                                 FROM likes
                                 WHERE user_id = ?) userLikes ON posts.id = userLikes.post_id
             WHERE posts.user_id = ?
               AND posts.visibility = "public"
             ORDER BY posts.created_at DESC`,
            [req.userId, userId]
        );

        for (let post of posts) {
            const [comments] = await db.query(
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

// Endpoint pour récupérer la liste des articles
app.get('/articles', async (req, res) => {
    try {
        const [articles] = await db.query('SELECT * FROM articles ORDER BY date DESC');
        res.status(200).send(articles);
    } catch (error) {
        console.error('Error fetching articles:', error);
        res.status(500).send('Server error');
    }
});

// Endpoint pour récupérer un article par ID
app.get('/articles/:id', verifyToken, async (req, res) => {
    const {id} = req.params;
    const userId = req.userId; // Assurez-vous que verifyToken est utilisé pour définir req.userId
    try {
        const [articles] = await db.query('SELECT * FROM articles WHERE id = ?', [id]);
        if (articles.length === 0) {
            return res.status(404).send('Article not found');
        }

        const article = articles[0];

        // Récupérer le nombre de likes
        const [[likesCount]] = await db.query(
            'SELECT COUNT(*) AS likesCount FROM article_likes WHERE article_id = ? AND is_like = true',
            [id]
        );

        // Récupérer le nombre de commentaires
        const [[commentsCount]] = await db.query(
            'SELECT COUNT(*) AS commentsCount FROM article_comments WHERE article_id = ?',
            [id]
        );

        // Vérifier si l'utilisateur a liké l'article
        const [[userLike]] = await db.query(
            'SELECT is_like FROM article_likes WHERE article_id = ? AND user_id = ?',
            [id, userId]
        );

        // Récupérer les commentaires
        const [comments] = await db.query(
            `SELECT article_comments.*, users.username, users.look
             FROM article_comments
                      JOIN users ON article_comments.user_id = users.id
             WHERE article_comments.article_id = ?
             ORDER BY article_comments.created_at DESC`,
            [id]
        );

        article.likesCount = likesCount.likesCount;
        article.commentsCount = commentsCount.commentsCount;
        article.userLike = userLike ? userLike.is_like : null;
        article.comments = comments;

        res.status(200).send(article);
    } catch (error) {
        console.error('Error fetching article:', error);
        res.status(500).send('Server error');
    }
});

// Endpoint for liking/disliking an article
app.post('/articles/:articleId/likes', verifyToken, async (req, res) => {
    const {articleId} = req.params;
    const {isLike} = req.body;
    try {
        const [existingLike] = await db.query(
            'SELECT * FROM article_likes WHERE article_id = ? AND user_id = ?',
            [articleId, req.userId]
        );

        if (existingLike.length > 0) {
            await db.query(
                'UPDATE article_likes SET is_like = ? WHERE id = ?',
                [isLike, existingLike[0].id]
            );
        } else {
            await db.query(
                'INSERT INTO article_likes (article_id, user_id, is_like) VALUES (?, ?, ?)',
                [articleId, req.userId, isLike]
            );
        }

        const [[likeStatus]] = await db.query(
            'SELECT is_like FROM article_likes WHERE article_id = ? AND user_id = ?',
            [articleId, req.userId]
        );

        const [[likesCount]] = await db.query(
            'SELECT COUNT(*) AS likesCount FROM article_likes WHERE article_id = ? AND is_like = true',
            [articleId]
        );

        res.status(201).send({userLike: likeStatus.is_like, likesCount: likesCount.likesCount});
    } catch (err) {
        console.error('Error adding like/dislike:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint for commenting on an article
app.post('/articles/:articleId/comments', verifyToken, async (req, res) => {
    const {articleId} = req.params;
    const {content} = req.body;

    try {
        const [[user]] = await db.query('SELECT last_comment_time FROM users WHERE id = ?', [req.userId]);

        const currentTime = Math.floor(Date.now() / 1000);

        if (user.last_comment_time && (currentTime - user.last_comment_time < 15)) {
            return res.status(429).send('You must wait 15 seconds before commenting again.');
        }

        const [result] = await db.query(
            'INSERT INTO article_comments (article_id, user_id, content) VALUES (?, ?, ?)',
            [articleId, req.userId, content]
        );

        await db.query('UPDATE users SET last_comment_time = ? WHERE id = ?', [currentTime, req.userId]);

        const [comment] = await db.query(
            'SELECT article_comments.*, users.username, users.look FROM article_comments JOIN users ON article_comments.user_id = users.id WHERE article_comments.id = ?',
            [result.insertId]
        );

        res.status(201).send(comment[0]);
    } catch (err) {
        console.error('Error adding comment:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour supprimer un commentaire d'article
app.delete('/article-comments/:commentId', verifyToken, async (req, res) => {
    const {commentId} = req.params;
    try {
        const [[comment]] = await db.query('SELECT user_id FROM article_comments WHERE id = ?', [commentId]);
        if (!comment) {
            return res.status(404).send('Comment not found');
        }

        const [[user]] = await db.query('SELECT rank FROM users WHERE id = ?', [req.userId]);
        if (user.rank < 5 && comment.user_id !== req.userId) {
            return res.status(403).send('Not authorized to delete this comment');
        }

        await db.query('DELETE FROM article_comments WHERE id = ?', [commentId]);
        res.status(200).send('Comment deleted successfully');
    } catch (err) {
        console.error('Error deleting comment:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint pour supprimer un commentaire d'article
app.delete('/comments/:commentId', verifyToken, async (req, res) => {
    const {commentId} = req.params;
    try {
        const [[comment]] = await db.query('SELECT user_id FROM comments WHERE id = ?', [commentId]);
        if (!comment) {
            return res.status(404).send('Comment not found');
        }

        const [[user]] = await db.query('SELECT rank FROM users WHERE id = ?', [req.userId]);
        if (user.rank < 5 && comment.user_id !== req.userId) {
            return res.status(403).send('Not authorized to delete this comment');
        }

        await db.query('DELETE FROM comments WHERE id = ?', [commentId]);
        res.status(200).send('Comment deleted successfully');
    } catch (err) {
        console.error('Error deleting comment:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint for creating a new article
app.post('/articles', verifyToken, async (req, res) => {
    const {title, summary, content, image} = req.body;
    const userId = req.userId;

    if (req.userRank < 5) {
        return res.status(403).send('Not authorized to create articles');
    }

    try {
        const currentTimeUTC = moment.utc().format(); // ISO 8601 format with UTC timezone
        const [result] = await db.query(
            'INSERT INTO articles (title, summary, content, image, date, user_id) VALUES (?, ?, ?, ?, ?, ?)',
            [title, summary, content, image, currentTimeUTC, userId]
        );
        res.status(201).send({
            id: result.insertId,
            title,
            summary,
            content,
            image,
            date: currentTimeUTC,
            user_id: userId
        });
    } catch (err) {
        console.error('Error creating article:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint for updating an article
app.put('/articles/:id', verifyToken, async (req, res) => {
    const {id} = req.params;
    const {title, summary, content, image} = req.body;
    if (req.userRank < 5) {
        return res.status(403).send('Not authorized to edit articles');
    }
    try {
        await db.query(
            'UPDATE articles SET title = ?, summary = ?, content = ?, image = ? WHERE id = ?',
            [title, summary, content, image, id]
        );
        res.status(200).send('Article updated successfully');
    } catch (err) {
        console.error('Error updating article:', err);
        res.status(500).send('Server error');
    }
});

// Endpoint for deleting an article
app.delete('/articles/:id', verifyToken, async (req, res) => {
    const {id} = req.params;

    if (req.userRank < 5) {
        return res.status(403).send('Not authorized to delete articles');
    }

    try {
        // Start a transaction
        await db.query('START TRANSACTION');

        // Delete related comments
        await db.query('DELETE FROM article_comments WHERE article_id = ?', [id]);

        // Delete related likes
        await db.query('DELETE FROM article_likes WHERE article_id = ?', [id]);

        // Delete the article
        const [result] = await db.query('DELETE FROM articles WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            await db.query('ROLLBACK');
            return res.status(404).send('Article not found');
        }

        // Commit the transaction
        await db.query('COMMIT');

        res.status(200).send('Article and related data deleted successfully');
    } catch (err) {
        await db.query('ROLLBACK');
        console.error('Error deleting article:', err);
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
