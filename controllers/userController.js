const db = require("../db");
const twofactor = require("node-2fa");
const qrcode = require("qrcode");

exports.getMyProfile = async (req, res) => {
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
};

exports.getUserProfile = async (req, res) => {
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
};

exports.getUserPhotos = async (req, res) => {
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
};

exports.downloadUserData = async (req, res) => {
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
};

exports.updateAccount = async (req, res) => {
    const { username, real_name, mail, motto, look, gender } = req.body;
    try {
        await db.query('UPDATE users SET username = ?, real_name = ?, mail = ?, motto = ?, look = ?, gender = ? WHERE id = ?',
            [username, real_name, mail, motto, look, gender, req.userId]);
        res.status(200).send('User account updated successfully');
    } catch (err) {
        console.error('Error updating user account:', err);
        res.status(500).send('Server error');
    }
};

exports.deleteAccount = async (req, res) => {
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
};

exports.checkUsername = async (req, res) => {
    const { username } = req.body;
    try {
        const [results] = await db.query('SELECT username FROM users WHERE username = ?', [username]);
        res.status(200).send({ exists: results.length > 0 });
    } catch (err) {
        console.error('Error checking username:', err);
        res.status(500).send('Server error');
    }
};

exports.checkEmail = async (req, res) => {
    const { email } = req.body;
    try {
        const [results] = await db.query('SELECT mail FROM users WHERE mail = ?', [email]);
        res.status(200).send({ exists: results.length > 0 });
    } catch (err) {
        console.error('Error checking email:', err);
        res.status(500).send('Server error');
    }
};

exports.check2FA = async (req, res) => {
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
};

exports.verify2FA = async (req, res) => {
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
};

exports.enable2FA = async (req, res) => {
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
};

exports.disable2FA = async (req, res) => {
    try {
        await db.query('UPDATE users SET is_2fa_enabled = 0, google_auth_secret = NULL WHERE id = ?', [req.userId]);
        res.status(200).send('2FA disabled successfully');
    } catch (err) {
        console.error('Error disabling 2FA:', err);
        res.status(500).send('Server error');
    }
};

exports.searchUsers = async (req, res) => {
    const { query } = req.query;
    try {
        const [results] = await db.query('SELECT id, username FROM users WHERE username LIKE ?', [`%${query}%`]);
        res.status(200).send(results);
    } catch (err) {
        console.error('Error searching users:', err);
        res.status(500).send('Server error');
    }
};

exports.getUserPoints = async (req, res) => {
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
};

exports.getUserWallet = async (req, res) => {
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
};

exports.getUserStories = async (req, res) => {
    const { userId } = req.params;
    try {
        const [stories] = await db.query('SELECT * FROM stories WHERE user_id = ?', [userId]);
        res.status(200).send(stories);
    } catch (err) {
        console.error('Error fetching stories:', err);
        res.status(500).send('Server error');
    }
};

//TODO: Ajout d'une verif du rank pour l'update
exports.updateUser = async (req, res) => {
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
};