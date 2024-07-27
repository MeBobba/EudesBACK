const db = require("../db");

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

// exports.updateAccount = async (req, res) => {
//     const { username, real_name, mail, motto, look, gender } = req.body;
//     try {
//         await db.query('UPDATE users SET username = ?, real_name = ?, mail = ?, motto = ?, look = ?, gender = ? WHERE id = ?',
//             [username, real_name, mail, motto, look, gender, req.userId]);
//         res.status(200).send('User account updated successfully');
//     } catch (err) {
//         console.error('Error updating user account:', err);
//         res.status(500).send('Server error');
//     }
// };

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