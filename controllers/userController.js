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