const express = require('express');
const router = express.Router();
const { verifyToken } = require("../middlewares/authMiddleware");
const musicController = require("../controllers/musicController");

router.get('/lyrics', verifyToken, musicController.getLyrics);
router.get('/tracks/:spotifyId', verifyToken, musicController.getTracks);
router.post('/tracks', verifyToken, musicController.saveTrack);
router.get('/currentTrack', verifyToken, async (req, res) => {
    const userId = req.userId; // Assurez-vous que verifyToken ajoute userId à la requête
    try {
        const [results] = await db.query('SELECT current_track, current_time FROM user_music_state WHERE user_id = ?', [userId]);
        if (results.length > 0) {
            res.send(results[0]);
        } else {
            res.send({});
        }
    } catch (error) {
        console.error('Error fetching current track:', error);
        res.status(500).send('Server error');
    }
});

router.post('/currentTrack', verifyToken, async (req, res) => {
    const userId = req.userId; // Assurez-vous que verifyToken ajoute userId à la requête
    const { currentTrack, currentTime } = req.body;
    try {
        await db.query('REPLACE INTO user_music_state (user_id, current_track, current_time) VALUES (?, ?, ?)', [userId, currentTrack, currentTime]);
        res.status(200).send('Current track updated');
    } catch (error) {
        console.error('Error saving current track:', error);
        res.status(500).send('Server error');
    }
});


module.exports = router;