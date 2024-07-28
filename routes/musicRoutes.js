const express = require('express');
const router = express.Router();
const {verifyToken} = require("../middlewares/authMiddleware");
const musicController = require("../controllers/musicController");

router.get('/lyrics', verifyToken, musicController.getLyrics);
router.get('/tracks/:spotifyId', verifyToken, musicController.getTracks);
router.post('/tracks', verifyToken, musicController.saveTrack);

module.exports = router;