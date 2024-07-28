const express = require('express');
const router = express.Router();
const {verifyToken} = require("../middlewares/authMiddleware");
const gameController = require("../controllers/gameController");

router.get('/', verifyToken, gameController.getGames);
router.get('/:id', verifyToken, gameController.getGame);
router.post('/', verifyToken, gameController.createGame);
router.delete('/:id', verifyToken, gameController.deleteGame);

module.exports = router;