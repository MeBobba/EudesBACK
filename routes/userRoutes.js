const express = require('express');
const router = express.Router();
const {verifyToken} = require("../middlewares/authMiddleware");
const userController = require("../controllers/userController");

router.get('/profile/me', verifyToken, userController.getMyProfile);
router.get('/profile/:userId', verifyToken, userController.getUserProfile);

module.exports = router;