const express = require('express');
const router = express.Router();
const {verifyToken} = require("../middlewares/authMiddleware");
const shopController = require("../controllers/shopController");

router.get('/last-members', verifyToken, shopController.getLastMembers);
router.post('/generate-credits', verifyToken, shopController.generateCredits);
router.post('/generate-pixels', verifyToken, shopController.generatePixels);
router.post('/lottery', verifyToken, shopController.lottery);

module.exports = router;