const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { verifyToken } = require('../middlewares/authMiddleware');

router.post('/login', authController.login);
router.post('/logout', verifyToken, authController.logout);
router.post('/register', authController.register);
router.get('/check-session', verifyToken, authController.checkSession);
router.get('/anti-robot-question', authController.generateAntiRobotQuestion);
router.get('/check-ban', verifyToken, authController.checkBan);
router.post('/unlock', verifyToken, authController.unlock);
router.post('/login-face', authController.loginWithFace); // Add this line

module.exports = router;
