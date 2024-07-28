const express = require('express');
const router = express.Router();
const {verifyToken} = require("../middlewares/authMiddleware");
const userController = require("../controllers/userController");

router.put('/update-account', verifyToken, userController.updateAccount);
router.put('/:userId', verifyToken, userController.updateUser);
router.get('/profile/me', verifyToken, userController.getMyProfile);
router.get('/profile/:userId', verifyToken, userController.getUserProfile);
router.get('/photos/:userId', verifyToken, userController.getUserPhotos);
router.get('/stories/:userId', verifyToken, userController.getUserStories);
router.get('/download-data', verifyToken, userController.downloadUserData);
router.get('/search', verifyToken, userController.searchUsers);
router.get('/points', verifyToken, userController.getUserPoints);
router.get('/wallet', verifyToken, userController.getUserWallet);
// todo: maybe move it to authRoutes
router.get('/check-2fa', userController.check2FA);
router.delete('/delete-account', verifyToken, userController.deleteAccount);
router.post('/check-username', userController.checkUsername);
router.post('/check-email', userController.checkEmail);
router.post('/verify-2fa', verifyToken, userController.verify2FA);
router.post('/enable-2fa', verifyToken, userController.enable2FA);
router.post('/disable-2fa', verifyToken, userController.disable2FA);

module.exports = router;