const express = require('express');
const router = express.Router();
const {verifyToken} = require("../middlewares/authMiddleware");
const staffController = require("../controllers/staffController");

router.get('/', verifyToken, staffController.getStaff);

module.exports = router;