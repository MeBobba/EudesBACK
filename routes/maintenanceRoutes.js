const express = require('express');
const router = express.Router();
const {verifyToken} = require("../middlewares/authMiddleware");
const maintenanceController = require("../controllers/maintenanceController");

router.get('/status', maintenanceController.getStatus);

module.exports = router;