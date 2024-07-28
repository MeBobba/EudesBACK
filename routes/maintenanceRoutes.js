const express = require('express');
const router = express.Router();
const maintenanceController = require("../controllers/maintenanceController");

router.get('/status', maintenanceController.getStatus);

module.exports = router;