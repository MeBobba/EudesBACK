const express = require('express');
const router = express.Router();
const headerController = require('../controllers/headerController');
const path = require("path");

router.use('/', express.static(path.join(__dirname, '../headerimages')));
router.get('/', headerController.getHeaderImages);

module.exports = router;
