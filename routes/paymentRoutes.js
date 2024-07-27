const express = require('express');
const router = express.Router();
const {verifyToken} = require("../middlewares/authMiddleware");
const paymentController = require("../controllers/paymentController");
const bodyParser = require("body-parser");

router.post('/create-checkout-session', verifyToken, paymentController.createCheckoutSession);
router.post('/webhook', bodyParser.raw({ type: 'application/json' }), paymentController.stripeWebhook);

module.exports = router;