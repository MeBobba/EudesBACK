const db = require("../db");
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

exports.createCheckoutSession = async (req, res) => {
    const { packageId } = req.body;

    // Définir les packages de jetons et leurs prix
    const tokenPackages = {
        1: { name: 'Small Package', amount: 100, price: 500 },  // prix en centimes
        2: { name: 'Medium Package', amount: 500, price: 2000 }, // prix en centimes
        3: { name: 'Large Package', amount: 1000, price: 3500 }  // prix en centimes
    };

    const selectedPackage = tokenPackages[packageId];
    if (!selectedPackage) {
        return res.status(400).send('Invalid package ID');
    }

    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: 'eur',
                        product_data: {
                            name: selectedPackage.name,
                        },
                        unit_amount: selectedPackage.price,
                    },
                    quantity: 1,
                },
            ],
            mode: 'payment',
            success_url: `${process.env.FRONTEND_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.FRONTEND_URL}/cancel`,
            metadata: {
                userId: req.userId,
                packageId: packageId
            }
        });

        res.status(200).send({ url: session.url });
    } catch (error) {
        console.error('Error creating Stripe checkout session:', error);
        res.status(500).send('Server error');
    }
};

exports.stripeWebhook = (req, res) => {
    const sig = req.headers['stripe-signature'];

    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        const userId = session.metadata.userId;
        const packageId = session.metadata.packageId;

        // Définir les packages de jetons et leurs montants
        const tokenPackages = {
            1: { name: 'Small Package', amount: 100 },
            2: { name: 'Medium Package', amount: 500 },
            3: { name: 'Large Package', amount: 1000 }
        };

        const selectedPackage = tokenPackages[packageId];

        if (selectedPackage) {
            // Ajouter les jetons à l'utilisateur dans la base de données
            db.query('UPDATE users SET points = points + ? WHERE id = ?', [selectedPackage.amount, userId], (err, result) => {
                if (err) {
                    console.error('Error updating user tokens:', err);
                } else {
                    console.log(`Added ${selectedPackage.amount} tokens to user ID ${userId}`);
                }
            });
        }
    }

    res.status(200).send('Received webhook');
};