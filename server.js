const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();
const http = require('http');
const axios = require('axios'); // Ajouté pour les requêtes proxy
const authRoutes = require('./routes/authRoutes');
const articleRoutes = require('./routes/articleRoutes');
const postRoutes = require('./routes/postRoutes');
const gameRoutes = require('./routes/gameRoutes');
const shopRoutes = require('./routes/shopRoutes');
const paymentRoutes = require('./routes/paymentRoutes');
const userRoutes = require('./routes/userRoutes');
const musicRoutes = require('./routes/musicRoutes');
const staffRoutes = require('./routes/staffRoutes');
const maintenanceRoutes = require('./routes/maintenanceRoutes');
const headerRoutes = require('./routes/headerRoutes');
const { initializeSocket } = require("./socket");

const app = express();
const server = http.createServer(app);

// initialize socket.io
initializeSocket(server);

const port = process.env.PORT || 3000;

app.use(bodyParser.json());
// CORS frontend
app.use(cors({
    origin: process.env.FRONTEND_URL,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Origin", "X-Requested-With", "Content-Type", "Accept", "x-access-token"]
}));

app.use((req, res, next) => {
    req.setTimeout(0); // Désactive le timeout pour chaque requête
    next();
});

// Proxy route for Genius API
app.get('/api/proxy', async (req, res) => {
    const { url } = req.query;
    try {
        const response = await axios.get(url);
        res.send(response.data);
    } catch (error) {
        console.error('Error fetching the URL:', error);
        res.status(500).send('Error fetching the URL');
    }
});

// gestion des routes par modules
// routes pour authentification
app.use('/auth', authRoutes);
// routes pour les articles
app.use('/articles', articleRoutes);
// route pour les posts
app.use('/posts', postRoutes);
// routes pour les jeux
app.use('/games', gameRoutes);
// routes pour la boutique
app.use('/shop', shopRoutes);
// routes pour le paiement
app.use('/payment', paymentRoutes);
// routes pour les utilisateurs
app.use('/users', userRoutes);
// routes pour musique
app.use('/music', musicRoutes);
// routes pour le staff
app.use('/staff', staffRoutes);
// routes pour la maintenance
app.use('/maintenance', maintenanceRoutes);
// routes pour le header
app.use('/headerimages', headerRoutes);

// Gestion des erreurs 404
app.use((req, res, next) => {
    res.status(404).send('Not Found');
});

// Gestion des erreurs 500
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Server Error');
});

server.listen(port, () => {
    console.log(`Server running on port ${port}`);
});