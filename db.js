// db.js
const mysql = require('mysql2');

const pool = mysql.createPool({
    host: '84.54.32.183',
    user: 'eudesdb',
    password: 'l5ia6!9J3',
    database: 'eudesdb',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

pool.getConnection((err, connection) => {
    if (err) {
        console.error('Error connecting to the database:', err);
    } else {
        console.log('Connected to the database');
        connection.release();
    }
});

// Fonction pour obtenir l'heure actuelle formatée
const getCurrentTime = () => {
    const now = new Date();
    return now.toISOString(); // Format ISO 8601
};

// Fonction pour exécuter une requête de ping
const pingDatabase = () => {
    pool.query('SELECT 1', (err) => {
        const currentTime = getCurrentTime();
        if (err) {
            console.error(`J'ai pas pu ping ta bdd à [${currentTime}] fdp:`, err);
        } else {
            console.log(`J'ai pu ping ta bdd à [${currentTime}] fdp de tes grands morts les chiens d'antarctique de l'ouest chinois`);
        }
    });
};

// Ping la base de données toutes les 5 minutes
setInterval(pingDatabase, 300000); // 300000 ms = 5 minutes

module.exports = pool;
