// db.js
const mysql = require('mysql2');

const pool = mysql.createPool({
    host: 'pma.mebobba.com',
    user: 'mebobbaprod',
    password: 'RPsBXtPItVBa22VE',
    database: 'mebobbaprod',
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
            console.error(`Error pinging the database at [${currentTime}]:`, err);
        } else {
            console.log(`Successfully pinged the database at [${currentTime}]`);
        }
    });
};

// Ping la base de données toutes les 5 minutes
setInterval(pingDatabase, 300000); // 300000 ms = 5 minutes

module.exports = pool.promise();
