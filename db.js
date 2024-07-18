// db.js
const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: '84.54.32.183',
    user: 'eudesdb',
    password: 'l5ia6!9J3',
    database: 'eudesdb',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    // Configurer le keepAlive pour éviter la déconnexion
    keepAliveInitialDelay: 10000, // 10 secondes
    enableKeepAlive: true,
});

connection.connect((err) => {
    if (err) throw err;
    console.log('Connected to the database');
});

module.exports = connection;
