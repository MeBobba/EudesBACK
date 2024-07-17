// db.js
const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: '84.54.32.183',
    user: 'eudescms',
    password: '2@Qpzc121',
    database: 'eudescms'
});

connection.connect((err) => {
    if (err) throw err;
    console.log('Connected to the database');
});

module.exports = connection;
