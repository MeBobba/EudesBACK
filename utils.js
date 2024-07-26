const db = require("./db");

// fonction pour obtenir l'adresse IP du client
exports.getClientIp = (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    return forwarded ? forwarded.split(',').shift() : req.connection.remoteAddress;
};

// fonction pour verifier si l'utilisateur est banni
exports.checkBan = async (userId, ip, machineId) => {
    try {
        const [results] = await db.query(
            'SELECT * FROM bans WHERE (user_id = ? OR ip = ? OR machine_id = ?) AND (ban_expire = 0 OR ban_expire > UNIX_TIMESTAMP())',
            [userId, ip, machineId]
        );
        return results.length > 0;
    } catch (err) {
        console.error('Error checking ban status:', err);
        throw new Error('Server error');
    }
}