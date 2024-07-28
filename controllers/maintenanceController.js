const db = require("../db");
const { getIo } = require("../socket");
exports.getStatus = async (req, res) => {
    try {
        const [results] = await db.query("SELECT `value` FROM `emulator_settings` WHERE `key` = 'website.maintenance'");
        const isMaintenance = results.length > 0 && results[0].value === '1';
        const io = getIo();
        // Notify clients if maintenance mode is enabled
        if (isMaintenance) {
            io.emit('maintenance', true);
        }

        res.status(200).send({ maintenance: isMaintenance });
    } catch (error) {
        console.error('Error fetching maintenance status:', error);
        res.status(500).send('Server error');
    }
};