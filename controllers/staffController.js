const db = require("../db");

exports.getStaff = async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;
    try {
        const [ranks] = await db.query(
            'SELECT * FROM permissions WHERE level >= 5 ORDER BY level DESC'
        );

        const [users] = await db.query(
            'SELECT * FROM users WHERE rank >= 5 ORDER BY rank DESC LIMIT ? OFFSET ?',
            [limit, offset]
        );

        const staffSections = ranks.map(rank => {
            return { rank_name: rank.rank_name, rank_level: rank.level, users: users.filter(user => user.rank === rank.level) };
        }).filter(section => section.users.length > 0);

        res.status(200).send({ staffSections, ranks });
    } catch (err) {
        console.error('Error fetching staff data:', err);
        res.status(500).send('Server error');
    }
};