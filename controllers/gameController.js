const db = require("../db");
exports.getGames = async (req, res) => {
    try {
        const [games] = await db.query('SELECT * FROM games');
        res.status(200).send(games);
    } catch (error) {
        console.error('Error fetching games:', error);
        res.status(500).send('Server error');
    }
};

exports.getGame = async (req, res) => {
    try {
        const [games] = await db.query('SELECT * FROM games WHERE id = ?', [req.params.id]);
        if (games.length === 0) {
            return res.status(404).send('Game not found');
        }
        res.status(200).send(games[0]);
    } catch (error) {
        console.error('Error fetching game by ID:', error);
        res.status(500).send('Server error');
    }
};

exports.deleteGame = async (req, res) => {
    const { id } = req.params;

    if (req.userRank < 5) {
        return res.status(403).send('Not authorized to delete games');
    }

    try {
        // Start a transaction
        await db.query('START TRANSACTION');

        // Delete the game
        const [result] = await db.query('DELETE FROM games WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            await db.query('ROLLBACK');
            return res.status(404).send('Game not found');
        }

        // Commit the transaction
        await db.query('COMMIT');

        res.status(200).send('Game deleted successfully');
    } catch (err) {
        await db.query('ROLLBACK');
        console.error('Error deleting game:', err);
        res.status(500).send('Server error');
    }
};

exports.createGame = async (req, res) => {
    const { icon, title, source } = req.body;

    if (req.userRank < 5) {
        return res.status(403).send('Not authorized to create games');
    }

    try {
        const [result] = await db.query(
            'INSERT INTO games (icon, title, source) VALUES (?, ?, ?)',
            [icon, title, source]
        );
        res.status(201).send(
            {
                id: result.insertId,
                icon: icon,
                title: title,
                source: source
            }
        );
    } catch (err) {
        console.error('Error creating game:', err);
        res.status(500).send('Server error');
    }
}