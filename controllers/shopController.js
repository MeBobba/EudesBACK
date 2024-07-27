const db = require("../db");

exports.generateCredits = async (req, res) => {
    try {
        const [results] = await db.query('SELECT credits FROM users WHERE id = ?', [req.userId]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        const userCredits = results[0].credits;
        if (userCredits < 10000) {
            const newCredits = userCredits + 10000;
            await db.query('UPDATE users SET credits = ? WHERE id = ?', [newCredits, req.userId]);
            res.status(200).send({ generatedCredits: 10000 });
        } else {
            res.status(400).send('You have enough credits.');
        }
    } catch (error) {
        console.error('Error generating credits:', error);
        res.status(500).send('Server error');
    }
};

exports.generatePixels = async (req, res) => {
    try {
        const [results] = await db.query('SELECT pixels FROM users WHERE id = ?', [req.userId]);
        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        const userPixels = results[0].pixels;
        if (userPixels < 10000) {
            const newPixels = userPixels + 10000;
            await db.query('UPDATE users SET pixels = ? WHERE id = ?', [newPixels, req.userId]);
            res.status(200).send({ generatedPixels: 10000 });
        } else {
            res.status(400).send('You have enough pixels.');
        }
    } catch (error) {
        console.error('Error generating pixels:', error);
        res.status(500).send('Server error');
    }
};

function drawLotteryNumbers(betAmount, selectedNumbers) {
    const numbers = Array.from({ length: 49 }, (_, i) => i + 1);
    const drawnNumbers = [];
    const chanceFactor = Math.min((betAmount - 150) / (1000 - 150), 0.7); // Facteur de chance limité à 0.7

    for (let i = 0; i < 6; i++) {
        let index;
        if (Math.random() < chanceFactor) {
            // Sélectionner un nombre parmi ceux choisis par l'utilisateur avec une probabilité accrue
            const commonNumbers = selectedNumbers.filter(num => numbers.includes(num));
            index = numbers.indexOf(commonNumbers[Math.floor(Math.random() * commonNumbers.length)]);
        } else {
            // Sélectionner un nombre aléatoire parmi les nombres restants
            index = Math.floor(Math.random() * numbers.length);
        }
        drawnNumbers.push(numbers.splice(index, 1)[0]);
    }
    return drawnNumbers;
}

function checkWin(selectedNumbers, drawnNumbers, betAmount) {
    const matches = selectedNumbers.filter(number => drawnNumbers.includes(number)).length;
    if (matches === 6) {
        const baseMultipliers = [0, 0, 0.5, 1, 2, 5, 10]; // Multiplicateurs de base pour 0 à 6 correspondances
        const chanceFactor = Math.min((betAmount - 150) / (1000 - 150), 0.7); // Facteur de chance limité à 0.7
        const adjustedMultipliers = baseMultipliers.map(multiplier => multiplier * (1 + chanceFactor));
        return adjustedMultipliers[matches];
    }
    return 0; // Si tous les numéros ne correspondent pas, retourne 0
}

exports.lottery = async (req, res) => {
    const { selectedNumbers, betAmount } = req.body;
    if (!Array.isArray(selectedNumbers) || selectedNumbers.length !== 6) {
        return res.status(400).send('Invalid input');
    }
    if (betAmount < 150 || betAmount > 1000) {
        return res.status(400).send('Bet amount must be between 150 and 1000 points.');
    }

    try {
        const [user] = await db.query('SELECT points FROM users WHERE id = ?', [req.userId]);
        if (user[0].points < betAmount) {
            return res.status(400).send({ success: false, message: 'You do not have enough points to play.' });
        }

        const drawnNumbers = drawLotteryNumbers(betAmount, selectedNumbers);
        const multiplier = checkWin(selectedNumbers, drawnNumbers, betAmount); // Utilisation de la nouvelle fonction
        const rewardAmount = betAmount * multiplier;

        await db.query('UPDATE users SET points = points - ? WHERE id = ?', [betAmount, req.userId]);

        if (rewardAmount > 0) {
            await db.query('UPDATE users SET points = points + ? WHERE id = ?', [rewardAmount, req.userId]);
        }

        await db.query(
            'INSERT INTO lottery_plays (user_id, bet_amount, reward_amount, reward_type, drawn_numbers) VALUES (?, ?, ?, ?, ?)',
            [req.userId, betAmount, rewardAmount, 'Points', drawnNumbers.join(',')]
        );

        res.status(200).send({ success: true, drawnNumbers, reward: { amount: rewardAmount, type: 'Points' } });
    } catch (error) {
        console.error('Error processing lottery:', error);
        res.status(500).send('Server error');
    }
};

exports.getLastMembers = async (req, res) => {
    try {
        const [results] = await db.query(
            `SELECT u.username,
                    l.bet_amount                           AS betAmount,
                    l.reward_amount                        AS rewardAmount,
                    l.reward_type                          AS rewardType,
                    (l.reward_amount / l.bet_amount * 100) AS probability
             FROM lottery_plays l
                      JOIN users u ON l.user_id = u.id
             ORDER BY l.created_at DESC LIMIT 10`
        );
        res.status(200).send(results);
    } catch (error) {
        console.error('Error fetching last members:', error);
        res.status(500).send('Server error');
    }
}