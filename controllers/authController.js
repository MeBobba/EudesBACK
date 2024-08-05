const db = require("../db");
const bcrypt = require("bcryptjs");
const twofactor = require("node-2fa");
const jwt = require("jsonwebtoken");
const { getClientIp, checkBan } = require("../utils");
const tf = require('@tensorflow/tfjs-node');
require('@tensorflow/tfjs-backend-wasm');
const faceapi = require('@vladmandic/face-api');
const canvas = require('canvas');

faceapi.env.monkeyPatch({ Canvas: canvas.Canvas, Image: canvas.Image });

const secretKey = process.env.SECRET_KEY || 'yourSecretKey';

tf.setBackend('wasm').then(() => {
    console.log('WASM backend set');
});

exports.login = async (req, res) => {
    const { username, password, token2fa, machine_id } = req.body;
    const ip = getClientIp(req);

    try {
        if (!username) {
            return res.status(400).json({ message: 'Username is required' });
        }

        if (!password) {
            return res.status(400).json({ message: 'Password is required' });
        }

        const [results] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        const user = results[0];

        const isBanned = await checkBan(user.id, ip, machine_id);
        if (isBanned) {
            return res.status(403).json({ message: 'User is banned' });
        }

        const passwordIsValid = await bcrypt.compare(password, user.password);
        if (!passwordIsValid) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        if (user.is_2fa_enabled) {
            const verified = twofactor.verifyToken(user.google_auth_secret, token2fa);
            if (!verified) {
                return res.status(401).json({ message: 'Invalid 2FA token' });
            }
        }

        const token = jwt.sign({ id: user.id, rank: user.rank }, secretKey, { expiresIn: '24h' });

        await db.query('UPDATE users SET machine_id = ? WHERE id = ?', [machine_id, user.id]);
        res.status(200).json({ auth: true, token });
    } catch (err) {
        console.error('Error logging in user:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.loginWithFace = async (req, res) => {
    const { image } = req.body;

    try {
        console.log("Received image data:", image.slice(0, 100)); // Log initial part of the image data for debugging
        const faceDescriptor = await getFaceDescriptor(image);
        const [users] = await db.query('SELECT id, face_id_image FROM users WHERE is_face_id_enabled = 1');

        for (let user of users) {
            console.log(`Comparing with user ${user.id}`);
            const storedDescriptor = JSON.parse(user.face_id_image);
            console.log('Stored Descriptor:', storedDescriptor);
            const distance = faceapi.euclideanDistance(faceDescriptor, storedDescriptor);
            console.log('Distance:', distance);

            if (distance < 0.6) { // You can adjust this threshold
                const token = jwt.sign({ id: user.id }, secretKey, { expiresIn: '1h' });
                return res.status(200).json({ token });
            }
        }

        res.status(401).json({ message: 'Face not recognized' });
    } catch (err) {
        console.error('Error logging in with Face ID:', err);
        res.status(500).json({ message: err.message });
    }
};

exports.enableFaceId = async (req, res) => {
    const { image } = req.body;
    try {
        const faceDescriptors = await getFaceDescriptor(image);
        await db.query('UPDATE users SET is_face_id_enabled = 1, face_id_image = ? WHERE id = ?', [JSON.stringify(faceDescriptors), req.userId]);
        res.status(200).json({ message: 'Face ID enabled successfully' });
    } catch (err) {
        console.error('Error enabling Face ID:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.disableFaceId = async (req, res) => {
    try {
        await db.query('UPDATE users SET is_face_id_enabled = 0, face_id_image = NULL WHERE id = ?', [req.userId]);
        res.status(200).json({ message: 'Face ID disabled successfully' });
    } catch (err) {
        console.error('Error disabling Face ID:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.logout = async (req, res) => {
    try {
        await db.query('UPDATE users SET is_logged_in = 0 WHERE id = ?', [req.userId]);
        res.status(200).json({ message: 'User logged out successfully' });
    } catch (err) {
        console.error('Error logging out user:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.register = async (req, res) => {
    const { username, password, mail, machine_id } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    const account_created = Math.floor(Date.now() / 1000);
    const last_login = account_created;
    const motto = 'Nouveau sur MeBobba';
    const ip = getClientIp(req);

    try {
        const [result] = await db.query(
            'INSERT INTO users (username, password, mail, account_created, last_login, motto, ip_register, ip_current, machine_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [username, hashedPassword, mail, account_created, last_login, motto, ip, ip, machine_id]
        );
        const token = jwt.sign({ id: result.insertId }, secretKey, { expiresIn: '24h' });
        res.status(200).json({ auth: true, token });
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.checkSession = (req, res) => {
    res.status(200).json({ valid: true });
};

function generateAntiRobotQuestion() {
    const num1 = Math.floor(Math.random() * 10);
    const num2 = Math.floor(Math.random() * 10);
    return {
        question: `What is ${num1} + ${num2}?`,
        answer: num1 + num2
    };
}

exports.generateAntiRobotQuestion = (req, res) => {
    const question = generateAntiRobotQuestion();
    res.status(200).json(question);
};

exports.checkBan = async (req, res) => {
    const ip = getClientIp(req);
    const machineId = req.headers['machine-id'];
    try {
        const isBanned = await checkBan(req.userId, ip, machineId);
        if (isBanned) {
            return res.status(403).json({ message: 'User is banned' });
        }
        res.status(200).json({ message: 'User is not banned' });
    } catch (err) {
        console.error('Error checking ban status:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.unlock = async (req, res) => {
    const { password } = req.body;
    const userId = req.userId; // assurez-vous que req.userId est bien défini par le middleware verifyToken
    try {
        const [results] = await db.query('SELECT password FROM users WHERE id = ?', [userId]);
        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid password' });
        }
        res.status(200).json({ success: true });
    } catch (err) {
        console.error('Error unlocking:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

// Util function to get face descriptor
async function getFaceDescriptor(image) {
    await faceapi.nets.ssdMobilenetv1.loadFromDisk('models');
    await faceapi.nets.faceLandmark68Net.loadFromDisk('models');
    await faceapi.nets.faceRecognitionNet.loadFromDisk('models');

    const img = await canvas.loadImage(image);
    const detections = await faceapi.detectSingleFace(img).withFaceLandmarks().withFaceDescriptor();

    if (!detections) {
        throw new Error('Face not detected');
    }

    return detections.descriptor;
}
