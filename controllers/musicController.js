const axios = require("axios");
const db = require("../db");

exports.getLyrics = async (req, res) => {
    const { q_track, q_artist } = req.query;
    try {
        const response = await axios.get(`https://api.musixmatch.com/ws/1.1/matcher.lyrics.get`, {
            params: {
                q_track,
                q_artist,
                apikey: process.env.MUSIXMATCH_API_KEY
            }
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).send('Error fetching lyrics');
    }
};

exports.getTracks = async (req, res) => {
    const spotifyId = req.params.spotifyId;
    try {
        const [results] = await db.query('SELECT * FROM tracks WHERE spotify_id = ?', [spotifyId]);
        res.send({ exists: results.length > 0 });
    } catch (error) {
        console.error('Error checking track existence:', error);
        res.status(500).send('Server error');
    }
};

exports.saveTrack = async (req, res) => {
    const track = req.body;
    const query = 'INSERT INTO tracks (name, album_id, duration, spotify_popularity, spotify_id, description, image, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())';
    const values = [
        track.name,
        track.album_id,
        track.duration,
        track.spotify_popularity,
        track.spotify_id,
        track.description,
        track.image
    ];
    try {
        await db.query(query, values);
        res.status(201).send('Track stored successfully');
    } catch (error) {
        console.error('Error storing track:', error);
        res.status(500).send('Server error');
    }
};