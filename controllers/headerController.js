const path = require('path');
const fs = require('fs');

exports.getHeaderImages = async (req, res) => {
    try {
        const imagesDir = path.join(__dirname, '../headerimages');
        fs.readdir(imagesDir, (err, files) => {
            if (err) {
                console.error('Error reading images directory:', err);
                return res.status(500).send('Server error');
            }

            const images = files.map(file => ({
                name: file,
                path: `/headerimages/${file}`
            }));

            res.status(200).send(images);
        });
    } catch (error) {
        console.error('Error fetching header images:', error);
        res.status(500).send('Server error');
    }
};
