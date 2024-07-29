const db = require("../db");
const moment = require("moment-timezone");
const path = require("path");
const fs = require("fs");

exports.getArticles = async (req, res) => {
    try {
        const [articles] = await db.query('SELECT * FROM articles ORDER BY date DESC');
        res.status(200).send(articles);
    } catch (error) {
        console.error('Error fetching articles:', error);
        res.status(500).send('Server error');
    }
};

exports.getArticle = async (req, res) => {
    const {id} = req.params;
    const userId = req.userId; // Assurez-vous que verifyToken est utilisé pour définir req.userId
    try {
        const [articles] = await db.query('SELECT * FROM articles WHERE id = ?', [id]);
        if (articles.length === 0) {
            return res.status(404).send('Article not found');
        }

        const article = articles[0];

        // Récupérer le nombre de likes
        const [[likesCount]] = await db.query(
            'SELECT COUNT(*) AS likesCount FROM article_likes WHERE article_id = ? AND is_like = true',
            [id]
        );

        // Récupérer le nombre de commentaires
        const [[commentsCount]] = await db.query(
            'SELECT COUNT(*) AS commentsCount FROM article_comments WHERE article_id = ?',
            [id]
        );

        // Vérifier si l'utilisateur a liké l'article
        const [[userLike]] = await db.query(
            'SELECT is_like FROM article_likes WHERE article_id = ? AND user_id = ?',
            [id, userId]
        );

        // Récupérer les commentaires
        const [comments] = await db.query(
            `SELECT article_comments.*, users.username, users.look
             FROM article_comments
                      JOIN users ON article_comments.user_id = users.id
             WHERE article_comments.article_id = ?
             ORDER BY article_comments.created_at DESC`,
            [id]
        );

        article.likesCount = likesCount.likesCount;
        article.commentsCount = commentsCount.commentsCount;
        article.userLike = userLike ? userLike.is_like : null;
        article.comments = comments;

        res.status(200).send(article);
    } catch (error) {
        console.error('Error fetching article:', error);
        res.status(500).send('Server error');
    }
};

exports.addLike = async (req, res) => {
    const {articleId} = req.params;
    const {isLike} = req.body;
    try {
        const [existingLike] = await db.query(
            'SELECT * FROM article_likes WHERE article_id = ? AND user_id = ?',
            [articleId, req.userId]
        );

        if (existingLike.length > 0) {
            await db.query(
                'UPDATE article_likes SET is_like = ? WHERE id = ?',
                [isLike, existingLike[0].id]
            );
        } else {
            await db.query(
                'INSERT INTO article_likes (article_id, user_id, is_like) VALUES (?, ?, ?)',
                [articleId, req.userId, isLike]
            );
        }

        const [[likeStatus]] = await db.query(
            'SELECT is_like FROM article_likes WHERE article_id = ? AND user_id = ?',
            [articleId, req.userId]
        );

        const [[likesCount]] = await db.query(
            'SELECT COUNT(*) AS likesCount FROM article_likes WHERE article_id = ? AND is_like = true',
            [articleId]
        );

        res.status(201).send({userLike: likeStatus.is_like, likesCount: likesCount.likesCount});
    } catch (err) {
        console.error('Error adding like/dislike:', err);
        res.status(500).send('Server error');
    }
};

exports.addComment = async (req, res) => {
    const {articleId} = req.params;
    const {content} = req.body;

    try {
        const [[user]] = await db.query('SELECT last_comment_time FROM users WHERE id = ?', [req.userId]);

        const currentTime = Math.floor(Date.now() / 1000);

        if (user.last_comment_time && (currentTime - user.last_comment_time < 15)) {
            return res.status(429).send('You must wait 15 seconds before commenting again.');
        }

        const [result] = await db.query(
            'INSERT INTO article_comments (article_id, user_id, content) VALUES (?, ?, ?)',
            [articleId, req.userId, content]
        );

        await db.query('UPDATE users SET last_comment_time = ? WHERE id = ?', [currentTime, req.userId]);

        const [comment] = await db.query(
            'SELECT article_comments.*, users.username, users.look FROM article_comments JOIN users ON article_comments.user_id = users.id WHERE article_comments.id = ?',
            [result.insertId]
        );

        res.status(201).send(comment[0]);
    } catch (err) {
        console.error('Error adding comment:', err);
        res.status(500).send('Server error');
    }
};

exports.deleteComment = async (req, res) => {
    const { commentId } = req.params;
    try {
        const [[comment]] = await db.query('SELECT user_id FROM article_comments WHERE id = ?', [commentId]);
        if (!comment) {
            return res.status(404).send('Comment not found');
        }

        const [[user]] = await db.query('SELECT rank FROM users WHERE id = ?', [req.userId]);
        if (user.rank < 5 && comment.user_id !== req.userId) {
            return res.status(403).send('Not authorized to delete this comment');
        }

        await db.query('DELETE FROM article_comments WHERE id = ?', [commentId]);
        res.status(200).send('Comment deleted successfully');
    } catch (err) {
        console.error('Error deleting comment:', err);
        res.status(500).send('Server error');
    }
};

exports.createArticle = async (req, res) => {
    const { title, summary, content, image } = req.body;
    const userId = req.userId;

    if (req.userRank < 5) {
        return res.status(403).send('Not authorized to create articles');
    }

    try {
        const currentTimeUTC = moment.utc().format().replace('T', ' ').replace('Z', ' '); // ISO 8601 format with UTC timezone
        const [result] = await db.query(
            'INSERT INTO articles (title, summary, content, image, date, user_id) VALUES (?, ?, ?, ?, ?, ?)',
            [title, summary, content, image, currentTimeUTC, userId]
        );
        res.status(201).send({
            id: result.insertId,
            title,
            summary,
            content,
            image,
            date: currentTimeUTC,
            user_id: userId
        });
    } catch (err) {
        console.error('Error creating article:', err);
        res.status(500).send('Server error');
    }
};

exports.updateArticle = async (req, res) => {
    const { id } = req.params;
    const { title, summary, content, image } = req.body;
    if (req.userRank < 5) {
        return res.status(403).send('Not authorized to edit articles');
    }
    try {
        await db.query(
            'UPDATE articles SET title = ?, summary = ?, content = ?, image = ? WHERE id = ?',
            [title, summary, content, image, id]
        );
        res.status(200).send('Article updated successfully');
    } catch (err) {
        console.error('Error updating article:', err);
        res.status(500).send('Server error');
    }
};

exports.deleteArticle = async (req, res) => {
    const { id } = req.params;

    if (req.userRank < 5) {
        return res.status(403).send('Not authorized to delete articles');
    }

    try {
        // Start a transaction
        await db.query('START TRANSACTION');

        // Delete related comments
        await db.query('DELETE FROM article_comments WHERE article_id = ?', [id]);

        // Delete related likes
        await db.query('DELETE FROM article_likes WHERE article_id = ?', [id]);

        // Delete the article
        const [result] = await db.query('DELETE FROM articles WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            await db.query('ROLLBACK');
            return res.status(404).send('Article not found');
        }

        // Commit the transaction
        await db.query('COMMIT');

        res.status(200).send('Article and related data deleted successfully');
    } catch (err) {
        await db.query('ROLLBACK');
        console.error('Error deleting article:', err);
        res.status(500).send('Server error');
    }
};

exports.getTopStory = async (req, res) => {
    try {
        // Assurez-vous que l'utilisateur a le rang nécessaire
        const [user] = await db.query('SELECT rank FROM users WHERE id = ?', [req.userId]);
        if (user.length === 0 || user[0].rank < 5) {
            return res.status(403).send('Access denied');
        }

        const imagesDir = path.join(__dirname, '../topstory');
        fs.readdir(imagesDir, (err, files) => {
            if (err) {
                console.error('Error reading images directory:', err);
                return res.status(500).send('Server error');
            }

            const images = files.map(file => ({
                name: file,
                path: `/articles/topstory/${file}`
            }));

            res.status(200).send(images);
        });
    } catch (error) {
        console.error('Error fetching topstory images:', error);
        res.status(500).send('Server error');
    }
};