const db = require("../db");

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