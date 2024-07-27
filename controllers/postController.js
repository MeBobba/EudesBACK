const db = require("../db");
const {exp} = require("qrcode/lib/core/galois-field");

exports.getPostsForUser = async (req, res) => {
    const userId = req.params.userId === 'me' ? req.userId : req.params.userId;
    try {
        const [posts] = await db.query(
            `SELECT posts.*,
                    users.username,
                    users.look,
                    COALESCE(likesCount.likesCount, 0)       as likesCount,
                    COALESCE(commentsCount.commentsCount, 0) as commentsCount,
                    userLikes.is_like                        as userLike
             FROM posts
                      JOIN users ON posts.user_id = users.id
                      LEFT JOIN (SELECT post_id, COUNT(*) as likesCount
                                 FROM likes
                                 WHERE is_like = true
                                 GROUP BY post_id) likesCount ON posts.id = likesCount.post_id
                      LEFT JOIN (SELECT post_id, COUNT(*) as commentsCount
                                 FROM comments
                                 GROUP BY post_id) commentsCount ON posts.id = commentsCount.post_id
                      LEFT JOIN (SELECT post_id, is_like
                                 FROM likes
                                 WHERE user_id = ?) userLikes ON posts.id = userLikes.post_id
             WHERE posts.user_id = ?
               AND posts.visibility = "public"
             ORDER BY posts.created_at DESC`,
            [req.userId, userId]
        );

        for (let post of posts) {
            const [comments] = await db.query(
                `SELECT comments.*, users.username, users.look
                 FROM comments
                          JOIN users ON comments.user_id = users.id
                 WHERE comments.post_id = ?
                 ORDER BY comments.created_at DESC`,
                [post.id]
            );
            post.comments = comments;
        }

        res.status(200).send(posts);
    } catch (err) {
        console.error('Error fetching posts:', err);
        res.status(500).send('Server error');
    }
};

exports.deleteComment = async (req, res) => {
    const { commentId } = req.params;
    try {
        const [[comment]] = await db.query('SELECT user_id FROM comments WHERE id = ?', [commentId]);
        if (!comment) {
            return res.status(404).send('Comment not found');
        }

        const [[user]] = await db.query('SELECT rank FROM users WHERE id = ?', [req.userId]);
        if (user.rank < 5 && comment.user_id !== req.userId) {
            return res.status(403).send('Not authorized to delete this comment');
        }

        await db.query('DELETE FROM comments WHERE id = ?', [commentId]);
        res.status(200).send('Comment deleted successfully');
    } catch (err) {
        console.error('Error deleting comment:', err);
        res.status(500).send('Server error');
    }
}

exports.addLike = async (req, res) => {
    const { postId, isLike } = req.body;
    try {
        const [existingLike] = await db.query(
            'SELECT * FROM likes WHERE post_id = ? AND user_id = ?',
            [postId, req.userId]
        );

        if (existingLike.length > 0) {
            if (existingLike[0].is_like === isLike) {
                // If the same like status is being sent, remove the like
                await db.query(
                    'DELETE FROM likes WHERE id = ?',
                    [existingLike[0].id]
                );
            } else {
                // Otherwise, update the like status
                await db.query(
                    'UPDATE likes SET is_like = ? WHERE id = ?',
                    [isLike, existingLike[0].id]
                );
            }
        } else {
            await db.query(
                'INSERT INTO likes (post_id, user_id, is_like) VALUES (?, ?, ?)',
                [postId, req.userId, isLike]
            );
        }

        const [[likeStatus]] = await db.query(
            'SELECT is_like FROM likes WHERE post_id = ? AND user_id = ?',
            [postId, req.userId]
        );

        const [[likesCount]] = await db.query(
            'SELECT COUNT(*) AS likesCount FROM likes WHERE post_id = ? AND is_like = true',
            [postId]
        );

        res.status(201).send({ userLike: likeStatus ? likeStatus.is_like : null, likesCount: likesCount.likesCount });
    } catch (err) {
        console.error('Error adding like/dislike:', err);
        res.status(500).send('Server error');
    }
};

exports.addComment = async (req, res) => {
    const { postId, content } = req.body;
    try {
        const [result] = await db.query(
            'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
            [postId, req.userId, content]
        );
        const [comment] = await db.query(
            'SELECT comments.*, users.username, users.look FROM comments JOIN users ON comments.user_id = users.id WHERE comments.id = ?',
            [result.insertId]
        );
        res.status(201).send(comment[0]);
    } catch (err) {
        console.error('Error adding comment:', err);
        res.status(500).send('Server error');
    }
};

async function deletePostWithComments(postId) {
    try {
        await db.query('DELETE FROM comments WHERE post_id = ?', [postId]);
        await db.query('DELETE FROM likes WHERE post_id = ?', [postId]);
        await db.query('DELETE FROM posts WHERE id = ?', [postId]);
    } catch (err) {
        throw err;
    }
}

exports.deletePost = async (req, res) => {
    const { postId } = req.params;
    try {
        const [[user]] = await db.query('SELECT rank FROM users WHERE id = ?', [req.userId]);
        const userRank = user.rank;

        const [[post]] = await db.query('SELECT user_id FROM posts WHERE id = ?', [postId]);
        if (!post) {
            return res.status(404).send('Post not found');
        }

        const postOwnerId = post.user_id;

        if (userRank < 5 && postOwnerId !== req.userId) {
            return res.status(403).send('Not authorized to delete this post');
        }

        await deletePostWithComments(postId);

        res.status(200).send('Post deleted successfully');
    } catch (err) {
        console.error('Error deleting post:', err);
        res.status(500).send('Server error');
    }
};

exports.getPublicPosts = async (req, res) => {
    const { page = 1, limit = 10 } = req.query;
    const offset = (page - 1) * limit;

    try {
        const [posts] = await db.query(
            `SELECT DISTINCT posts.*,
                             users.username,
                             users.look,
                             COALESCE(likesCount.likesCount, 0)       as likesCount,
                             COALESCE(commentsCount.commentsCount, 0) as commentsCount,
                             COALESCE(userLikes.is_like, false)       as userLike
             FROM posts
                      JOIN users ON posts.user_id = users.id
                      LEFT JOIN (SELECT post_id, COUNT(*) as likesCount
                                 FROM likes
                                 WHERE is_like = true
                                 GROUP BY post_id) likesCount ON posts.id = likesCount.post_id
                      LEFT JOIN (SELECT post_id, COUNT(*) as commentsCount
                                 FROM comments
                                 GROUP BY post_id) commentsCount ON posts.id = commentsCount.post_id
                      LEFT JOIN (SELECT post_id, is_like
                                 FROM likes
                                 WHERE user_id = ?) userLikes ON posts.id = userLikes.post_id
             WHERE posts.visibility = 'public' AND posts.user_id != ?
             ORDER BY posts.created_at DESC LIMIT ?
             OFFSET ?`,
            [req.userId, req.userId, parseInt(limit), parseInt(offset)]
        );

        const postIds = posts.map(post => post.id);
        if (postIds.length > 0) {
            const [comments] = await db.query(
                `SELECT comments.*, users.username, users.look, comments.post_id
                 FROM comments
                          JOIN users ON comments.user_id = users.id
                 WHERE comments.post_id IN (?)
                 ORDER BY comments.created_at DESC`,
                [postIds]
            );

            const commentsByPostId = comments.reduce((acc, comment) => {
                if (!acc[comment.post_id]) {
                    acc[comment.post_id] = [];
                }
                acc[comment.post_id].push(comment);
                return acc;
            }, {});

            posts.forEach(post => {
                post.comments = commentsByPostId[post.id] || [];
            });
        }

        res.status(200).send(posts);
    } catch (err) {
        console.error('Error fetching public posts:', err);
        res.status(500).send('Server error');
    }
};


exports.createPost = async (req, res) => {
    const { content, image, video, visibility } = req.body;

    try {
        const [[user]] = await db.query('SELECT rank, last_post_time FROM users WHERE id = ?', [req.userId]);
        const currentTime = Math.floor(Date.now() / 1000);

        // Check for flood protection
        if (user.rank < 5 && user.last_post_time && (currentTime - user.last_post_time < 15)) {
            return res.status(429).send('You must wait 15 seconds before posting again.');
        }

        // Apply wordfilter
        const [wordFilters] = await db.query('SELECT * FROM wordfilter');
        let filteredContent = content;
        wordFilters.forEach(filter => {
            const regex = new RegExp(`\\b${filter.key}\\b`, 'gi');
            filteredContent = filteredContent.replace(regex, filter.replacement);
        });

        const [result] = await db.query(
            'INSERT INTO posts (user_id, content, image, video, visibility, created_at) VALUES (?, ?, ?, ?, ?, ?)',
            [req.userId, filteredContent, image, video, visibility, new Date()]
        );

        await db.query('UPDATE users SET last_post_time = ? WHERE id = ?', [currentTime, req.userId]);

        const [newPost] = await db.query(
            `SELECT posts.*, users.username, users.look
             FROM posts
                      JOIN users ON posts.user_id = users.id
             WHERE posts.id = ?`,
            [result.insertId]
        );

        res.status(201).send(newPost[0]);
    } catch (err) {
        console.error('Error creating post:', err);
        res.status(500).send('Server error');
    }
};

exports.editPost = async (req, res) => {
    const { postId } = req.params;
    const { content } = req.body;

    try {
        const [result] = await db.query(
            'UPDATE posts SET content = ? WHERE id = ?',
            [content, postId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).send('Post not found');
        }

        const [updatedPost] = await db.query('SELECT * FROM posts WHERE id = ?', [postId]);
        res.status(200).send(updatedPost[0]);
    } catch (err) {
        console.error('Error updating post:', err);
        res.status(500).send('Server error');
    }
};