const express = require('express');
const router = express.Router();
const {verifyToken} = require("../middlewares/authMiddleware");
const postController = require("../controllers/postController");

// router.get('/', verifyToken, articleController.getArticles);
// router.get('/:id', verifyToken, articleController.getArticle);
// router.post('/:articleId/likes', verifyToken, articleController.addLike);
// router.post('/:articleId/comments', verifyToken, articleController.addComment);
// router.post('/', verifyToken, articleController.createArticle);
// router.delete('/:articleId/comments/:commentId', verifyToken, articleController.deleteComment);
// router.delete('/:id', verifyToken, articleController.deleteArticle);
// router.put('/:id', verifyToken, articleController.updateArticle);

router.get('/:userId', verifyToken, postController.getPostsForUser);
router.get('/public', verifyToken, postController.getPublicPosts);
router.post('/', verifyToken, postController.createPost);
router.post('/likes', verifyToken, postController.addLike);
router.post('/comments', verifyToken, postController.addComment);
router.delete('/comments/:commentId', verifyToken, postController.deleteComment);
router.delete('/:postId', verifyToken, postController.deletePost);

module.exports = router;