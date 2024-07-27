const express = require('express');
const router = express.Router();
const {verifyToken} = require("../middlewares/authMiddleware");
const postController = require("../controllers/postController");

router.get('/public', verifyToken, postController.getPublicPosts);
router.get('/:userId', verifyToken, postController.getPostsForUser);
router.post('/', verifyToken, postController.createPost);
router.post('/likes', verifyToken, postController.addLike);
router.post('/comments', verifyToken, postController.addComment);
router.delete('/comments/:commentId', verifyToken, postController.deleteComment);
router.delete('/:postId', verifyToken, postController.deletePost);
router.put('/:postId', verifyToken, postController.editPost);

module.exports = router;