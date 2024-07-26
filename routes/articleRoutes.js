const express = require('express');
const router = express.Router();
const {verifyToken} = require("../middlewares/authMiddleware");
const articleController = require("../controllers/articleController");

router.get('/', verifyToken, articleController.getArticles);
router.get('/:id', verifyToken, articleController.getArticle);
router.post('/:articleId/likes', verifyToken, articleController.addLike);
router.post('/:articleId/comments', verifyToken, articleController.addComment);
router.post('/', verifyToken, articleController.createArticle);
router.delete('/:articleId/comments/:commentId', verifyToken, articleController.deleteComment);
router.delete('/:id', verifyToken, articleController.deleteArticle);
router.put('/:id', verifyToken, articleController.updateArticle);

module.exports = router;