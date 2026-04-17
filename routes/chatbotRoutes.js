const express = require('express');
const router = express.Router();
const { sendMessage, getSuggestions } = require('../controllers/chatbotController');

router.post('/message',     sendMessage);
router.get('/suggestions',  getSuggestions);

module.exports = router;