const express = require('express');
const {
    register,
    login,
    refreshToken,
    logout,
    profile,
} = require('../controllers/authController');
const { authenticateToken } = require('../middlewares/authMiddleware');
const { loginRateLimiter } = require('../middlewares/rateLimiter');

const router = express.Router();

router.post('/register', register);
router.post('/login',loginRateLimiter, login);
router.post('/refresh-token', refreshToken);
router.post('/logout', logout);
router.get('/profile', authenticateToken, profile);

module.exports = router;
