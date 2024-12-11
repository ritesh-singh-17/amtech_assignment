const jwt = require('jsonwebtoken');
const { checkBlacklist } = require('../utils/tokenBackList');

exports.authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    if (checkBlacklist(token)) {
        return res.status(401).json({ message: 'Token has been invalidated' });
    }
    
    try {
        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({ message: 'Invalid or expired token' });
            }
            req.user = user;
            next();
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
};
