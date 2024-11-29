const jwt = require('jsonwebtoken');

const authorizeAdmin = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: 'Token not provided' });
    }
    try {
        const token = authHeader.split(' ')[1]; // Pastikan format: "Bearer <token>"
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        if (decoded.role !== 'ADMIN') {
            return res.status(403).json({ message: 'Access forbidden: Admins only' });
        }
        
        req.user = decoded; // Simpan data pengguna ke request jika diperlukan
        next();
    } catch (error) {
        return res.status(403).json({ message: 'Invalid token' });
    }
};

module.exports = authorizeAdmin;
