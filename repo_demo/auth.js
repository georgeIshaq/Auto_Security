// Authentication module with security vulnerabilities
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// VULNERABILITY: Hardcoded admin credentials
const ADMIN_CREDENTIALS = {
    username: 'admin',
    password: 'admin123',  // Plain text password
    email: 'admin@company.com'
};

// VULNERABILITY: Weak JWT secret
const JWT_SECRET = 'secret123';

// VULNERABILITY: Insecure password hashing
function hashPassword(password) {
    // Using weak salt rounds
    return bcrypt.hashSync(password, 5);
}

// VULNERABILITY: No rate limiting, vulnerable to brute force
function authenticateUser(username, password) {
    // Hardcoded user database
    const users = [
        { id: 1, username: 'admin', password: hashPassword('admin123'), role: 'admin' },
        { id: 2, username: 'user1', password: hashPassword('password123'), role: 'user' },
        { id: 3, username: 'test', password: hashPassword('test123'), role: 'user' }
    ];
    
    const user = users.find(u => u.username === username);
    if (user && bcrypt.compareSync(password, user.password)) {
        // VULNERABILITY: JWT without expiration
        const token = jwt.sign(
            { 
                userId: user.id, 
                username: user.username,
                role: user.role 
            }, 
            JWT_SECRET
        );
        return { success: true, token, user };
    }
    return { success: false, message: 'Invalid credentials' };
}

// VULNERABILITY: Weak token verification
function verifyToken(token) {
    try {
        // No expiration check
        const decoded = jwt.verify(token, JWT_SECRET);
        return { valid: true, user: decoded };
    } catch (error) {
        return { valid: false, error: error.message };
    }
}

// VULNERABILITY: Password reset with weak token
function generatePasswordResetToken(email) {
    // Using simple timestamp as token - easily guessable
    const token = Date.now().toString();
    return token;
}

// VULNERABILITY: No input validation
function changePassword(userId, newPassword) {
    // No password strength requirements
    // No old password verification
    console.log(`Changing password for user ${userId} to: ${newPassword}`);
    return true;
}

// VULNERABILITY: Session management issues
const sessions = {};

function createSession(userId) {
    // Simple session ID generation
    const sessionId = Math.random().toString(36).substring(2);
    sessions[sessionId] = {
        userId: userId,
        createdAt: new Date(),
        // No expiration set
    };
    return sessionId;
}

// VULNERABILITY: Exposed session data
function getSession(sessionId) {
    return sessions[sessionId];
}

module.exports = {
    authenticateUser,
    verifyToken,
    generatePasswordResetToken,
    changePassword,
    createSession,
    getSession,
    hashPassword
};
