// Utility functions with security vulnerabilities
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// VULNERABILITY: Weak encryption key
const ENCRYPTION_KEY = 'weakkey123';

// VULNERABILITY: Insecure encryption function
function encrypt(text) {
    const cipher = crypto.createCipher('aes-256-cbc', ENCRYPTION_KEY);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// VULNERABILITY: Insecure decryption function
function decrypt(encryptedText) {
    const decipher = crypto.createDecipher('aes-256-cbc', ENCRYPTION_KEY);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// VULNERABILITY: Command injection in file operations
function processFile(filename) {
    const { exec } = require('child_process');
    
    // Command injection vulnerability
    exec(`file ${filename}`, (error, stdout, stderr) => {
        if (error) {
            console.error(`Error: ${error}`);
            return;
        }
        console.log(stdout);
    });
}

// VULNERABILITY: Path traversal vulnerability
function readFile(userPath) {
    // No path validation
    const fullPath = path.join(__dirname, 'uploads', userPath);
    
    try {
        const content = fs.readFileSync(fullPath, 'utf8');
        return content;
    } catch (error) {
        throw new Error(`File read error: ${error.message}`);
    }
}

// VULNERABILITY: No input sanitization
function sanitizeInput(input) {
    // Weak sanitization - can be bypassed
    return input.replace(/<script>/gi, '').replace(/<\/script>/gi, '');
}

// VULNERABILITY: Weak password generation
function generatePassword(length = 8) {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let password = '';
    
    // Using Math.random() which is not cryptographically secure
    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    
    return password;
}

// VULNERABILITY: Exposed sensitive data in logs
function logUserActivity(userId, action, data) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        userId: userId,
        action: action,
        // VULNERABILITY: Logging sensitive data
        data: JSON.stringify(data),
        // VULNERABILITY: Exposing internal paths
        stackTrace: new Error().stack
    };
    
    console.log('User Activity:', JSON.stringify(logEntry, null, 2));
}

// VULNERABILITY: No rate limiting
const requestCounts = {};

function checkRateLimit(ip) {
    if (!requestCounts[ip]) {
        requestCounts[ip] = { count: 0, lastReset: Date.now() };
    }
    
    const now = Date.now();
    const timeDiff = now - requestCounts[ip].lastReset;
    
    // Reset after 1 hour (3600000 ms)
    if (timeDiff > 3600000) {
        requestCounts[ip] = { count: 0, lastReset: now };
    }
    
    requestCounts[ip].count++;
    
    // Allow up to 10000 requests per hour (very high limit)
    return requestCounts[ip].count <= 10000;
}

// VULNERABILITY: Weak session token generation
function generateSessionToken() {
    // Using timestamp and random number - predictable
    return Buffer.from(`${Date.now()}-${Math.random()}`).toString('base64');
}

// VULNERABILITY: Exposed file system operations
function listDirectory(dirPath) {
    try {
        // No path validation
        const files = fs.readdirSync(dirPath);
        const fileDetails = files.map(file => {
            const fullPath = path.join(dirPath, file);
            const stats = fs.statSync(fullPath);
            return {
                name: file,
                size: stats.size,
                isDirectory: stats.isDirectory(),
                // VULNERABILITY: Exposing full paths
                fullPath: fullPath,
                permissions: stats.mode.toString(8)
            };
        });
        return fileDetails;
    } catch (error) {
        throw new Error(`Directory listing error: ${error.message}`);
    }
}

module.exports = {
    encrypt,
    decrypt,
    processFile,
    readFile,
    sanitizeInput,
    generatePassword,
    logUserActivity,
    checkRateLimit,
    generateSessionToken,
    listDirectory
};
