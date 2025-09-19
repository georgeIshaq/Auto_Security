// Main application file with various security vulnerabilities
const express = require('express');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');

const app = express();

// VULNERABILITY: Hardcoded API keys and secrets
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const OPENAI_API_KEY = 'sk-1234567890abcdef1234567890abcdef1234567890abcdef';
const STRIPE_SECRET_KEY = 'sk_test_51234567890abcdef1234567890abcdef1234567890abcdef';

// VULNERABILITY: Hardcoded database credentials
const DB_CONFIG = {
    host: 'localhost',
    user: 'admin',
    password: 'SuperSecretPassword123!',
    database: 'production_db'
};

// VULNERABILITY: JWT secret exposed
const JWT_SECRET = 'my-super-secret-jwt-key-that-should-never-be-committed';

// VULNERABILITY: Hardcoded admin credentials
const ADMIN_USER = 'admin';
const ADMIN_PASSWORD = 'admin123';

// VULNERABILITY: SQL injection vulnerable endpoint
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // Direct SQL injection vulnerability
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    
    const connection = mysql.createConnection(DB_CONFIG);
    connection.query(query, (err, results) => {
        if (err) {
            res.status(500).json({ error: err.message });
        } else {
            res.json(results);
        }
    });
    connection.end();
});

// VULNERABILITY: Authentication bypass
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // Weak authentication logic
    if (username === ADMIN_USER && password === ADMIN_PASSWORD) {
        const token = jwt.sign({ user: username }, JWT_SECRET);
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// VULNERABILITY: Sensitive data exposure
app.get('/debug/config', (req, res) => {
    // Exposing sensitive configuration
    res.json({
        db_password: DB_CONFIG.password,
        jwt_secret: JWT_SECRET,
        aws_key: AWS_ACCESS_KEY_ID,
        stripe_key: STRIPE_SECRET_KEY
    });
});

// VULNERABILITY: Directory traversal
app.get('/file', (req, res) => {
    const filename = req.query.name;
    const fs = require('fs');
    
    // No path validation - directory traversal vulnerability
    const filePath = `./uploads/${filename}`;
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.status(404).json({ error: 'File not found' });
        } else {
            res.send(data);
        }
    });
});

// VULNERABILITY: Command injection
app.post('/backup', (req, res) => {
    const { dbname } = req.body;
    
    // Command injection vulnerability
    const { exec } = require('child_process');
    exec(`mysqldump -u ${DB_CONFIG.user} -p${DB_CONFIG.password} ${dbname}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).json({ error: error.message });
        } else {
            res.json({ backup: stdout });
        }
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
